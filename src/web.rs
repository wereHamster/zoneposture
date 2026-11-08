use futures::stream::{self, StreamExt};
use jiff::Timestamp;
use reqwest::Url;
use reqwest::header::LOCATION;

use crate::finding::{Finding, Severity};
use crate::headers;
use crate::http::{Clients, Response, fetch};
use crate::security_txt;
use crate::tls;
use crate::zone::{Skip, Zone};

const CONCURRENT_HOSTS: usize = 16;
const MAX_HTTP_REDIRECTS: usize = 10;

/// Findings of the checks that connect to the zone's web hosts, each grouped
/// by host in the order of [`Zone::web_hosts`]. A skipped host appears only in
/// `https`, and a host whose HTTPS endpoint cannot be reached appears only in
/// `https` and `certificates`.
#[derive(Default)]
pub struct Report {
    pub https: Vec<Finding>,
    pub certificates: Vec<Finding>,
    pub headers: Vec<Finding>,
    pub disclosure: Vec<Finding>,
}

pub async fn audit(clients: &Clients, tls: &tls::Context, zone: &Zone, now: Timestamp) -> Report {
    let reports: Vec<Report> = stream::iter(zone.web_hosts())
        .map(|host| async move {
            match &host.skip {
                Some(skip) => Report {
                    https: vec![skipped(host.name, skip, &zone.apex)],
                    ..Report::default()
                },
                None => audit_host(clients, tls, zone, host.name, now).await,
            }
        })
        .buffered(CONCURRENT_HOSTS)
        .collect()
        .await;

    let mut report = Report::default();
    for host in reports {
        report.https.extend(host.https);
        report.certificates.extend(host.certificates);
        report.headers.extend(host.headers);
        report.disclosure.extend(host.disclosure);
    }
    report
}

fn finding(host: &str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: host.to_string(),
        check: "HTTPS",
        severity,
        message,
    }
}

fn skipped(host: &str, skip: &Skip, apex: &str) -> Finding {
    match skip {
        Skip::Wildcard => finding(
            host,
            Severity::Info,
            "wildcard name; not probed".to_string(),
        ),
        Skip::NonPublic(addresses) => {
            let list: Vec<String> = addresses
                .iter()
                .map(|(addr, range)| format!("{addr} ({range})"))
                .collect();
            let consequence = if addresses.iter().any(|(_, range)| *range == "loopback") {
                format!("a loopback name lets local services count as same-site with {apex}")
            } else {
                "publishing them reveals internal network layout".to_string()
            };
            finding(
                host,
                Severity::Warn,
                format!(
                    "not probed: only non-public addresses {}; {consequence}",
                    list.join(", ")
                ),
            )
        }
    }
}

async fn audit_host(
    clients: &Clients,
    tls: &tls::Context,
    zone: &Zone,
    host: &str,
    now: Timestamp,
) -> Report {
    let url = format!("https://{host}/");
    let (root, redirect, certificates) = tokio::join!(
        fetch(&clients.https, &url, false),
        check_http_redirect(clients, host),
        tls::check_host(tls, zone, host, now),
    );

    match root {
        Err(err) => Report {
            https: vec![
                finding(host, Severity::Fail, format!("{url}: {err}")),
                redirect,
            ],
            certificates,
            ..Report::default()
        },
        Ok(response) => Report {
            https: vec![redirect],
            certificates,
            headers: headers::grade(host, host == zone.apex, &response),
            disclosure: security_txt::check_host(&clients.https, host, now).await,
        },
    }
}

enum Hop {
    Done(Finding),
    Follow(String),
}

async fn check_http_redirect(clients: &Clients, host: &str) -> Finding {
    let start = format!("http://{host}/");
    let mut url = start.clone();

    for _ in 0..MAX_HTTP_REDIRECTS {
        let response = match fetch(&clients.no_redirect, &url, false).await {
            Ok(response) => response,
            Err(err) if url == start => {
                return finding(
                    host,
                    Severity::Pass,
                    format!("{start} is not served ({err})"),
                );
            }
            Err(err) => {
                return finding(
                    host,
                    Severity::Fail,
                    format!("{start} redirects to {url}, which fails ({err})"),
                );
            }
        };
        match classify_http_response(host, &start, &url, &response) {
            Hop::Done(finding) => return finding,
            Hop::Follow(next) => url = next,
        }
    }

    finding(
        host,
        Severity::Fail,
        format!("{start} redirects more than {MAX_HTTP_REDIRECTS} times without reaching HTTPS"),
    )
}

fn classify_http_response(host: &str, start: &str, url: &str, response: &Response) -> Hop {
    let status = response.status;
    let served_at = if url == start {
        start.to_string()
    } else {
        format!("{start} (via {url})")
    };

    if !(300..400).contains(&status) {
        let (severity, what) = if (200..300).contains(&status) {
            (Severity::Fail, "serves content over plain HTTP")
        } else {
            (Severity::Warn, "returns an error over plain HTTP")
        };
        return Hop::Done(finding(
            host,
            severity,
            format!("{served_at} {what} (HTTP {status}) instead of redirecting to HTTPS"),
        ));
    }

    let location = response
        .headers
        .get(LOCATION)
        .and_then(|value| value.to_str().ok());
    let target = location.and_then(|location| Url::parse(url).ok()?.join(location).ok());
    let Some(target) = target else {
        return Hop::Done(finding(
            host,
            Severity::Fail,
            format!("{served_at} returns HTTP {status} without a valid Location header"),
        ));
    };

    match target.scheme() {
        "https" => Hop::Done(finding(
            host,
            Severity::Pass,
            format!("{start} redirects to {target}"),
        )),
        "http" => Hop::Follow(target.to_string()),
        scheme => Hop::Done(finding(
            host,
            Severity::Fail,
            format!("{served_at} redirects to a {scheme}: URL instead of HTTPS"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response;

    fn skip_message(skip: Skip) -> (Severity, String) {
        let finding = skipped("dev.example.com", &skip, "example.com");
        (finding.severity, finding.message)
    }

    #[test]
    fn skipped_hosts_are_reported() {
        assert_eq!(
            skip_message(Skip::Wildcard),
            (Severity::Info, "wildcard name; not probed".to_string())
        );
        assert_eq!(
            skip_message(Skip::NonPublic(vec![("127.0.0.1".parse().unwrap(), "loopback")])),
            (
                Severity::Warn,
                "not probed: only non-public addresses 127.0.0.1 (loopback); a loopback name lets local services count as same-site with example.com"
                    .to_string()
            )
        );
        assert_eq!(
            skip_message(Skip::NonPublic(vec![
                ("10.0.0.1".parse().unwrap(), "private"),
                ("fd00::1".parse().unwrap(), "private"),
            ])),
            (
                Severity::Warn,
                "not probed: only non-public addresses 10.0.0.1 (private), fd00::1 (private); publishing them reveals internal network layout"
                    .to_string()
            )
        );
    }

    const START: &str = "http://example.com/";

    fn classify(
        url: &str,
        status: u16,
        headers: &[(&str, &str)],
    ) -> Result<(Severity, String), String> {
        match classify_http_response("example.com", START, url, &response(status, headers, "")) {
            Hop::Done(finding) => Ok((finding.severity, finding.message)),
            Hop::Follow(next) => Err(next),
        }
    }

    #[test]
    fn redirect_to_https_passes() {
        assert_eq!(
            classify(START, 301, &[("location", "https://example.com/")]),
            Ok((
                Severity::Pass,
                "http://example.com/ redirects to https://example.com/".to_string()
            ))
        );
    }

    #[test]
    fn redirect_to_http_is_followed() {
        assert_eq!(
            classify(START, 302, &[("location", "/start")]),
            Err("http://example.com/start".to_string())
        );
        assert_eq!(
            classify(START, 308, &[("location", "http://www.example.com/")]),
            Err("http://www.example.com/".to_string())
        );
    }

    #[test]
    fn plain_http_content_fails() {
        assert_eq!(
            classify("http://www.example.com/", 200, &[]),
            Ok((
                Severity::Fail,
                "http://example.com/ (via http://www.example.com/) serves content over plain HTTP (HTTP 200) instead of redirecting to HTTPS"
                    .to_string()
            ))
        );
    }

    #[test]
    fn plain_http_error_warns() {
        assert_eq!(
            classify(START, 404, &[]),
            Ok((
                Severity::Warn,
                "http://example.com/ returns an error over plain HTTP (HTTP 404) instead of redirecting to HTTPS"
                    .to_string()
            ))
        );
    }

    #[test]
    fn redirect_without_location_fails() {
        assert_eq!(
            classify(START, 301, &[]),
            Ok((
                Severity::Fail,
                "http://example.com/ returns HTTP 301 without a valid Location header".to_string()
            ))
        );
    }
}
