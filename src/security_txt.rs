use jiff::Timestamp;
use reqwest::Client;

use crate::finding::{Finding, Severity};
use crate::http::{MAX_BODY_BYTES, Response, fetch};

const CHECK: &str = "security.txt";
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

/// Many servers answer unknown paths with `200` and an HTML page, so only a
/// plain-text response counts as a security.txt file.
fn is_found(response: &Response) -> bool {
    response.status == 200 && response.media_type().as_deref() == Some("text/plain")
}

fn describe_miss(response: &Response) -> String {
    if response.status != 200 {
        format!("HTTP {}", response.status)
    } else {
        let content_type = response.content_type().unwrap_or("no Content-Type");
        format!("{content_type} instead of text/plain")
    }
}

/// Checks a host for an RFC 9116 security.txt file.
pub async fn check_host(client: &Client, host: &str, now: Timestamp) -> Vec<Finding> {
    let well_known_url = format!("https://{host}/.well-known/security.txt");
    let well_known = fetch(client, &well_known_url, true).await;
    if let Ok(response) = &well_known
        && is_found(response)
    {
        return grade(host, &well_known_url, response, now);
    }

    let legacy_url = format!("https://{host}/security.txt");
    if let Ok(response) = fetch(client, &legacy_url, true).await
        && is_found(&response)
    {
        let mut findings = vec![finding(
            host,
            Severity::Warn,
            format!("found only at {legacy_url}; serve it at /.well-known/security.txt"),
        )];
        findings.extend(grade(host, &legacy_url, &response, now));
        return findings;
    }

    let reason = match well_known {
        Ok(response) => format!("{well_known_url} returned {}", describe_miss(&response)),
        Err(err) => format!("{well_known_url}: {err}"),
    };
    vec![finding(
        host,
        Severity::Fail,
        format!("no security.txt; {reason}"),
    )]
}

fn finding(host: &str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: host.to_string(),
        check: CHECK,
        severity,
        message,
    }
}

fn grade(host: &str, url: &str, response: &Response, now: Timestamp) -> Vec<Finding> {
    let result = |severity, message| finding(host, severity, message);

    if response.truncated {
        return vec![result(
            Severity::Fail,
            format!("{url} is larger than {} KiB", MAX_BODY_BYTES / 1024),
        )];
    }
    let Ok(text) = std::str::from_utf8(&response.body) else {
        return vec![result(Severity::Fail, format!("{url} is not valid UTF-8"))];
    };

    let mut findings = Vec::new();

    let content_type = response.content_type().unwrap_or_default();
    let declares_utf8 = content_type.split(';').skip(1).any(|param| {
        param.split_once('=').is_some_and(|(k, v)| {
            k.trim().eq_ignore_ascii_case("charset")
                && v.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
        })
    });
    if !declares_utf8 {
        findings.push(result(
            Severity::Warn,
            format!("Content-Type {content_type:?} does not declare charset=utf-8"),
        ));
    }

    let fields = parse_fields(text);
    let values = |name: &str| -> Vec<&str> {
        fields
            .iter()
            .filter(|(field, _)| field == name)
            .map(|(_, value)| *value)
            .collect()
    };

    let contacts = values("contact");
    if contacts.is_empty() {
        findings.push(result(Severity::Fail, "no Contact field".to_string()));
    } else {
        for contact in &contacts {
            match contact.split_once(':').map(|(scheme, _)| scheme) {
                Some(scheme) if is_uri_scheme(scheme) => {
                    if scheme.eq_ignore_ascii_case("http") {
                        findings.push(result(
                            Severity::Fail,
                            format!("Contact {contact} must use https"),
                        ));
                    }
                }
                _ => findings.push(result(
                    Severity::Fail,
                    format!("Contact value {contact:?} is not a URI"),
                )),
            }
        }
        findings.push(result(
            Severity::Pass,
            format!("Contact: {}", contacts.join(", ")),
        ));
    }

    findings.push(check_expires(host, &values("expires"), now));

    let canonical = values("canonical");
    if !canonical.is_empty()
        && !canonical
            .iter()
            .any(|value| *value == url || *value == response.final_url)
    {
        findings.push(result(
            Severity::Warn,
            format!("Canonical does not list {url}"),
        ));
    }

    findings
}

fn check_expires(host: &str, values: &[&str], now: Timestamp) -> Finding {
    let result = |severity, message| finding(host, severity, message);

    let value = match values {
        [value] => *value,
        [] => return result(Severity::Fail, "no Expires field".to_string()),
        _ => {
            return result(
                Severity::Fail,
                format!("{} Expires fields; only one is allowed", values.len()),
            );
        }
    };
    let Ok(expires) = value.parse::<Timestamp>() else {
        return result(
            Severity::Fail,
            format!("Expires value {value:?} is not an RFC 3339 date-time"),
        );
    };

    let date = expires.strftime("%Y-%m-%d");
    let days = expires.duration_since(now).as_secs() / SECONDS_PER_DAY;
    if expires <= now {
        result(Severity::Fail, format!("expired on {date}"))
    } else if days > 366 {
        result(
            Severity::Warn,
            format!("expires {date}, more than a year ahead; RFC 9116 recommends less"),
        )
    } else if days < 30 {
        result(Severity::Warn, format!("expires {date}, in {days} days"))
    } else {
        result(Severity::Pass, format!("expires {date}"))
    }
}

fn is_uri_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Returns the fields as (lowercase name, value) pairs, in file order.
fn parse_fields(text: &str) -> Vec<(String, &str)> {
    signed_content(text)
        .into_iter()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim()))
        .collect()
}

/// Returns the lines of the file, or only the signed lines if the file is an
/// OpenPGP cleartext-signed message (RFC 4880, section 7).
fn signed_content(text: &str) -> Vec<&str> {
    let mut lines = text.lines().map(|line| line.trim_end_matches('\r'));
    let is_signed = text
        .trim_start()
        .starts_with("-----BEGIN PGP SIGNED MESSAGE-----");
    if !is_signed {
        return lines.collect();
    }

    lines
        .by_ref()
        .find(|line| line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"));
    lines.by_ref().find(|line| line.trim().is_empty());
    lines
        .take_while(|line| !line.starts_with("-----BEGIN PGP SIGNATURE-----"))
        .map(|line| line.strip_prefix("- ").unwrap_or(line))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://example.com/.well-known/security.txt";

    fn now() -> Timestamp {
        "2026-11-08T12:00:00Z".parse().unwrap()
    }

    fn response_with(content_type: &str, body: &str) -> Response {
        let mut response = crate::http::response(200, &[("content-type", content_type)], body);
        response.final_url = URL.to_string();
        response
    }

    fn response(body: &str) -> Response {
        response_with("text/plain; charset=utf-8", body)
    }

    fn results(response: &Response) -> Vec<(Severity, String)> {
        grade("example.com", URL, response, now())
            .into_iter()
            .map(|f| (f.severity, f.message))
            .collect()
    }

    fn result(severity: Severity, message: &str) -> (Severity, String) {
        (severity, message.to_string())
    }

    #[test]
    fn valid_file_passes() {
        let response = response(
            "# Our security policy
Contact: mailto:security@example.com
contact: https://example.com/security
Expires: 2027-06-30T23:00:00.000Z
Canonical: https://example.com/.well-known/security.txt
",
        );
        assert_eq!(
            results(&response),
            [
                result(
                    Severity::Pass,
                    "Contact: mailto:security@example.com, https://example.com/security"
                ),
                result(Severity::Pass, "expires 2027-06-30"),
            ]
        );
    }

    #[test]
    fn missing_required_fields_fail() {
        assert_eq!(
            results(&response("Policy: https://example.com/policy\n")),
            [
                result(Severity::Fail, "no Contact field"),
                result(Severity::Fail, "no Expires field"),
            ]
        );
    }

    #[test]
    fn expires_grades() {
        for (expires, expected) in [
            (
                "2026-11-01T00:00:00Z",
                result(Severity::Fail, "expired on 2026-11-01"),
            ),
            (
                "2026-11-20T00:00:00Z",
                result(Severity::Warn, "expires 2026-11-20, in 11 days"),
            ),
            (
                "2028-01-01T00:00:00Z",
                result(
                    Severity::Warn,
                    "expires 2028-01-01, more than a year ahead; RFC 9116 recommends less",
                ),
            ),
            (
                "2027-06-30",
                result(
                    Severity::Fail,
                    "Expires value \"2027-06-30\" is not an RFC 3339 date-time",
                ),
            ),
        ] {
            let findings = results(&response(&format!(
                "Contact: mailto:s@example.com\nExpires: {expires}\n"
            )));
            assert_eq!(findings[1], expected, "{expires}");
        }
    }

    #[test]
    fn duplicate_expires_fails() {
        let findings = results(&response(
            "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nExpires: 2027-02-01T00:00:00Z\n",
        ));
        assert_eq!(
            findings[1],
            result(Severity::Fail, "2 Expires fields; only one is allowed")
        );
    }

    #[test]
    fn invalid_contacts_fail() {
        let findings = results(&response(
            "Contact: security@example.com\nContact: http://example.com/security\nExpires: 2027-01-01T00:00:00Z\n",
        ));
        assert_eq!(
            &findings[..2],
            [
                result(
                    Severity::Fail,
                    "Contact value \"security@example.com\" is not a URI"
                ),
                result(
                    Severity::Fail,
                    "Contact http://example.com/security must use https"
                ),
            ]
        );
    }

    #[test]
    fn canonical_mismatch_warns() {
        let findings = results(&response(
            "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\nCanonical: https://other.example/.well-known/security.txt\n",
        ));
        assert_eq!(
            findings.last().unwrap(),
            &result(
                Severity::Warn,
                "Canonical does not list https://example.com/.well-known/security.txt"
            )
        );
    }

    #[test]
    fn missing_charset_warns() {
        let response = response_with(
            "text/plain",
            "Contact: mailto:s@example.com\nExpires: 2027-01-01T00:00:00Z\n",
        );
        assert_eq!(
            results(&response)[0],
            result(
                Severity::Warn,
                "Content-Type \"text/plain\" does not declare charset=utf-8"
            )
        );
    }

    #[test]
    fn signed_file_is_unwrapped() {
        let response = response(
            "-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00Z
- -dash-escaped line
-----BEGIN PGP SIGNATURE-----

Contact: mailto:not-signed@example.com
-----END PGP SIGNATURE-----
",
        );
        assert_eq!(
            results(&response),
            [
                result(Severity::Pass, "Contact: mailto:security@example.com"),
                result(Severity::Pass, "expires 2027-01-01"),
            ]
        );
    }

    #[test]
    fn html_fallback_page_is_not_found() {
        let response = response_with("text/html; charset=utf-8", "<!doctype html>");
        assert!(!is_found(&response));
        assert_eq!(
            describe_miss(&response),
            "text/html; charset=utf-8 instead of text/plain"
        );
    }

    #[test]
    fn invalid_utf8_fails() {
        let mut response = response("");
        response.body = vec![0xff, 0xfe];
        assert_eq!(
            results(&response),
            [result(
                Severity::Fail,
                format!("{URL} is not valid UTF-8").as_str()
            )]
        );
    }
}
