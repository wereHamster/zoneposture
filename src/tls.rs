use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::future::join_all;
use jiff::Timestamp;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    AlertDescription, CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore,
    SignatureScheme,
};
use tokio::net::{TcpStream, lookup_host};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;

use crate::caa;
use crate::finding::{Finding, Severity};
use crate::zone::{RecordData, Zone, non_public_range};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

/// Certificates are verified with webpki against the Mozilla root store rather
/// than the operating system's verifier, because some system verifiers fetch
/// missing intermediate certificates themselves and would hide incomplete
/// chains.
pub struct Context {
    provider: Arc<CryptoProvider>,
    verifier: Arc<WebPkiServerVerifier>,
}

impl Context {
    pub fn new() -> Result<Context, Box<dyn std::error::Error>> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let roots = Arc::new(RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        });
        let verifier =
            WebPkiServerVerifier::builder_with_provider(roots, provider.clone()).build()?;
        Ok(Context { provider, verifier })
    }
}

/// Records the verdict of the real verifier and the presented chain, but
/// lets the handshake continue so that invalid certificates can be
/// inspected. Handshake signatures are still verified.
#[derive(Debug)]
struct Recorder {
    inner: Arc<WebPkiServerVerifier>,
    captured: Mutex<Option<(Vec<CertificateDer<'static>>, Verdict)>>,
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let chain = std::iter::once(end_entity)
            .chain(intermediates)
            .map(|cert| cert.clone().into_owned())
            .collect();
        *self.captured.lock().unwrap() = Some((chain, Verdict::from(result)));
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    Valid,
    Expired,
    NotYetValid,
    WrongName,
    UnknownIssuer,
    Invalid(String),
}

impl From<Result<ServerCertVerified, rustls::Error>> for Verdict {
    fn from(result: Result<ServerCertVerified, rustls::Error>) -> Verdict {
        match result {
            Ok(_) => Verdict::Valid,
            Err(rustls::Error::InvalidCertificate(err)) => match err {
                CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                    Verdict::Expired
                }
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                    Verdict::NotYetValid
                }
                CertificateError::NotValidForName
                | CertificateError::NotValidForNameContext { .. } => Verdict::WrongName,
                CertificateError::UnknownIssuer => Verdict::UnknownIssuer,
                err => Verdict::Invalid(rustls::Error::InvalidCertificate(err).to_string()),
            },
            Err(err) => Verdict::Invalid(err.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertInfo {
    not_after: Timestamp,
    issuer_organization: Option<String>,
    issuer_common_name: Option<String>,
    names: Vec<String>,
}

fn first<'a>(
    mut values: impl Iterator<Item = &'a x509_parser::x509::AttributeTypeAndValue<'a>>,
) -> Option<String> {
    values
        .next()
        .and_then(|value| value.as_str().ok())
        .map(str::to_string)
}
impl CertInfo {
    fn parse(der: &[u8]) -> Option<CertInfo> {
        let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
        let names = match cert.subject_alternative_name() {
            Ok(Some(extension)) => extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DNSName(name) => Some(name.to_ascii_lowercase()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        Some(CertInfo {
            not_after: Timestamp::from_second(cert.validity().not_after.timestamp()).ok()?,
            issuer_organization: first(cert.issuer().iter_organization()),
            issuer_common_name: first(cert.issuer().iter_common_name()),
            names,
        })
    }

    fn issuer(&self) -> String {
        match (&self.issuer_organization, &self.issuer_common_name) {
            (Some(organization), Some(name)) => format!("{organization} ({name})"),
            (Some(value), None) | (None, Some(value)) => value.clone(),
            (None, None) => "an unnamed issuer".to_string(),
        }
    }

    fn has_wildcard(&self) -> bool {
        self.names.iter().any(|name| name.starts_with("*."))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// An IPv6 address could not be reached because this machine has no IPv6
    /// route, which says nothing about the server.
    NoIpv6Route,
    ConnectFailed(String),
    HandshakeFailed(String),
    Certificate {
        info: CertInfo,
        verdict: Verdict,
    },
}

/// Connects to every public address of `host` and checks the certificate
/// each one presents, then compares the issuer with the zone's CAA records.
pub async fn check_host(
    context: &Context,
    zone: &Zone,
    host: &str,
    now: Timestamp,
) -> Vec<Finding> {
    let addresses = match addresses(zone, host).await {
        Ok(addresses) if !addresses.is_empty() => addresses,
        Ok(_) => {
            return vec![finding(
                host,
                "Certificate",
                Severity::Fail,
                format!("{host} has no public addresses"),
            )];
        }
        Err(err) => {
            return vec![finding(
                host,
                "Certificate",
                Severity::Fail,
                format!("cannot resolve {host}: {err}"),
            )];
        }
    };

    let outcomes: Vec<(IpAddr, Outcome)> = join_all(
        addresses
            .iter()
            .map(|addr| async move { (*addr, probe(context, host, *addr).await) }),
    )
    .await;

    let mut findings = grade_addresses(host, &outcomes, now);
    findings.extend(check_caa(zone, host, &outcomes));
    findings
}

async fn addresses(zone: &Zone, host: &str) -> io::Result<Vec<IpAddr>> {
    let mut addresses: Vec<IpAddr> = zone
        .records_at(host)
        .filter_map(|data| match data {
            RecordData::A(addr) => Some(IpAddr::V4(*addr)),
            RecordData::Aaaa(addr) => Some(IpAddr::V6(*addr)),
            _ => None,
        })
        .collect();
    if addresses.is_empty() {
        for addr in lookup_host((host, 443)).await? {
            if !addresses.contains(&addr.ip()) {
                addresses.push(addr.ip());
            }
        }
    }
    addresses.retain(|addr| non_public_range(addr).is_none());
    Ok(addresses)
}

async fn probe(context: &Context, host: &str, addr: IpAddr) -> Outcome {
    let Ok(server_name) = ServerName::try_from(host.to_string()) else {
        return Outcome::HandshakeFailed(format!("{host} is not a valid server name"));
    };

    let tcp = match timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect(SocketAddr::new(addr, 443)),
    )
    .await
    {
        Err(_) => return Outcome::ConnectFailed("connection timed out".to_string()),
        Ok(Err(err))
            if addr.is_ipv6()
                && matches!(
                    err.kind(),
                    io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable
                ) =>
        {
            return Outcome::NoIpv6Route;
        }
        Ok(Err(err)) => return Outcome::ConnectFailed(err.to_string()),
        Ok(Ok(tcp)) => tcp,
    };

    let recorder = Arc::new(Recorder {
        inner: context.verifier.clone(),
        captured: Mutex::new(None),
    });
    let config = match ClientConfig::builder_with_provider(context.provider.clone())
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(recorder.clone())
            .with_no_client_auth(),
        Err(err) => return Outcome::HandshakeFailed(err.to_string()),
    };

    let handshake = timeout(
        HANDSHAKE_TIMEOUT,
        TlsConnector::from(Arc::new(config)).connect(server_name, tcp),
    )
    .await;
    let captured = recorder.captured.lock().unwrap().take();

    match (handshake, captured) {
        (_, Some((chain, verdict))) => match chain.first().and_then(|der| CertInfo::parse(der)) {
            Some(info) => Outcome::Certificate { info, verdict },
            None => Outcome::HandshakeFailed("cannot parse the server certificate".to_string()),
        },
        (Ok(Ok(_)), None) => {
            Outcome::HandshakeFailed("the server presented no certificate".to_string())
        }
        (Ok(Err(err)), None) => Outcome::HandshakeFailed(describe_handshake_error(host, &err)),
        (Err(_), None) => Outcome::HandshakeFailed("handshake timed out".to_string()),
    }
}

fn describe_handshake_error(host: &str, err: &io::Error) -> String {
    let rustls_error = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
    match rustls_error {
        Some(
            err @ rustls::Error::AlertReceived(
                AlertDescription::InternalError
                | AlertDescription::UnrecognisedName
                | AlertDescription::HandshakeFailure,
            ),
        ) => format!("{err}; the server likely has no certificate for {host}"),
        Some(err) => err.to_string(),
        None => err.to_string(),
    }
}

fn finding(host: &str, check: &'static str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: host.to_string(),
        check,
        severity,
        message,
    }
}

fn grade_outcome(host: &str, outcome: &Outcome, now: Timestamp) -> (Severity, String) {
    match outcome {
        Outcome::NoIpv6Route => (
            Severity::Info,
            "not checked; this machine has no IPv6 route".to_string(),
        ),
        Outcome::ConnectFailed(err) => {
            (Severity::Fail, format!("cannot connect to port 443: {err}"))
        }
        Outcome::HandshakeFailed(err) => (Severity::Fail, format!("TLS handshake failed: {err}")),
        Outcome::Certificate { info, verdict } => {
            let issuer = info.issuer();
            let date = info.not_after.strftime("%Y-%m-%d");
            match verdict {
                Verdict::Valid => {
                    let days = info.not_after.duration_since(now).as_secs() / SECONDS_PER_DAY;
                    let severity = if days < 14 {
                        Severity::Fail
                    } else if days < 30 {
                        Severity::Warn
                    } else {
                        Severity::Pass
                    };
                    (
                        severity,
                        format!("valid; issued by {issuer}, expires {date} (in {days} days)"),
                    )
                }
                Verdict::Expired => (
                    Severity::Fail,
                    format!("expired on {date}; issued by {issuer}"),
                ),
                Verdict::NotYetValid => {
                    (Severity::Fail, format!("not valid yet; issued by {issuer}"))
                }
                Verdict::WrongName => (
                    Severity::Fail,
                    format!(
                        "not valid for {host}; it covers {}",
                        summarize_names(&info.names)
                    ),
                ),
                Verdict::UnknownIssuer => (
                    Severity::Fail,
                    format!(
                        "chain does not lead to a trusted root; issued by {issuer}. The server may not send its intermediate certificates"
                    ),
                ),
                Verdict::Invalid(err) => (Severity::Fail, format!("invalid: {err}")),
            }
        }
    }
}

fn summarize_names(names: &[String]) -> String {
    const SHOWN: usize = 4;
    match names.len() {
        0 => "no DNS names".to_string(),
        n if n <= SHOWN => names.join(", "),
        n => format!("{} and {} more", names[..SHOWN].join(", "), n - SHOWN),
    }
}

/// Reports once per host when every reachable address gives the same result,
/// and per address otherwise.
fn grade_addresses(host: &str, outcomes: &[(IpAddr, Outcome)], now: Timestamp) -> Vec<Finding> {
    let (untested, tested): (Vec<_>, Vec<_>) = outcomes
        .iter()
        .map(|(addr, outcome)| (addr, grade_outcome(host, outcome, now)))
        .partition(|(_, (severity, _))| *severity == Severity::Info);

    let mut findings = Vec::new();
    let all_same = tested.windows(2).all(|pair| pair[0].1 == pair[1].1);
    if all_same && let Some((_, (severity, message))) = tested.first() {
        findings.push(finding(host, "Certificate", *severity, message.clone()));
    } else {
        for (addr, (severity, message)) in &tested {
            findings.push(finding(
                host,
                "Certificate",
                *severity,
                format!("{addr}: {message}"),
            ));
        }
    }
    for (addr, (severity, message)) in untested {
        findings.push(finding(
            host,
            "Certificate",
            severity,
            format!("{addr}: {message}"),
        ));
    }
    findings
}

/// CAA identifiers of common CAs, matched against the organization of the
/// certificate's issuer. Taken from the CAs' published CAA domains.
const CA_DOMAINS: &[(&str, &[&str])] = &[
    ("let's encrypt", &["letsencrypt.org"]),
    ("google trust services", &["pki.goog"]),
    (
        "digicert",
        &[
            "digicert.com",
            "symantec.com",
            "thawte.com",
            "geotrust.com",
            "rapidssl.com",
            "digicert.ne.jp",
        ],
    ),
    (
        "sectigo",
        &[
            "sectigo.com",
            "comodoca.com",
            "comodo.com",
            "usertrust.com",
            "trust-provider.com",
        ],
    ),
    ("zerossl", &["sectigo.com"]),
    (
        "amazon",
        &[
            "amazon.com",
            "amazontrust.com",
            "awstrust.com",
            "amazonaws.com",
        ],
    ),
    ("microsoft", &["microsoft.com"]),
    ("globalsign", &["globalsign.com"]),
    ("entrust", &["entrust.net"]),
    ("ssl corporation", &["ssl.com"]),
    ("buypass", &["buypass.com", "buypass.no"]),
    ("certainly", &["certainly.com"]),
    ("harica", &["harica.gr"]),
    ("actalis", &["actalis.it"]),
];

fn ca_domains(organization: &str) -> Option<&'static [&'static str]> {
    let organization = organization.to_ascii_lowercase();
    CA_DOMAINS
        .iter()
        .find(|(pattern, _)| organization.contains(pattern))
        .map(|(_, domains)| *domains)
}

fn check_caa(zone: &Zone, host: &str, outcomes: &[(IpAddr, Outcome)]) -> Vec<Finding> {
    let mut certificates: Vec<&CertInfo> = Vec::new();
    for (_, outcome) in outcomes {
        if let Outcome::Certificate { info, .. } = outcome
            && !certificates
                .iter()
                .any(|seen| seen.issuer_organization == info.issuer_organization)
        {
            certificates.push(info);
        }
    }

    let cname_target = zone.records_at(host).find_map(|data| match data {
        RecordData::Cname(target) => Some(target.as_str()),
        _ => None,
    });

    certificates
        .into_iter()
        .filter_map(|info| {
            let (owner, allowed) = caa::allowed_issuers(zone, host, info.has_wildcard())?;
            let (severity, message) = grade_caa(
                info.issuer_organization.as_deref(),
                &owner,
                &allowed,
                cname_target,
            );
            Some(finding(host, "CAA", severity, message))
        })
        .collect()
}

fn grade_caa(
    organization: Option<&str>,
    owner: &str,
    allowed: &[String],
    cname_target: Option<&str>,
) -> (Severity, String) {
    let Some(organization) = organization else {
        return (
            Severity::Warn,
            format!(
                "the certificate's issuer has no organization; compare it with the CAA records at {owner} manually"
            ),
        );
    };
    let Some(domains) = ca_domains(organization) else {
        return (
            Severity::Warn,
            format!(
                "cannot map issuer {organization} to a CAA domain; compare it with the CAA records at {owner} manually"
            ),
        );
    };

    if let Some(domain) = domains
        .iter()
        .find(|domain| allowed.iter().any(|a| a == *domain))
    {
        return (
            Severity::Pass,
            format!("issuer {organization} ({domain}) is allowed by CAA at {owner}"),
        );
    }

    let allows = if allowed.is_empty() {
        "no CA".to_string()
    } else {
        allowed.join(", ")
    };
    let message = format!(
        "issuer {organization} ({}) is not allowed by CAA at {owner}, which allows {allows}; renewals will fail",
        domains[0]
    );
    match cname_target {
        Some(target) => (
            Severity::Warn,
            format!("{message}, unless CAA records at {target} take precedence"),
        ),
        None => (Severity::Fail, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        "2026-11-08T12:00:00Z".parse().unwrap()
    }

    fn info(not_after: &str) -> CertInfo {
        CertInfo {
            not_after: not_after.parse().unwrap(),
            issuer_organization: Some("Let's Encrypt".to_string()),
            issuer_common_name: Some("R11".to_string()),
            names: vec!["example.com".to_string(), "www.example.com".to_string()],
        }
    }

    fn certificate(not_after: &str, verdict: Verdict) -> Outcome {
        Outcome::Certificate {
            info: info(not_after),
            verdict,
        }
    }

    fn grade(outcome: Outcome) -> (Severity, String) {
        grade_outcome("example.com", &outcome, now())
    }

    #[test]
    fn valid_certificate_expiry_grades() {
        assert_eq!(
            grade(certificate("2027-01-30T00:00:00Z", Verdict::Valid)),
            (
                Severity::Pass,
                "valid; issued by Let's Encrypt (R11), expires 2027-01-30 (in 82 days)".to_string()
            )
        );
        assert_eq!(
            grade(certificate("2026-11-30T00:00:00Z", Verdict::Valid)).0,
            Severity::Warn
        );
        assert_eq!(
            grade(certificate("2026-11-15T00:00:00Z", Verdict::Valid)).0,
            Severity::Fail
        );
    }

    #[test]
    fn invalid_certificates_fail() {
        assert_eq!(
            grade(certificate("2026-10-01T00:00:00Z", Verdict::Expired)),
            (
                Severity::Fail,
                "expired on 2026-10-01; issued by Let's Encrypt (R11)".to_string()
            )
        );
        assert_eq!(
            grade(certificate("2027-01-30T00:00:00Z", Verdict::WrongName)),
            (
                Severity::Fail,
                "not valid for example.com; it covers example.com, www.example.com".to_string()
            )
        );
        assert!(
            grade(certificate("2027-01-30T00:00:00Z", Verdict::UnknownIssuer))
                .1
                .contains("intermediate certificates")
        );
    }

    #[test]
    fn many_names_are_summarized() {
        let names: Vec<String> = (1..=6).map(|i| format!("h{i}.example.com")).collect();
        assert_eq!(
            summarize_names(&names),
            "h1.example.com, h2.example.com, h3.example.com, h4.example.com and 2 more"
        );
    }

    #[test]
    fn identical_addresses_are_reported_once() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let ok = certificate("2027-01-30T00:00:00Z", Verdict::Valid);

        let findings = grade_addresses("example.com", &[(v4, ok.clone()), (v6, ok.clone())], now());
        assert_eq!(findings.len(), 1);
        assert!(!findings[0].message.starts_with("192.0.2.1"));

        let findings = grade_addresses(
            "example.com",
            &[
                (v4, ok),
                (v6, Outcome::ConnectFailed("refused".to_string())),
            ],
            now(),
        );
        let messages: Vec<&str> = findings.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(
            messages,
            [
                "192.0.2.1: valid; issued by Let's Encrypt (R11), expires 2027-01-30 (in 82 days)",
                "2001:db8::1: cannot connect to port 443: refused",
            ]
        );
    }

    #[test]
    fn missing_ipv6_route_is_informational() {
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let findings = grade_addresses(
            "example.com",
            &[
                (v4, certificate("2027-01-30T00:00:00Z", Verdict::Valid)),
                (v6, Outcome::NoIpv6Route),
            ],
            now(),
        );
        let results: Vec<(Severity, &str)> = findings
            .iter()
            .map(|f| (f.severity, f.message.as_str()))
            .collect();
        assert_eq!(
            results,
            [
                (
                    Severity::Pass,
                    "valid; issued by Let's Encrypt (R11), expires 2027-01-30 (in 82 days)"
                ),
                (
                    Severity::Info,
                    "2001:db8::1: not checked; this machine has no IPv6 route"
                ),
            ]
        );
    }

    #[test]
    fn caa_comparison() {
        let allowed = vec!["letsencrypt.org".to_string(), "pki.goog".to_string()];
        assert_eq!(
            grade_caa(Some("Google Trust Services"), "example.com", &allowed, None),
            (
                Severity::Pass,
                "issuer Google Trust Services (pki.goog) is allowed by CAA at example.com"
                    .to_string()
            )
        );
        assert_eq!(
            grade_caa(Some("DigiCert Inc"), "example.com", &allowed, None),
            (
                Severity::Fail,
                "issuer DigiCert Inc (digicert.com) is not allowed by CAA at example.com, which allows letsencrypt.org, pki.goog; renewals will fail"
                    .to_string()
            )
        );
        assert_eq!(
            grade_caa(
                Some("DigiCert Inc"),
                "example.com",
                &[],
                Some("cdn.example.net")
            )
            .0,
            Severity::Warn
        );
        assert_eq!(
            grade_caa(Some("Example CA"), "example.com", &allowed, None).0,
            Severity::Warn
        );
    }
}
