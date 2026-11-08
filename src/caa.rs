use std::collections::BTreeSet;

use crate::finding::{Finding, Severity};
use crate::zone::{RecordData, Zone};

/// Tags registered with IANA. CAs must refuse to issue when they encounter an
/// unknown tag with the critical flag set (RFC 8659, section 4.1).
const KNOWN_TAGS: &[&str] = &[
    "issue",
    "issuewild",
    "iodef",
    "issuemail",
    "issuevmc",
    "contactemail",
    "contactphone",
];

struct Property<'a> {
    critical: bool,
    tag: &'a str,
    value: &'a str,
}

/// CAs search for CAA records from the requested name up towards the root and
/// use the first record set they find, so a set at the apex covers every name
/// in the zone that has no set of its own. The apex comes first, the other
/// owners are sorted.
pub fn audit(zone: &Zone) -> Vec<Finding> {
    let owners: BTreeSet<&str> = zone
        .records
        .iter()
        .filter(|r| matches!(r.data, RecordData::Caa { .. }))
        .map(|r| r.name.as_str())
        .collect();

    let mut findings = Vec::new();
    if !owners.contains(zone.apex.as_str()) {
        findings.push(finding(
            &zone.apex,
            Severity::Fail,
            format!(
                "no CAA records; any CA may issue certificates for {} and its subdomains",
                zone.apex
            ),
        ));
    }

    let apex = owners.iter().filter(|owner| **owner == zone.apex);
    let others = owners.iter().filter(|owner| **owner != zone.apex);
    for owner in apex.chain(others) {
        let properties: Vec<Property> = zone
            .records_at(owner)
            .filter_map(|data| match data {
                RecordData::Caa {
                    critical,
                    tag,
                    value,
                } => Some(Property {
                    critical: *critical,
                    tag,
                    value,
                }),
                _ => None,
            })
            .collect();
        findings.extend(check_record_set(owner, &properties));
    }

    findings
}

fn finding(subject: &str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: subject.to_string(),
        check: "CAA",
        severity,
        message,
    }
}

fn check_record_set(owner: &str, properties: &[Property]) -> Vec<Finding> {
    let caa = |severity, message| finding(owner, severity, message);
    let values = |tag: &str| -> Vec<&str> {
        properties
            .iter()
            .filter(|p| p.tag == tag)
            .map(|p| p.value)
            .collect()
    };
    let mut findings = Vec::new();

    for property in properties {
        if property.critical && !KNOWN_TAGS.contains(&property.tag) {
            findings.push(caa(
                Severity::Fail,
                format!(
                    "unknown tag {} is marked critical; CAs refuse to issue any certificate",
                    property.tag
                ),
            ));
        }
    }

    let issue = values("issue");
    findings.extend(check_issuers(owner, "issue", &issue));

    let issuewild = values("issuewild");
    let issue_allows_some_ca = issue.iter().any(|value| issuer(value).is_some());
    if issuewild.is_empty() {
        if issue_allows_some_ca {
            findings.push(caa(
                Severity::Warn,
                "no issuewild tag; the CAs in issue may also issue wildcard certificates"
                    .to_string(),
            ));
        }
    } else {
        findings.extend(check_issuers(owner, "issuewild", &issuewild));
    }

    let iodef = values("iodef");
    if iodef.is_empty() {
        findings.push(caa(
            Severity::Warn,
            "no iodef tag; CAs cannot report requests that violate the policy".to_string(),
        ));
    }
    for url in iodef {
        let scheme = url
            .split_once(':')
            .map(|(scheme, _)| scheme.to_ascii_lowercase());
        if !matches!(scheme.as_deref(), Some("mailto" | "http" | "https")) {
            findings.push(caa(
                Severity::Fail,
                format!("iodef value {url:?} is not a mailto:, http: or https: URL"),
            ));
        }
    }

    findings
}

/// Returns the issuer domain of an `issue` or `issuewild` value, or `None` if
/// the value authorizes no CA (e.g. `";"`).
fn issuer(value: &str) -> Option<String> {
    let domain = value.split(';').next().unwrap_or_default().trim();
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

fn is_domain_name(name: &str) -> bool {
    name.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn check_issuers(owner: &str, tag: &str, values: &[&str]) -> Vec<Finding> {
    let caa = |severity, message| finding(owner, severity, message);

    if values.is_empty() {
        return vec![caa(
            Severity::Fail,
            format!("no {tag} tag; any CA may issue certificates"),
        )];
    }

    let issuers: BTreeSet<String> = values.iter().filter_map(|value| issuer(value)).collect();
    let mut findings = Vec::new();

    for issuer in issuers.iter().filter(|issuer| !is_domain_name(issuer)) {
        findings.push(caa(
            Severity::Warn,
            format!("{tag} value {issuer:?} is not a valid CA domain name"),
        ));
    }

    let kind = if tag == "issuewild" {
        "wildcard certificates"
    } else {
        "certificates"
    };
    let summary = if issuers.is_empty() {
        format!("{tag} \";\": no CA may issue {kind}")
    } else {
        let list: Vec<&str> = issuers.iter().map(String::as_str).collect();
        format!("{tag}: {}", list.join(", "))
    };
    findings.insert(0, caa(Severity::Pass, summary));

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zone::parse_str;

    fn zone(records: &str) -> Zone {
        parse_str(&format!(
            "$ORIGIN example.com.\n$TTL 300\n@ SOA ns admin 1 3600 600 86400 300\n{records}"
        ))
        .unwrap()
    }

    fn results(zone: &Zone) -> Vec<(String, Severity, String)> {
        audit(zone)
            .into_iter()
            .map(|f| (f.subject, f.severity, f.message))
            .collect()
    }

    fn result(subject: &str, severity: Severity, message: &str) -> (String, Severity, String) {
        (subject.to_string(), severity, message.to_string())
    }

    #[test]
    fn missing_at_apex_fails() {
        let zone = zone("www A 192.0.2.1\n");
        assert_eq!(
            results(&zone),
            [result(
                "example.com",
                Severity::Fail,
                "no CAA records; any CA may issue certificates for example.com and its subdomains"
            )]
        );
    }

    #[test]
    fn complete_record_set_passes() {
        let zone = zone(
            "@ CAA 0 issue \"letsencrypt.org\"
@ CAA 0 issue \"Pki.Goog; cansignhttpexchanges=yes\"
@ CAA 0 issuewild \";\"
@ CAA 0 iodef \"mailto:security@example.com\"
",
        );
        assert_eq!(
            results(&zone),
            [
                result(
                    "example.com",
                    Severity::Pass,
                    "issue: letsencrypt.org, pki.goog"
                ),
                result(
                    "example.com",
                    Severity::Pass,
                    "issuewild \";\": no CA may issue wildcard certificates"
                ),
            ]
        );
    }

    #[test]
    fn deny_all_needs_no_issuewild() {
        let zone = zone("@ CAA 0 issue \";\"\n@ CAA 0 iodef \"https://example.com/caa\"\n");
        assert_eq!(
            results(&zone),
            [result(
                "example.com",
                Severity::Pass,
                "issue \";\": no CA may issue certificates"
            )]
        );
    }

    #[test]
    fn missing_tags_are_reported() {
        let zone = zone("@ CAA 0 issuewild \"letsencrypt.org\"\n");
        assert_eq!(
            results(&zone),
            [
                result(
                    "example.com",
                    Severity::Fail,
                    "no issue tag; any CA may issue certificates"
                ),
                result("example.com", Severity::Pass, "issuewild: letsencrypt.org"),
                result(
                    "example.com",
                    Severity::Warn,
                    "no iodef tag; CAs cannot report requests that violate the policy"
                ),
            ]
        );
    }

    #[test]
    fn missing_issuewild_warns() {
        let zone = zone(
            "@ CAA 0 issue \"letsencrypt.org\"\n@ CAA 0 iodef \"mailto:security@example.com\"\n",
        );
        assert_eq!(
            results(&zone)[1],
            result(
                "example.com",
                Severity::Warn,
                "no issuewild tag; the CAs in issue may also issue wildcard certificates"
            )
        );
    }

    #[test]
    fn invalid_values_are_reported() {
        let zone = zone(
            "@ CAA 0 issue \"not a domain\"
@ CAA 0 issuewild \";\"
@ CAA 0 iodef \"security@example.com\"
@ CAA 128 tbs \"unknown\"
@ CAA 128 issue \"letsencrypt.org\"
",
        );
        let findings = results(&zone);
        assert!(findings.contains(&result(
            "example.com",
            Severity::Fail,
            "unknown tag tbs is marked critical; CAs refuse to issue any certificate"
        )));
        assert!(findings.contains(&result(
            "example.com",
            Severity::Warn,
            "issue value \"not a domain\" is not a valid CA domain name"
        )));
        assert!(findings.contains(&result(
            "example.com",
            Severity::Fail,
            "iodef value \"security@example.com\" is not a mailto:, http: or https: URL"
        )));
        assert_eq!(
            findings
                .iter()
                .filter(|(_, severity, _)| *severity == Severity::Fail)
                .count(),
            2,
            "a known critical tag must not be reported: {findings:?}"
        );
    }

    #[test]
    fn subdomain_record_sets_are_checked_after_apex() {
        let zone = zone(
            "www CAA 0 issue \";\"
www CAA 0 iodef \"mailto:security@example.com\"
@ CAA 0 issue \"letsencrypt.org\"
@ CAA 0 issuewild \";\"
@ CAA 0 iodef \"mailto:security@example.com\"
",
        );
        let subjects: Vec<String> = results(&zone).into_iter().map(|(s, _, _)| s).collect();
        assert_eq!(subjects, ["example.com", "example.com", "www.example.com"]);
    }

    #[test]
    fn subdomain_record_set_without_apex_set() {
        let zone = zone("www CAA 0 issue \";\"\nwww CAA 0 iodef \"mailto:s@example.com\"\n");
        assert_eq!(
            results(&zone),
            [
                result(
                    "example.com",
                    Severity::Fail,
                    "no CAA records; any CA may issue certificates for example.com and its subdomains"
                ),
                result(
                    "www.example.com",
                    Severity::Pass,
                    "issue \";\": no CA may issue certificates"
                ),
            ]
        );
    }
}
