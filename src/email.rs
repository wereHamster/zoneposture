use std::collections::BTreeSet;

use crate::finding::{Finding, Severity};
use crate::zone::{RecordData, Zone};

/// Returns the zone's mail domains: the apex, plus every name that has MX or
/// SPF records, a DMARC record under `_dmarc.<name>`, or DKIM keys under
/// `<selector>._domainkey.<name>`. The apex comes first, the rest are sorted.
pub fn mail_domains(zone: &Zone) -> Vec<String> {
    let mut domains = BTreeSet::new();

    for record in &zone.records {
        let name = record.name.as_str();
        let is_mail_record = match &record.data {
            RecordData::Mx(_) => true,
            RecordData::Txt(text) => is_spf(text),
            _ => false,
        };
        if is_mail_record {
            domains.insert(name.to_string());
        }
        if let Some(domain) = name.strip_prefix("_dmarc.") {
            domains.insert(domain.to_string());
        }
        if let Some(domain) = dkim_domain(name) {
            domains.insert(domain);
        }
    }

    domains.remove(&zone.apex);
    std::iter::once(zone.apex.clone()).chain(domains).collect()
}

pub fn audit(zone: &Zone) -> Vec<Finding> {
    mail_domains(zone)
        .iter()
        .flat_map(|domain| {
            let mut findings = check_spf(zone, domain);
            findings.extend(check_dmarc(zone, domain));
            findings
        })
        .collect()
}

fn dkim_domain(name: &str) -> Option<String> {
    let labels: Vec<&str> = name.split('.').collect();
    let index = labels.iter().position(|label| *label == "_domainkey")?;
    let domain = labels[index + 1..].join(".");
    (!domain.is_empty()).then_some(domain)
}

fn has_dkim(zone: &Zone, domain: &str) -> bool {
    zone.records
        .iter()
        .any(|r| dkim_domain(&r.name).as_deref() == Some(domain))
}

pub(crate) fn is_spf(text: &str) -> bool {
    let Some(prefix) = text.get(..6) else {
        return false;
    };
    prefix.eq_ignore_ascii_case("v=spf1") && text[6..].chars().next().is_none_or(|c| c == ' ')
}

fn finding(subject: &str, check: &'static str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: subject.to_string(),
        check,
        severity,
        message,
    }
}

fn check_spf(zone: &Zone, domain: &str) -> Vec<Finding> {
    let spf = |severity, message| vec![finding(domain, "SPF", severity, message)];
    let records: Vec<&str> = zone.txt_at(domain).filter(|text| is_spf(text)).collect();

    let record = match records.as_slice() {
        [record] => *record,
        [] => {
            let receives_or_signs = zone
                .records_at(domain)
                .any(|data| matches!(data, RecordData::Mx(_)))
                || has_dkim(zone, domain);
            let message = if receives_or_signs {
                "no SPF record".to_string()
            } else {
                format!("no SPF record; publish \"v=spf1 -all\" if {domain} sends no mail")
            };
            return spf(Severity::Fail, message);
        }
        _ => {
            return spf(
                Severity::Fail,
                format!(
                    "{} SPF records; receivers treat this as a permanent error",
                    records.len()
                ),
            );
        }
    };

    let mut all = None;
    let mut redirect = None;
    for term in record.split_whitespace().skip(1) {
        let term = term.to_ascii_lowercase();
        if let Some(target) = term.strip_prefix("redirect=") {
            redirect = Some(target.to_string());
            continue;
        }
        let (qualifier, mechanism) = match term.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &term[1..]),
            _ => ('+', term.as_str()),
        };
        // Terms after `all` are never evaluated, and `redirect=` is ignored
        // when `all` is present.
        if mechanism == "all" {
            all = Some(qualifier);
            break;
        }
    }

    let (severity, verdict) = match (all, redirect) {
        (Some('-'), _) => (Severity::Pass, "ends in -all".to_string()),
        (Some('~'), _) => (
            Severity::Warn,
            "ends in ~all (softfail); unauthorized mail may still be accepted".to_string(),
        ),
        (Some('?'), _) => (
            Severity::Fail,
            "ends in ?all (neutral); unauthorized mail is not rejected".to_string(),
        ),
        (Some(_), _) => (
            Severity::Fail,
            "ends in +all; every host is authorized to send".to_string(),
        ),
        (None, Some(target)) => (
            Severity::Warn,
            format!("delegates to {target} via redirect=, which is not evaluated"),
        ),
        (None, None) => (
            Severity::Fail,
            "has no all mechanism; unauthorized mail defaults to neutral".to_string(),
        ),
    };
    spf(severity, format!("\"{record}\" {verdict}"))
}

#[derive(Debug)]
enum DmarcLookup {
    Missing,
    Multiple(usize),
    Delegated(String),
    Record(Vec<(String, String)>),
}

fn lookup_dmarc(zone: &Zone, domain: &str) -> DmarcLookup {
    let name = format!("_dmarc.{domain}");

    if let Some(target) = zone.records_at(&name).find_map(|data| match data {
        RecordData::Cname(target) => Some(target.clone()),
        _ => None,
    }) {
        return DmarcLookup::Delegated(target);
    }

    // Receivers discard TXT records at `_dmarc` that do not start with
    // `v=DMARC1`, so they neither count as a record nor as a duplicate.
    let mut records: Vec<Vec<(String, String)>> = zone
        .txt_at(&name)
        .map(parse_tags)
        .filter(|tags| tags.first().is_some_and(|(k, v)| k == "v" && v == "DMARC1"))
        .collect();

    match records.len() {
        0 => DmarcLookup::Missing,
        1 => DmarcLookup::Record(records.remove(0)),
        n => DmarcLookup::Multiple(n),
    }
}

fn parse_tags(text: &str) -> Vec<(String, String)> {
    text.split(';')
        .filter_map(|tag| tag.split_once('='))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect()
}

fn tag<'a>(tags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn policy_strength(policy: &str) -> Option<u8> {
    match policy.to_ascii_lowercase().as_str() {
        "none" => Some(0),
        "quarantine" => Some(1),
        "reject" => Some(2),
        _ => None,
    }
}

fn grade_policy(policy: &str) -> (Severity, &'static str) {
    match policy_strength(policy) {
        Some(2) | Some(1) => (Severity::Pass, ""),
        Some(_) => (
            Severity::Fail,
            "; it only monitors, spoofed mail is delivered",
        ),
        None => (Severity::Fail, "; not a valid policy"),
    }
}

fn check_dmarc(zone: &Zone, domain: &str) -> Vec<Finding> {
    let dmarc = |severity, message| finding(domain, "DMARC", severity, message);
    let name = format!("_dmarc.{domain}");

    let tags = match lookup_dmarc(zone, domain) {
        DmarcLookup::Record(tags) => tags,
        DmarcLookup::Multiple(n) => {
            return vec![dmarc(
                Severity::Fail,
                format!("{n} DMARC records at {name}; receivers ignore all of them"),
            )];
        }
        DmarcLookup::Delegated(target) => {
            return vec![dmarc(
                Severity::Warn,
                format!("{name} is a CNAME to {target}, which is not evaluated"),
            )];
        }
        DmarcLookup::Missing if domain != zone.apex => {
            return vec![inherited_dmarc(zone, domain)];
        }
        DmarcLookup::Missing => {
            return vec![dmarc(Severity::Fail, format!("no DMARC record at {name}"))];
        }
    };

    let Some(policy) = tag(&tags, "p") else {
        return vec![dmarc(
            Severity::Fail,
            format!("record at {name} has no p= tag"),
        )];
    };

    let (severity, note) = grade_policy(policy);
    let mut findings = vec![dmarc(severity, format!("p={policy}{note}"))];

    if domain == zone.apex
        && let Some(subdomain_policy) = tag(&tags, "sp")
        && policy_strength(subdomain_policy) < policy_strength(policy)
    {
        findings.push(dmarc(
            Severity::Warn,
            format!("sp={subdomain_policy} is weaker than p={policy} for subdomains"),
        ));
    }

    if let Some(pct) = tag(&tags, "pct")
        && pct.parse::<u8>().is_ok_and(|pct| pct < 100)
    {
        findings.push(dmarc(
            Severity::Warn,
            format!("pct={pct} applies the policy to only {pct}% of failing mail"),
        ));
    }

    if tag(&tags, "rua").is_none() {
        findings.push(dmarc(
            Severity::Warn,
            "no rua= tag; no aggregate reports are sent".to_string(),
        ));
    }

    findings
}

// The apex is assumed to be the organizational domain, whose policy covers
// subdomains without a record of their own.
fn inherited_dmarc(zone: &Zone, domain: &str) -> Finding {
    let apex_name = format!("_dmarc.{}", zone.apex);
    let (severity, message) = match lookup_dmarc(zone, &zone.apex) {
        DmarcLookup::Record(tags) => {
            let inherited = tag(&tags, "sp")
                .map(|sp| ("sp", sp))
                .or_else(|| tag(&tags, "p").map(|p| ("p", p)));
            match inherited {
                Some((key, policy)) => {
                    let (severity, note) = grade_policy(policy);
                    (
                        severity,
                        format!("inherits {key}={policy} from {apex_name}{note}"),
                    )
                }
                None => (
                    Severity::Fail,
                    format!("no record of its own, and {apex_name} has no p= tag"),
                ),
            }
        }
        DmarcLookup::Delegated(_) => (
            Severity::Warn,
            format!("no record of its own; inherits from {apex_name}, which is not evaluated"),
        ),
        DmarcLookup::Missing | DmarcLookup::Multiple(_) => (
            Severity::Fail,
            format!("no DMARC record at _dmarc.{domain} or {apex_name}"),
        ),
    };
    finding(domain, "DMARC", severity, message)
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

    fn results(zone: &Zone) -> Vec<(String, &'static str, Severity)> {
        audit(zone)
            .into_iter()
            .map(|f| (f.subject, f.check, f.severity))
            .collect()
    }

    fn messages(zone: &Zone, check: &str) -> Vec<String> {
        audit(zone)
            .into_iter()
            .filter(|f| f.check == check)
            .map(|f| f.message)
            .collect()
    }

    #[test]
    fn mail_domains_come_from_mail_records() {
        let zone = zone(
            "a              MX    10 mx.example.net.
b              TXT   \"v=spf1 -all\"
c              TXT   \"v=spf10 is not spf\"
_dmarc.d       TXT   \"v=DMARC1; p=reject\"
s1._domainkey.e CNAME s1.example.net.
www            A     192.0.2.1
",
        );
        assert_eq!(
            mail_domains(&zone),
            [
                "example.com",
                "a.example.com",
                "b.example.com",
                "d.example.com",
                "e.example.com"
            ]
        );
    }

    #[test]
    fn spf_all_qualifiers() {
        for (record, severity) in [
            ("v=spf1 mx -all", Severity::Pass),
            ("V=SPF1 MX -ALL", Severity::Pass),
            ("v=spf1 mx ~all", Severity::Warn),
            ("v=spf1 mx ?all", Severity::Fail),
            ("v=spf1 mx all", Severity::Fail),
            ("v=spf1 mx +all", Severity::Fail),
            ("v=spf1 mx", Severity::Fail),
            ("v=spf1 redirect=_spf.example.net", Severity::Warn),
            ("v=spf1 -all redirect=_spf.example.net", Severity::Pass),
        ] {
            let zone = zone(&format!("@ TXT \"{record}\"\n"));
            let spf = check_spf(&zone, "example.com");
            assert_eq!(spf.len(), 1, "{record}");
            assert_eq!(spf[0].severity, severity, "{record}");
        }
    }

    #[test]
    fn spf_missing_suggests_null_record_for_non_sending_domain() {
        let without_mx = zone("");
        assert!(messages(&without_mx, "SPF")[0].contains("v=spf1 -all"));

        let with_mx = zone("@ MX 10 mx.example.net.\n");
        assert_eq!(messages(&with_mx, "SPF"), ["no SPF record"]);
    }

    #[test]
    fn spf_multiple_records_fail() {
        let zone = zone("@ TXT \"v=spf1 -all\"\n@ TXT \"v=spf1 mx -all\"\n");
        let spf = check_spf(&zone, "example.com");
        assert_eq!(spf[0].severity, Severity::Fail);
        assert!(spf[0].message.contains("2 SPF records"));
    }

    #[test]
    fn dmarc_policy_grades() {
        for (record, severity) in [
            (
                "v=DMARC1; p=reject; rua=mailto:d@example.com",
                Severity::Pass,
            ),
            (
                "v=DMARC1; p=quarantine; rua=mailto:d@example.com",
                Severity::Pass,
            ),
            ("v=DMARC1; p=none; rua=mailto:d@example.com", Severity::Fail),
            (
                "v=DMARC1; p=bogus; rua=mailto:d@example.com",
                Severity::Fail,
            ),
            ("v=DMARC1; rua=mailto:d@example.com", Severity::Fail),
        ] {
            let zone = zone(&format!("_dmarc TXT \"{record}\"\n"));
            let dmarc = check_dmarc(&zone, "example.com");
            assert_eq!(dmarc.len(), 1, "{record}: {dmarc:?}");
            assert_eq!(dmarc[0].severity, severity, "{record}");
        }
    }

    #[test]
    fn dmarc_warnings() {
        let zone = zone("_dmarc TXT \"v=DMARC1; p=reject; sp=none; pct=50\"\n");
        assert_eq!(
            messages(&zone, "DMARC"),
            [
                "p=reject",
                "sp=none is weaker than p=reject for subdomains",
                "pct=50 applies the policy to only 50% of failing mail",
                "no rua= tag; no aggregate reports are sent",
            ]
        );
    }

    #[test]
    fn dmarc_ignores_records_without_version_tag() {
        let zone = zone(
            "_dmarc TXT \"p=none\"\n_dmarc TXT \"v=DMARC1; p=reject; rua=mailto:d@example.com\"\n",
        );
        assert_eq!(messages(&zone, "DMARC"), ["p=reject"]);
    }

    #[test]
    fn dmarc_multiple_records_fail() {
        let zone = zone("_dmarc TXT \"v=DMARC1; p=reject\"\n_dmarc TXT \"v=DMARC1; p=none\"\n");
        assert_eq!(
            messages(&zone, "DMARC"),
            ["2 DMARC records at _dmarc.example.com; receivers ignore all of them"]
        );
    }

    #[test]
    fn dmarc_cname_is_not_evaluated() {
        let zone = zone("_dmarc CNAME dmarc.example.net.\n");
        assert_eq!(
            results(&zone)[1],
            ("example.com".into(), "DMARC", Severity::Warn)
        );
    }

    #[test]
    fn subdomain_inherits_apex_policy() {
        let zone = zone(
            "_dmarc TXT \"v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com\"
mail MX 10 mx.example.net.
mail TXT \"v=spf1 mx -all\"
",
        );
        let dmarc: Vec<_> = audit(&zone)
            .into_iter()
            .filter(|f| f.subject == "mail.example.com" && f.check == "DMARC")
            .collect();
        assert_eq!(dmarc.len(), 1);
        assert_eq!(dmarc[0].severity, Severity::Fail);
        assert!(
            dmarc[0]
                .message
                .starts_with("inherits sp=none from _dmarc.example.com")
        );
    }

    #[test]
    fn subdomain_without_any_dmarc_fails() {
        let zone = zone("mail MX 10 mx.example.net.\n");
        assert!(
            messages(&zone, "DMARC").contains(
                &"no DMARC record at _dmarc.mail.example.com or _dmarc.example.com".into()
            )
        );
    }
}
