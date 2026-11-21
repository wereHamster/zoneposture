use std::collections::BTreeSet;

use crate::dns::{self, Rdata, Resolve, Rr};
use crate::finding::{Finding, Severity};
use crate::rules;
use crate::zone::{Record, RecordData, Zone};

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

/// How many names a finding lists before it summarizes the rest.
const LISTED_NAMES: usize = 5;

struct Property<'a> {
    critical: bool,
    tag: &'a str,
    value: &'a str,
}

/// A host whose CNAME chain leaves the zone at `target`, where the CAA lookup
/// failed. Whether CAA records cover the host is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    pub host: String,
    pub target: String,
    pub error: String,
}

/// Looks up the CAA records of names outside the zone at which the CNAME
/// chains of its hosts end, and adds them to `zone`. A zone file cannot hold
/// them, but CAs follow the chains. The name is looked up rather than the
/// host, so that the zone file, not the published zone, decides the chain.
pub async fn add_alias_targets(resolver: &impl Resolve, zone: &mut Zone) -> Vec<Unresolved> {
    let hosts: Vec<String> = zone
        .web_hosts()
        .iter()
        .map(|host| host.name.to_string())
        .collect();

    let mut lookups: Vec<(String, Result<(), String>)> = Vec::new();
    let mut unresolved = Vec::new();
    for host in hosts {
        let Some(target) = foreign_target(zone, &host) else {
            continue;
        };
        let result = match lookups.iter().find(|(name, _)| *name == target) {
            Some((_, result)) => result.clone(),
            None => {
                let result = dns::caa_records(resolver, &target)
                    .await
                    .map(|found| add_records(zone, found));
                lookups.push((target.clone(), result.clone()));
                result
            }
        };
        if let Err(error) = result {
            unresolved.push(Unresolved {
                host,
                target,
                error,
            });
        }
    }
    unresolved
}

/// The name outside the zone at which the CNAME chain of `host` continues
/// beyond the records in the zone, if it does.
fn foreign_target(zone: &Zone, host: &str) -> Option<String> {
    let mut name = host;
    for _ in 0..=dns::MAX_ALIASES {
        let mut records = zone.records_at(name).peekable();
        if records.peek().is_none() {
            return (!zone.contains(name)).then(|| name.to_string());
        }
        name = records.find_map(|data| match data {
            RecordData::Cname(target) => Some(target.as_str()),
            _ => None,
        })?;
    }
    None
}

fn add_records(zone: &mut Zone, found: Vec<Rr>) {
    for rr in found {
        let data = match rr.data {
            Rdata::Cname(target) => RecordData::Cname(target),
            Rdata::Caa { flags, tag, value } => RecordData::Caa {
                critical: flags & 0x80 != 0,
                tag,
                value,
            },
            _ => continue,
        };
        let record = Record {
            name: rr.owner,
            data,
        };
        if !zone.records.contains(&record) {
            zone.records.push(record);
        }
    }
}

/// Checks the record sets at names in the zone. Record sets of CNAME targets
/// outside the zone belong to someone else and only count towards whether a
/// host is covered. The apex comes first, the other owners are sorted.
pub fn audit(zone: &Zone, unresolved: &[Unresolved]) -> Vec<Finding> {
    let owners: BTreeSet<&str> = zone
        .records
        .iter()
        .filter(|r| matches!(r.data, RecordData::Caa { .. }) && zone.contains(&r.name))
        .map(|r| r.name.as_str())
        .collect();

    let mut findings = Vec::new();
    if !owners.contains(zone.apex.as_str()) {
        findings.extend(missing_at_apex(zone, unresolved));
    }

    let apex = owners.iter().filter(|owner| **owner == zone.apex);
    let others = owners.iter().filter(|owner| **owner != zone.apex);
    for owner in apex.chain(others) {
        findings.extend(check_record_set(owner, &properties_at(zone, owner)));
    }

    findings
}

/// A record set at the apex would cover every name in the zone. Without one,
/// a host is covered only by a record set of its own, at a parent below the
/// apex, or at the end of its CNAME chain.
fn missing_at_apex(zone: &Zone, unresolved: &[Unresolved]) -> Vec<Finding> {
    let apex = &zone.apex;
    let mut covered = Vec::new();
    let mut uncovered = Vec::new();
    let mut unknown = Vec::new();
    for host in zone.web_hosts() {
        if let Some(entry) = unresolved.iter().find(|u| u.host == host.name) {
            unknown.push(entry);
            continue;
        }
        match relevant_record_set(zone, host.name) {
            Some((owner, _)) if owner == host.name => covered.push(owner.to_string()),
            Some((owner, _)) => covered.push(format!("{} via {owner}", host.name)),
            None => uncovered.push(host.name.to_string()),
        }
    }

    let mut parts = vec!["no CAA records".to_string()];
    if covered.is_empty() && uncovered.is_empty() && unknown.is_empty() {
        parts.push(format!(
            "any CA may issue certificates for {apex} and its subdomains"
        ));
    } else {
        if !uncovered.is_empty() {
            parts.push(format!(
                "any CA may issue certificates for {}",
                list(&uncovered)
            ));
        }
        if !covered.is_empty() {
            parts.push(format!(
                "covered by CAA records elsewhere: {}",
                list(&covered)
            ));
        }
        if !unknown.is_empty() {
            let hosts: Vec<String> = unknown.iter().map(|u| u.host.clone()).collect();
            parts.push(format!("coverage unknown: {}", list(&hosts)));
        }
        parts.push(format!("other names under {apex} are not covered"));
    }
    let severity = if uncovered.is_empty() && !(covered.is_empty() && unknown.is_empty()) {
        Severity::Warn
    } else {
        Severity::Fail
    };

    let mut findings = vec![finding(
        apex,
        rules::CAA_MISSING,
        severity,
        parts.join("; "),
    )];
    for entry in unknown {
        findings.push(finding(
            &entry.host,
            rules::CAA_MISSING,
            Severity::Warn,
            format!(
                "cannot tell whether CAA records cover this host, the lookup at its alias target failed: {}",
                entry.error
            ),
        ));
    }
    findings
}

fn list(names: &[String]) -> String {
    if names.len() <= LISTED_NAMES {
        return names.join(", ");
    }
    format!(
        "{}, and {} more",
        names[..LISTED_NAMES].join(", "),
        names.len() - LISTED_NAMES
    )
}

fn properties_at<'a>(zone: &'a Zone, name: &'a str) -> Vec<Property<'a>> {
    zone.records_at(name)
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
        .collect()
}

/// The record set that a CAA lookup of `name` returns: the one at `name`, or
/// if `name` is a CNAME, the one at the end of its chain of aliases. Returns
/// the owner of the record set, or `None` if the lookup comes back empty.
fn record_set_at<'a>(zone: &'a Zone, name: &'a str) -> Option<(&'a str, Vec<Property<'a>>)> {
    let mut name = name;
    for _ in 0..=dns::MAX_ALIASES {
        let properties = properties_at(zone, name);
        if !properties.is_empty() {
            return Some((name, properties));
        }
        name = zone.records_at(name).find_map(|data| match data {
            RecordData::Cname(target) => Some(target.as_str()),
            _ => None,
        })?;
    }
    None
}

/// The record set that applies to `host` (RFC 8659, section 3): the first
/// non-empty lookup from `host` up to the apex. A lookup that comes back
/// empty at the end of a CNAME chain continues at the parent of the name,
/// not of the alias target.
fn relevant_record_set<'a>(zone: &'a Zone, host: &'a str) -> Option<(&'a str, Vec<Property<'a>>)> {
    let mut name = host;
    loop {
        if let Some(set) = record_set_at(zone, name) {
            return Some(set);
        }
        if name == zone.apex {
            return None;
        }
        name = name.split_once('.')?.1;
        if !zone.contains(name) {
            return None;
        }
    }
}

fn finding(subject: &str, id: &'static str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: subject.to_string(),
        id,
        severity,
        message,
    }
}

fn check_record_set(owner: &str, properties: &[Property]) -> Vec<Finding> {
    let caa = |id, severity, message| finding(owner, id, severity, message);
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
                rules::CAA_CRITICAL_TAG,
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
                rules::CAA_ISSUEWILD,
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
            rules::CAA_IODEF,
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
                rules::CAA_IODEF,
                Severity::Fail,
                format!("iodef value {url:?} is not a mailto:, http: or https: URL"),
            ));
        }
    }

    findings
}

/// Finds the CAA record set that applies to `host`, following CNAMEs, and
/// returns its owner and the CA domains it allows. For a wildcard
/// certificate, `issuewild` applies if present. Returns `None` if no record
/// set applies or it does not restrict issuance.
pub fn allowed_issuers(zone: &Zone, host: &str, wildcard: bool) -> Option<(String, Vec<String>)> {
    let (owner, properties) = relevant_record_set(zone, host)?;
    let has_issuewild = properties.iter().any(|p| p.tag == "issuewild");
    let tag = if wildcard && has_issuewild {
        "issuewild"
    } else {
        "issue"
    };
    let values: Vec<&str> = properties
        .iter()
        .filter(|p| p.tag == tag)
        .map(|p| p.value)
        .collect();
    if values.is_empty() {
        return None;
    }
    let issuers: BTreeSet<String> = values.iter().filter_map(|value| issuer(value)).collect();
    Some((owner.to_string(), issuers.into_iter().collect()))
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
    let id = if tag == "issuewild" {
        rules::CAA_ISSUEWILD
    } else {
        rules::CAA_ISSUE
    };
    let caa = |severity, message| finding(owner, id, severity, message);

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
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;
    use crate::dns::Qtype;
    use crate::zone::parse_str;

    fn zone(records: &str) -> Zone {
        parse_str(&format!(
            "$ORIGIN example.com.\n$TTL 300\n@ SOA ns admin 1 3600 600 86400 300\n{records}"
        ))
        .unwrap()
    }

    fn results(zone: &Zone) -> Vec<(String, Severity, String)> {
        results_with(zone, &[])
    }

    fn results_with(zone: &Zone, unresolved: &[Unresolved]) -> Vec<(String, Severity, String)> {
        audit(zone, unresolved)
            .into_iter()
            .map(|f| (f.subject, f.severity, f.message))
            .collect()
    }

    fn result(subject: &str, severity: Severity, message: &str) -> (String, Severity, String) {
        (subject.to_string(), severity, message.to_string())
    }

    fn ids(zone: &Zone) -> Vec<&'static str> {
        audit(zone, &[]).iter().map(|f| f.id).collect()
    }

    #[test]
    fn findings_carry_the_id_of_their_rule() {
        assert_eq!(ids(&zone("www A 192.0.2.1\n")), ["caa-missing"]);
        assert_eq!(
            ids(&zone(
                "@ CAA 128 tbs \"x\"
@ CAA 0 issue \"letsencrypt.org\"
@ CAA 0 iodef \"security@example.com\"
"
            )),
            [
                "caa-critical-tag",
                "caa-issue",
                "caa-issuewild",
                "caa-iodef"
            ]
        );
        assert_eq!(
            ids(&zone(
                "@ CAA 0 issue \";\"
@ CAA 0 issuewild \"not a domain\"
@ CAA 0 iodef \"mailto:security@example.com\"
"
            )),
            ["caa-issue", "caa-issuewild", "caa-issuewild"]
        );
    }

    #[test]
    fn missing_at_apex_fails() {
        let zone = zone("www A 192.0.2.1\n");
        assert_eq!(
            results(&zone),
            [result(
                "example.com",
                Severity::Fail,
                "no CAA records; any CA may issue certificates for www.example.com; other names under example.com are not covered"
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
    fn allowed_issuers_climb_to_the_closest_record_set() {
        let zone = zone(
            "@ CAA 0 issue \"letsencrypt.org\"
@ CAA 0 issue \"pki.goog; cansignhttpexchanges=yes\"
@ CAA 0 issuewild \";\"
shop CAA 0 issue \"digicert.com\"
iodef-only CAA 0 iodef \"mailto:s@example.com\"
",
        );
        let allowed = |host, wildcard| allowed_issuers(&zone, host, wildcard);
        let set = |owner: &str, issuers: &[&str]| {
            Some((
                owner.to_string(),
                issuers.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
            ))
        };

        assert_eq!(
            allowed("www.example.com", false),
            set("example.com", &["letsencrypt.org", "pki.goog"])
        );
        assert_eq!(allowed("www.example.com", true), set("example.com", &[]));
        assert_eq!(
            allowed("a.shop.example.com", true),
            set("shop.example.com", &["digicert.com"])
        );
        assert_eq!(allowed("iodef-only.example.com", false), None);
    }

    #[test]
    fn allowed_issuers_follow_cnames() {
        let zone = zone(
            "@ CAA 0 issue \"letsencrypt.org\"
app CNAME cname.vercel-dns.com.
cname.vercel-dns.com. CAA 0 issue \"pki.goog\"
docs CNAME alias.example.net.
alias.example.net. CNAME pages.example.org.
pages.example.org. CAA 0 issue \"digicert.com\"
shop CNAME shops.example.net.
a.b CNAME b
b CAA 0 issue \"sectigo.com\"
loop CNAME loop
",
        );
        let allowed = |host| allowed_issuers(&zone, host, false);
        let set = |owner: &str, issuer: &str| Some((owner.to_string(), vec![issuer.to_string()]));

        assert_eq!(
            allowed("app.example.com"),
            set("cname.vercel-dns.com", "pki.goog")
        );
        assert_eq!(
            allowed("docs.example.com"),
            set("pages.example.org", "digicert.com")
        );
        assert_eq!(
            allowed("shop.example.com"),
            set("example.com", "letsencrypt.org"),
            "an alias target without CAA records continues at the parent of the name"
        );
        assert_eq!(
            allowed("a.b.example.com"),
            set("b.example.com", "sectigo.com")
        );
        assert_eq!(
            allowed("loop.example.com"),
            set("example.com", "letsencrypt.org")
        );
    }

    #[test]
    fn hosts_covered_through_cnames_only_warn() {
        let zone = zone(
            "stories CNAME cname.vercel-dns.com.
cname.vercel-dns.com. CAA 0 issue \"letsencrypt.org\"
",
        );
        assert_eq!(
            results(&zone),
            [result(
                "example.com",
                Severity::Warn,
                "no CAA records; covered by CAA records elsewhere: stories.example.com via cname.vercel-dns.com; other names under example.com are not covered"
            )],
            "record sets outside the zone are not checked"
        );
    }

    #[test]
    fn uncovered_hosts_fail_and_covered_ones_are_named() {
        let zone = zone(
            "www A 192.0.2.1
stories CNAME cname.vercel-dns.com.
cname.vercel-dns.com. CAA 0 issue \"letsencrypt.org\"
",
        );
        assert_eq!(
            results(&zone),
            [result(
                "example.com",
                Severity::Fail,
                "no CAA records; any CA may issue certificates for www.example.com; covered by CAA records elsewhere: stories.example.com via cname.vercel-dns.com; other names under example.com are not covered"
            )]
        );
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

    #[derive(Default)]
    struct Fake {
        answers: HashMap<(&'static str, Qtype), Vec<Rr>>,
        errors: HashMap<&'static str, String>,
        queries: RefCell<Vec<String>>,
    }

    impl Fake {
        fn with(mut self, name: &'static str, qtype: Qtype, owner: &str, data: Rdata) -> Self {
            self.answers.entry((name, qtype)).or_default().push(Rr {
                owner: owner.to_string(),
                ttl: 300,
                data,
            });
            self
        }
    }

    impl Resolve for Fake {
        async fn query(&self, name: &str, qtype: Qtype) -> Result<Vec<Rr>, String> {
            self.queries.borrow_mut().push(name.to_string());
            if let Some(err) = self.errors.get(name) {
                return Err(err.clone());
            }
            Ok(self
                .answers
                .get(&(name, qtype))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn issue(value: &str) -> Rdata {
        Rdata::Caa {
            flags: 0,
            tag: "issue".to_string(),
            value: value.to_string(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn alias_targets_outside_the_zone_are_looked_up() {
        let mut zone = zone(
            "stories CNAME cname.vercel-dns.com.
app CNAME cname.vercel-dns.com.
docs CNAME alias.example.net.
www CNAME stories
shop CNAME shops.example.org.
",
        );
        let resolver = Fake::default()
            .with(
                "cname.vercel-dns.com",
                Qtype::Caa,
                "cname.vercel-dns.com",
                issue("letsencrypt.org"),
            )
            .with(
                "alias.example.net",
                Qtype::Caa,
                "pages.example.org",
                issue("digicert.com"),
            )
            .with(
                "alias.example.net",
                Qtype::Cname,
                "alias.example.net",
                Rdata::Cname("pages.example.org".into()),
            );

        let unresolved = add_alias_targets(&resolver, &mut zone).await;

        assert_eq!(unresolved, []);
        assert_eq!(
            *resolver.queries.borrow(),
            [
                "cname.vercel-dns.com",
                "alias.example.net",
                "alias.example.net",
                "shops.example.org"
            ],
            "each target is looked up once, names in the zone are not looked up"
        );
        let set = |owner: &str, issuer: &str| Some((owner.to_string(), vec![issuer.to_string()]));
        for host in ["stories.example.com", "app.example.com", "www.example.com"] {
            assert_eq!(
                allowed_issuers(&zone, host, false),
                set("cname.vercel-dns.com", "letsencrypt.org")
            );
        }
        assert_eq!(
            allowed_issuers(&zone, "docs.example.com", false),
            set("pages.example.org", "digicert.com")
        );
        assert_eq!(allowed_issuers(&zone, "shop.example.com", false), None);
        assert_eq!(
            results_with(&zone, &unresolved)[0],
            result(
                "example.com",
                Severity::Fail,
                "no CAA records; any CA may issue certificates for shop.example.com; covered by CAA records elsewhere: stories.example.com via cname.vercel-dns.com, app.example.com via cname.vercel-dns.com, docs.example.com via pages.example.org, www.example.com via cname.vercel-dns.com; other names under example.com are not covered"
            )
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn alias_targets_already_in_the_zone_are_not_looked_up() {
        let mut zone = zone(
            "stories CNAME cname.vercel-dns.com.
cname.vercel-dns.com. CAA 0 issue \"letsencrypt.org\"
",
        );
        let resolver = Fake::default();
        assert_eq!(add_alias_targets(&resolver, &mut zone).await, []);
        assert!(resolver.queries.borrow().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_failed_alias_target_lookup_leaves_the_host_unknown() {
        let mut zone = zone(
            "stories CNAME cname.vercel-dns.com.
www CNAME cname.vercel-dns.com.
",
        );
        let mut resolver = Fake::default();
        resolver
            .errors
            .insert("cname.vercel-dns.com", "SERVFAIL".to_string());

        let unresolved = add_alias_targets(&resolver, &mut zone).await;

        let unknown = |host: &str| Unresolved {
            host: host.to_string(),
            target: "cname.vercel-dns.com".to_string(),
            error: "SERVFAIL".to_string(),
        };
        assert_eq!(
            unresolved,
            [unknown("stories.example.com"), unknown("www.example.com")]
        );
        assert_eq!(resolver.queries.borrow().len(), 1);
        assert_eq!(
            results_with(&zone, &unresolved),
            [
                result(
                    "example.com",
                    Severity::Warn,
                    "no CAA records; coverage unknown: stories.example.com, www.example.com; other names under example.com are not covered"
                ),
                result(
                    "stories.example.com",
                    Severity::Warn,
                    "cannot tell whether CAA records cover this host, the lookup at its alias target failed: SERVFAIL"
                ),
                result(
                    "www.example.com",
                    Severity::Warn,
                    "cannot tell whether CAA records cover this host, the lookup at its alias target failed: SERVFAIL"
                ),
            ]
        );
    }

    #[test]
    fn long_host_lists_are_summarized() {
        let records: String = (1..=7).map(|i| format!("h{i} A 192.0.2.{i}\n")).collect();
        assert_eq!(
            results(&zone(&records))[0].2,
            "no CAA records; any CA may issue certificates for h1.example.com, h2.example.com, h3.example.com, h4.example.com, h5.example.com, and 2 more; other names under example.com are not covered"
        );
    }
}
