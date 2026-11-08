use std::collections::VecDeque;
use std::fmt::Write;
use std::hash::{BuildHasher, Hasher};

use futures::future::try_join_all;
use jiff::Timestamp;

use crate::dns::{Qtype, Rdata, Resolve, Rr};
use crate::email;

/// A partial zone built from DNS lookups. It holds the SOA record of the
/// enclosing zone, the host records of the requested names, their mail records
/// (MX, SPF, DMARC) and those of the apex, the CAA records a CA would consult
/// for them, and, if the zone has one, a wildcard.
#[derive(Debug)]
pub struct Snapshot {
    pub apex: String,
    pub names: Vec<String>,
    /// The SOA record comes first.
    pub records: Vec<Rr>,
    pub warnings: Vec<String>,
}

/// Looks up `names`, which must all belong to the same zone. CNAME targets
/// inside the zone are followed, targets outside it are not: they belong to
/// someone else's zone.
pub async fn snapshot(resolver: &impl Resolve, names: &[String]) -> Result<Snapshot, String> {
    let mut valid: Vec<String> = Vec::new();
    for name in names {
        let name = validate(name)?;
        if !valid.contains(&name) {
            valid.push(name);
        }
    }
    let names = valid;

    let soa = find_soa(resolver, &names[0]).await?;
    let apex = soa.owner.clone();
    for name in &names[1..] {
        let other = find_soa(resolver, name).await?;
        if other.owner != apex {
            return Err(format!(
                "{name} is in zone {}, but {} is in zone {apex}; take one snapshot per zone",
                other.owner, names[0]
            ));
        }
    }

    let mut records = vec![soa];
    let mut warnings = Vec::new();
    let mut queue: VecDeque<String> = names.iter().cloned().collect();
    let mut visited: Vec<String> = Vec::new();
    while let Some(name) = queue.pop_front() {
        if visited.contains(&name) {
            continue;
        }
        let found = host_records(resolver, &name).await?;
        if found.is_empty() {
            warnings.push(format!("{name}: no A, AAAA or CNAME records"));
        }
        for rr in &found {
            if let Rdata::Cname(target) = &rr.data
                && in_zone(target, &apex)
            {
                queue.push_back(target.clone());
            }
        }
        records.extend(found);
        visited.push(name);
    }

    let candidates = std::iter::once(&apex).chain(visited.iter().filter(|name| **name != apex));
    for domain in candidates {
        let basics = mail_basics(resolver, domain).await?;
        if *domain != apex && basics.is_empty() {
            continue;
        }
        records.extend(basics);
        records.extend(mail_conventions(resolver, domain).await?);
    }

    for owner in caa_owners(&visited, &apex) {
        let found = resolver.query(&owner, Qtype::Caa).await?;
        records.extend(found.into_iter().filter(|rr| rr.owner == owner));
    }

    let probe = format!("{}.{apex}", random_label());
    for mut rr in host_records(resolver, &probe).await? {
        rr.owner = format!("*.{apex}");
        records.push(rr);
    }

    Ok(Snapshot {
        apex,
        names,
        records,
        warnings,
    })
}

fn validate(raw: &str) -> Result<String, String> {
    let name = raw.trim_end_matches('.').to_ascii_lowercase();
    let invalid = |reason: &str| Err(format!("{raw}: {reason}"));

    if !name.is_ascii() {
        return invalid("not an ASCII name, use the punycode form");
    }
    if name.is_empty() || name.len() > 253 {
        return invalid("not a valid domain name");
    }
    for label in name.split('.') {
        if label == "*" {
            return invalid("wildcard names cannot be looked up");
        }
        let valid_chars = label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if label.is_empty() || label.len() > 63 || !valid_chars {
            return invalid("not a valid domain name");
        }
    }
    Ok(name)
}

fn in_zone(name: &str, apex: &str) -> bool {
    name == apex
        || name
            .strip_suffix(apex)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// The SOA record of the closest zone that encloses `name`. The walk up stops
/// at two labels, so top-level domains are never taken as the zone.
async fn find_soa(resolver: &impl Resolve, name: &str) -> Result<Rr, String> {
    let labels: Vec<&str> = name.split('.').collect();
    for start in 0..labels.len().saturating_sub(1) {
        let candidate = labels[start..].join(".");
        let answer = resolver.query(&candidate, Qtype::Soa).await?;
        if let Some(soa) = answer.into_iter().find(|rr| rr.owner == candidate) {
            return Ok(soa);
        }
    }
    Err(format!("{name}: no enclosing zone found"))
}

/// A name with a CNAME has no other records, so only the CNAME is returned.
async fn host_records(resolver: &impl Resolve, name: &str) -> Result<Vec<Rr>, String> {
    let mut records = Vec::new();
    for qtype in [Qtype::Cname, Qtype::A, Qtype::Aaaa] {
        let answer = resolver.query(name, qtype).await?;
        records.extend(answer.into_iter().filter(|rr| rr.owner == name));
        if !records.is_empty() && qtype == Qtype::Cname {
            break;
        }
    }
    Ok(records)
}

/// The MX and SPF records at `name`. Other TXT records, such as site
/// verification tokens, are not part of the mail posture and are left out.
async fn mail_basics(resolver: &impl Resolve, name: &str) -> Result<Vec<Rr>, String> {
    let mx = resolver.query(name, Qtype::Mx).await?;
    let txt = resolver.query(name, Qtype::Txt).await?;
    let spf = txt.into_iter().filter(|rr| match &rr.data {
        Rdata::Txt(text) => email::is_spf(&String::from_utf8_lossy(text)),
        _ => false,
    });
    Ok(mx
        .into_iter()
        .chain(spf)
        .filter(|rr| rr.owner == name)
        .collect())
}

/// Labels under a mail domain at which policies are published by convention:
/// DMARC, MTA-STS (RFC 8461), TLS reporting (RFC 8460), and BIMI.
const MAIL_POLICY_LABELS: &[&str] = &["_dmarc", "_mta-sts", "_smtp._tls", "default._bimi"];

/// DKIM selectors are chosen by the sender and cannot be listed in DNS, so
/// only the defaults of common mail providers can be found.
const DKIM_SELECTORS: &[&str] = &[
    "default",
    "dkim",
    "mail",
    "smtp",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "k3",
    "mandrill",
    "mxvault",
    "zoho",
    "protonmail",
    "protonmail2",
    "protonmail3",
    "fm1",
    "fm2",
    "fm3",
];

/// The records at the conventional names under the mail domain `domain`,
/// and the host that serves its MTA-STS policy if it has one.
async fn mail_conventions(resolver: &impl Resolve, domain: &str) -> Result<Vec<Rr>, String> {
    let names: Vec<String> = MAIL_POLICY_LABELS
        .iter()
        .map(|label| format!("{label}.{domain}"))
        .chain(
            DKIM_SELECTORS
                .iter()
                .map(|selector| format!("{selector}._domainkey.{domain}")),
        )
        .collect();
    let mut records: Vec<Rr> = try_join_all(names.iter().map(|name| alias_or_text(resolver, name)))
        .await?
        .into_iter()
        .flatten()
        .collect();

    let mta_sts = format!("_mta-sts.{domain}");
    if records.iter().any(|rr| rr.owner == mta_sts) {
        records.extend(host_records(resolver, &format!("mta-sts.{domain}")).await?);
    }
    Ok(records)
}

/// The CNAME at `name`, or if there is none, its TXT records.
async fn alias_or_text(resolver: &impl Resolve, name: &str) -> Result<Vec<Rr>, String> {
    for qtype in [Qtype::Cname, Qtype::Txt] {
        let answer = resolver.query(name, qtype).await?;
        let found: Vec<Rr> = answer.into_iter().filter(|rr| rr.owner == name).collect();
        if !found.is_empty() {
            return Ok(found);
        }
    }
    Ok(Vec::new())
}

/// Every name from which a CA may take the CAA records for one of `names`:
/// the names themselves and their parents up to the apex.
fn caa_owners(names: &[String], apex: &str) -> Vec<String> {
    let mut owners: Vec<String> = Vec::new();
    for name in names {
        let mut owner = name.as_str();
        loop {
            if !owners.iter().any(|seen| seen == owner) {
                owners.push(owner.to_string());
            }
            match owner.split_once('.') {
                Some((_, parent)) if owner != apex => owner = parent,
                _ => break,
            }
        }
    }
    owners
}

/// A label that is not likely to exist in the zone, to find out whether
/// the zone has a wildcard.
fn random_label() -> String {
    let random = std::hash::RandomState::new().build_hasher().finish();
    format!("zp-{random:016x}")
}

fn fqdn(name: &str) -> String {
    if name == "." {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// A character-string in zone file syntax. Bytes outside printable ASCII are
/// written as decimal escapes, so the result does not depend on the encoding.
fn quote(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(byte as char);
            }
            0x20..=0x7e => out.push(byte as char),
            _ => write!(out, "\\{byte:03}").unwrap(),
        }
    }
    out.push('"');
    out
}

pub fn render(snapshot: &Snapshot, now: Timestamp) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "; Synthetic zone for {}, generated by `zoneposture snapshot` on {}.",
        snapshot.apex,
        now.strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    .unwrap();
    writeln!(
        out,
        "; Partial: only the records for these names were looked up: {}.",
        snapshot.names.join(", ")
    )
    .unwrap();
    for rr in &snapshot.records {
        let (rtype, data) = match &rr.data {
            Rdata::Soa(soa) => (
                "SOA",
                format!(
                    "{}. {}. {} {} {} {} {}",
                    soa.mname,
                    soa.rname,
                    soa.serial,
                    soa.refresh,
                    soa.retry,
                    soa.expire,
                    soa.minimum
                ),
            ),
            Rdata::A(addr) => ("A", addr.to_string()),
            Rdata::Aaaa(addr) => ("AAAA", addr.to_string()),
            Rdata::Cname(target) => ("CNAME", fqdn(target)),
            Rdata::Caa { flags, tag, value } => {
                ("CAA", format!("{flags} {tag} {}", quote(value.as_bytes())))
            }
            Rdata::Mx {
                preference,
                exchange,
            } => ("MX", format!("{preference} {}", fqdn(exchange))),
            Rdata::Txt(text) => {
                let strings: Vec<String> = text.chunks(255).map(quote).collect();
                let data = if strings.is_empty() {
                    quote(&[])
                } else {
                    strings.join(" ")
                };
                ("TXT", data)
            }
        };
        writeln!(out, "{}. {} IN {rtype} {data}", rr.owner, rr.ttl).unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use super::*;
    use crate::dns::Soa;
    use crate::zone::{self, Record, RecordData, Zone};

    #[derive(Default)]
    struct Fake {
        answers: HashMap<(&'static str, Qtype), Vec<Rr>>,
        errors: HashMap<(&'static str, Qtype), String>,
        wildcard: Option<Rr>,
        queries: RefCell<Vec<(String, Qtype)>>,
    }

    impl Fake {
        fn with(mut self, name: &'static str, qtype: Qtype, data: Rdata) -> Self {
            self.answers
                .entry((name, qtype))
                .or_default()
                .push(rr(name, data));
            self
        }

        fn queried(&self, name: &str) -> bool {
            self.queries.borrow().iter().any(|(n, _)| n == name)
        }
    }

    impl Resolve for Fake {
        async fn query(&self, name: &str, qtype: Qtype) -> Result<Vec<Rr>, String> {
            self.queries.borrow_mut().push((name.to_string(), qtype));
            if let Some(err) = self.errors.get(&(name, qtype)) {
                return Err(err.clone());
            }
            if name.starts_with("zp-") {
                return Ok(match (&self.wildcard, qtype) {
                    (Some(rr), q) if rr.data.qtype() == q => {
                        vec![Rr {
                            owner: name.to_string(),
                            ..rr.clone()
                        }]
                    }
                    _ => vec![],
                });
            }
            Ok(self
                .answers
                .get(&(name, qtype))
                .cloned()
                .unwrap_or_default())
        }
    }

    fn rr(owner: &str, data: Rdata) -> Rr {
        Rr {
            owner: owner.to_string(),
            ttl: 300,
            data,
        }
    }

    fn soa() -> Rdata {
        Rdata::Soa(Soa {
            mname: "ns.client.com".to_string(),
            rname: "admin.client.com".to_string(),
            serial: 7,
            refresh: 3600,
            retry: 600,
            expire: 86400,
            minimum: 300,
        })
    }

    fn caa(value: &str) -> Rdata {
        Rdata::Caa {
            flags: 0,
            tag: "issue".to_string(),
            value: value.to_string(),
        }
    }

    fn client_zone() -> Fake {
        Fake::default().with("client.com", Qtype::Soa, soa())
    }

    fn names(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| n.to_string()).collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writes_a_zone_that_the_audit_can_read() {
        let resolver = client_zone()
            .with(
                "www.client.com",
                Qtype::Cname,
                Rdata::Cname("client.com".into()),
            )
            .with(
                "client.com",
                Qtype::A,
                Rdata::A("192.0.2.1".parse().unwrap()),
            )
            .with("client.com", Qtype::Caa, caa("letsencrypt.org"))
            .with(
                "app.client.com",
                Qtype::Aaaa,
                Rdata::Aaaa("2001:db8::1".parse().unwrap()),
            );

        let snapshot = snapshot(&resolver, &names(&["WWW.client.com.", "app.client.com"]))
            .await
            .unwrap();
        let text = render(&snapshot, "2026-11-08T12:00:00Z".parse().unwrap());
        assert!(
            text.starts_with("; Synthetic zone for client.com"),
            "{text}"
        );

        let record = |name: &str, data| Record {
            name: name.to_string(),
            data,
        };
        assert_eq!(
            zone::parse_str(&text).unwrap(),
            Zone {
                apex: "client.com".to_string(),
                records: vec![
                    record("www.client.com", RecordData::Cname("client.com".into())),
                    record(
                        "app.client.com",
                        RecordData::Aaaa("2001:db8::1".parse().unwrap())
                    ),
                    record("client.com", RecordData::A("192.0.2.1".parse().unwrap())),
                    record(
                        "client.com",
                        RecordData::Caa {
                            critical: false,
                            tag: "issue".into(),
                            value: "letsencrypt.org".into()
                        }
                    ),
                ],
            }
        );
        assert!(snapshot.warnings.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn does_not_follow_cnames_out_of_the_zone() {
        let resolver = client_zone()
            .with(
                "www.client.com",
                Qtype::Cname,
                Rdata::Cname("shop.example.net".into()),
            )
            .with(
                "shop.example.net",
                Qtype::A,
                Rdata::A("192.0.2.9".parse().unwrap()),
            );

        let snapshot = snapshot(&resolver, &names(&["www.client.com"]))
            .await
            .unwrap();

        assert!(!resolver.queried("shop.example.net"));
        assert_eq!(snapshot.records.len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stops_at_the_names_own_zone_when_it_is_delegated() {
        let resolver = client_zone().with("app.client.com", Qtype::Soa, soa());
        let snapshot = snapshot(&resolver, &names(&["www.app.client.com"]))
            .await
            .unwrap();
        assert_eq!(snapshot.apex, "app.client.com");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn looks_up_caa_from_the_name_up_to_the_apex_only() {
        let resolver = client_zone()
            .with(
                "a.b.client.com",
                Qtype::A,
                Rdata::A("192.0.2.1".parse().unwrap()),
            )
            .with("b.client.com", Qtype::Caa, caa("example.org"));

        let snapshot = snapshot(&resolver, &names(&["a.b.client.com"]))
            .await
            .unwrap();

        for owner in ["a.b.client.com", "b.client.com", "client.com"] {
            assert!(
                resolver
                    .queries
                    .borrow()
                    .contains(&(owner.to_string(), Qtype::Caa))
            );
        }
        assert!(!resolver.queried("com"));
        assert!(snapshot.records.iter().any(|rr| rr.owner == "b.client.com"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn records_a_wildcard() {
        let resolver = Fake {
            wildcard: Some(rr("", Rdata::A("192.0.2.5".parse().unwrap()))),
            ..client_zone()
        };

        let snapshot = snapshot(&resolver, &names(&["www.client.com"]))
            .await
            .unwrap();

        assert!(
            snapshot
                .records
                .contains(&rr("*.client.com", Rdata::A("192.0.2.5".parse().unwrap())))
        );
        assert_eq!(
            snapshot.warnings,
            ["www.client.com: no A, AAAA or CNAME records"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_names_from_different_zones() {
        let resolver = client_zone().with("other.org", Qtype::Soa, soa());
        let err = snapshot(&resolver, &names(&["www.client.com", "other.org"]))
            .await
            .unwrap_err();
        assert!(err.contains("one snapshot per zone"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejects_a_name_without_a_zone() {
        let err = snapshot(&Fake::default(), &names(&["www.client.com"]))
            .await
            .unwrap_err();
        assert!(err.contains("no enclosing zone"), "{err}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fails_when_a_lookup_fails() {
        let mut resolver = client_zone();
        resolver
            .errors
            .insert(("client.com", Qtype::Caa), "SERVFAIL".to_string());
        let err = snapshot(&resolver, &names(&["www.client.com"]))
            .await
            .unwrap_err();
        assert_eq!(err, "SERVFAIL");
    }

    fn txt(text: &str) -> Rdata {
        Rdata::Txt(text.as_bytes().to_vec())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writes_the_mail_records_that_exist() {
        let key = format!("v=DKIM1; k=rsa; p={}\"é", "A".repeat(300));
        let resolver = client_zone()
            .with(
                "www.client.com",
                Qtype::A,
                Rdata::A("192.0.2.1".parse().unwrap()),
            )
            .with(
                "client.com",
                Qtype::Mx,
                Rdata::Mx {
                    preference: 10,
                    exchange: "mail.client.com".into(),
                },
            )
            .with(
                "client.com",
                Qtype::Txt,
                txt("v=spf1 include:example.net -all"),
            )
            .with(
                "client.com",
                Qtype::Txt,
                txt("google-site-verification=abc"),
            )
            .with("_dmarc.client.com", Qtype::Txt, txt("v=DMARC1; p=reject"))
            .with("_mta-sts.client.com", Qtype::Txt, txt("v=STSv1; id=1"))
            .with(
                "mta-sts.client.com",
                Qtype::A,
                Rdata::A("192.0.2.2".parse().unwrap()),
            )
            .with("google._domainkey.client.com", Qtype::Txt, txt(&key))
            .with(
                "selector1._domainkey.client.com",
                Qtype::Cname,
                Rdata::Cname("selector1-client-com._domainkey.example.net".into()),
            );

        let snapshot = snapshot(&resolver, &names(&["www.client.com"]))
            .await
            .unwrap();
        let text = render(&snapshot, Timestamp::UNIX_EPOCH);

        let record = |name: &str, data| Record {
            name: name.to_string(),
            data,
        };
        assert_eq!(
            zone::parse_str(&text).unwrap().records,
            vec![
                record(
                    "www.client.com",
                    RecordData::A("192.0.2.1".parse().unwrap())
                ),
                record("client.com", RecordData::Mx("mail.client.com".into())),
                record(
                    "client.com",
                    RecordData::Txt("v=spf1 include:example.net -all".into())
                ),
                record(
                    "_dmarc.client.com",
                    RecordData::Txt("v=DMARC1; p=reject".into())
                ),
                record(
                    "_mta-sts.client.com",
                    RecordData::Txt("v=STSv1; id=1".into())
                ),
                record("google._domainkey.client.com", RecordData::Txt(key)),
                record(
                    "selector1._domainkey.client.com",
                    RecordData::Cname("selector1-client-com._domainkey.example.net".into())
                ),
                record(
                    "mta-sts.client.com",
                    RecordData::A("192.0.2.2".parse().unwrap())
                ),
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probes_a_name_for_mail_only_if_it_has_mail_records() {
        let resolver = client_zone()
            .with(
                "www.client.com",
                Qtype::A,
                Rdata::A("192.0.2.1".parse().unwrap()),
            )
            .with(
                "mail.client.com",
                Qtype::Mx,
                Rdata::Mx {
                    preference: 10,
                    exchange: "mx.example.net".into(),
                },
            );

        snapshot(&resolver, &names(&["www.client.com", "mail.client.com"]))
            .await
            .unwrap();

        assert!(resolver.queried("_dmarc.mail.client.com"));
        assert!(resolver.queried("_dmarc.client.com"));
        assert!(!resolver.queried("_dmarc.www.client.com"));
    }

    #[test]
    fn renders_a_null_mx() {
        let snapshot = Snapshot {
            apex: "client.com".into(),
            names: names(&["client.com"]),
            records: vec![rr(
                "client.com",
                Rdata::Mx {
                    preference: 0,
                    exchange: ".".into(),
                },
            )],
            warnings: vec![],
        };
        let text = render(&snapshot, Timestamp::UNIX_EPOCH);
        assert!(text.ends_with("client.com. 300 IN MX 0 .\n"), "{text}");
    }

    #[test]
    fn validates_names() {
        assert_eq!(validate("Www.Client.COM.").unwrap(), "www.client.com");
        assert_eq!(validate("_dmarc.client.com").unwrap(), "_dmarc.client.com");
        for name in ["", ".", "a..b", "*.client.com", "bücher.de", "a b.com"] {
            assert!(validate(name).is_err(), "{name}");
        }
    }

    #[test]
    fn escapes_caa_values() {
        let snapshot = Snapshot {
            apex: "client.com".into(),
            names: names(&["client.com"]),
            records: vec![rr("client.com", caa("a\"b\\c"))],
            warnings: vec![],
        };
        let text = render(&snapshot, Timestamp::UNIX_EPOCH);
        assert!(
            text.ends_with("client.com. 300 IN CAA 0 issue \"a\\\"b\\\\c\"\n"),
            "{text}"
        );
    }
}
