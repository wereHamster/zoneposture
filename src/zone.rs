use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::{Entry, Zonefile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRecord {
    pub name: String,
    pub data: HostData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
}

impl HostData {
    pub fn record_type(&self) -> &'static str {
        match self {
            HostData::A(_) => "A",
            HostData::Aaaa(_) => "AAAA",
            HostData::Cname(_) => "CNAME",
        }
    }
}

impl fmt::Display for HostData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostData::A(addr) => addr.fmt(f),
            HostData::Aaaa(addr) => addr.fmt(f),
            HostData::Cname(target) => target.fmt(f),
        }
    }
}

/// Reads a BIND-format zone file and returns its A, AAAA, and CNAME records
/// in file order.
pub fn read_host_records(path: &Path) -> Result<Vec<HostRecord>, Box<dyn Error>> {
    parse_host_records(&mut File::open(path)?)
}

fn parse_host_records(input: &mut impl Read) -> Result<Vec<HostRecord>, Box<dyn Error>> {
    let mut zonefile = Zonefile::load(input)?;
    let mut records = Vec::new();

    while let Some(entry) = zonefile.next_entry()? {
        let record = match entry {
            Entry::Record(record) => record,
            Entry::Include { .. } => return Err("$INCLUDE is not supported".into()),
        };

        let data = match record.data() {
            ZoneRecordData::A(a) => HostData::A(a.addr()),
            ZoneRecordData::Aaaa(aaaa) => HostData::Aaaa(aaaa.addr()),
            ZoneRecordData::Cname(cname) => {
                HostData::Cname(expand_origin_symbol(cname.cname().to_string()))
            }
            _ => continue,
        };

        records.push(HostRecord {
            name: record.owner().to_string(),
            data,
        });
    }

    Ok(records)
}

// The domain crate (0.12) expands `@` only in owner names. In record data it
// keeps `@` as a literal label and appends the origin, so `CNAME @` comes out
// as `@.<origin>`. An escaped literal `\@` label is indistinguishable after
// parsing and is expanded too, which is acceptable since such labels are not
// valid hostnames.
fn expand_origin_symbol(name: String) -> String {
    match name.strip_prefix("@.") {
        Some(origin) => origin.to_string(),
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Result<Vec<HostRecord>, Box<dyn Error>> {
        parse_host_records(&mut input.as_bytes())
    }

    fn record(name: &str, data: HostData) -> HostRecord {
        HostRecord {
            name: name.to_string(),
            data,
        }
    }

    #[test]
    fn keeps_only_host_records() {
        let records = parse(
            "example.com. 300 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 300
example.com. 300 IN NS ns.example.com.
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN TXT \"v=spf1 -all\"
example.com. 300 IN A 192.0.2.1
example.com. 300 IN AAAA 2001:db8::1
www.example.com. 300 IN CNAME example.com.
",
        )
        .unwrap();

        assert_eq!(
            records,
            vec![
                record("example.com", HostData::A("192.0.2.1".parse().unwrap())),
                record(
                    "example.com",
                    HostData::Aaaa("2001:db8::1".parse().unwrap())
                ),
                record(
                    "www.example.com",
                    HostData::Cname("example.com".to_string())
                ),
            ]
        );
    }

    #[test]
    fn resolves_relative_names_against_origin() {
        let records = parse(
            "$ORIGIN example.com.
$TTL 300
@ IN SOA ns admin (
    1     ; serial
    3600  ; refresh
    600   ; retry
    86400 ; expire
    300 ) ; minimum
@     A     192.0.2.1
      AAAA  2001:db8::1 ; owner carried over from the previous line
www   CNAME @
blog  CNAME www
",
        )
        .unwrap();

        assert_eq!(
            records,
            vec![
                record("example.com", HostData::A("192.0.2.1".parse().unwrap())),
                record(
                    "example.com",
                    HostData::Aaaa("2001:db8::1".parse().unwrap())
                ),
                record(
                    "www.example.com",
                    HostData::Cname("example.com".to_string())
                ),
                record(
                    "blog.example.com",
                    HostData::Cname("www.example.com".to_string())
                ),
            ]
        );
    }

    #[test]
    fn rejects_relative_name_without_origin() {
        let err = parse("www 300 IN A 192.0.2.1\n").unwrap_err();
        assert!(err.to_string().contains("missing origin"), "{err}");
    }

    #[test]
    fn rejects_include() {
        let err = parse("$INCLUDE other.zone\n").unwrap_err();
        assert!(err.to_string().contains("$INCLUDE"), "{err}");
    }
}
