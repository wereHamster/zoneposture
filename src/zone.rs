use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use domain::base::iana::Class;
use domain::rdata::ZoneRecordData;
use domain::zonefile::inplace::{Entry, Zonefile};

/// The records of a zone that the audits use. Names are lowercase and have no
/// trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// Owner name of the SOA record.
    pub apex: String,
    /// Records in file order.
    pub records: Vec<Record>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub data: RecordData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx(String),
    /// The character-strings of the record, concatenated.
    Txt(String),
    Caa {
        critical: bool,
        /// Lowercase.
        tag: String,
        value: String,
    },
}

impl RecordData {
    pub fn record_type(&self) -> &'static str {
        match self {
            RecordData::A(_) => "A",
            RecordData::Aaaa(_) => "AAAA",
            RecordData::Cname(_) => "CNAME",
            RecordData::Mx(_) => "MX",
            RecordData::Txt(_) => "TXT",
            RecordData::Caa { .. } => "CAA",
        }
    }

    pub fn is_host(&self) -> bool {
        matches!(
            self,
            RecordData::A(_) | RecordData::Aaaa(_) | RecordData::Cname(_)
        )
    }
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordData::A(addr) => addr.fmt(f),
            RecordData::Aaaa(addr) => addr.fmt(f),
            RecordData::Cname(target) | RecordData::Mx(target) => target.fmt(f),
            RecordData::Txt(text) => write!(f, "{text:?}"),
            RecordData::Caa {
                critical,
                tag,
                value,
            } => write!(f, "{} {tag} {value:?}", if *critical { 128 } else { 0 }),
        }
    }
}

impl Zone {
    /// Reads a BIND-format zone file.
    pub fn read(path: &Path) -> Result<Zone, Box<dyn Error>> {
        Zone::parse(&mut File::open(path)?)
    }

    fn parse(input: &mut impl Read) -> Result<Zone, Box<dyn Error>> {
        let mut zonefile = Zonefile::load(input)?;
        zonefile.set_default_class(Class::IN);
        let mut apex = None;
        let mut records = Vec::new();

        while let Some(entry) = zonefile.next_entry()? {
            let record = match entry {
                Entry::Record(record) => record,
                Entry::Include { .. } => return Err("$INCLUDE is not supported".into()),
            };
            let name = normalize_name(record.owner().to_string());

            let data = match record.data() {
                ZoneRecordData::Soa(_) => {
                    if apex.is_some() {
                        return Err("multiple SOA records".into());
                    }
                    apex = Some(name);
                    continue;
                }
                ZoneRecordData::A(a) => RecordData::A(a.addr()),
                ZoneRecordData::Aaaa(aaaa) => RecordData::Aaaa(aaaa.addr()),
                ZoneRecordData::Cname(cname) => {
                    RecordData::Cname(normalize_name(cname.cname().to_string()))
                }
                ZoneRecordData::Mx(mx) => RecordData::Mx(normalize_name(mx.exchange().to_string())),
                ZoneRecordData::Txt(txt) => {
                    RecordData::Txt(String::from_utf8_lossy(&txt.text::<Vec<u8>>()).into_owned())
                }
                ZoneRecordData::Caa(caa) => RecordData::Caa {
                    critical: caa.flags().bits() & 0x80 != 0,
                    tag: caa.tag().to_string().to_ascii_lowercase(),
                    value: String::from_utf8_lossy(caa.value()).into_owned(),
                },
                _ => continue,
            };

            records.push(Record { name, data });
        }

        let apex = apex.ok_or("no SOA record, cannot determine the zone apex")?;
        Ok(Zone { apex, records })
    }

    pub fn records_at<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a RecordData> {
        self.records
            .iter()
            .filter(move |r| r.name == name)
            .map(|r| &r.data)
    }

    pub fn txt_at<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.records_at(name).filter_map(|data| match data {
            RecordData::Txt(text) => Some(text.as_str()),
            _ => None,
        })
    }
}

fn normalize_name(name: String) -> String {
    expand_origin_symbol(name).to_ascii_lowercase()
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
pub(crate) fn parse_str(input: &str) -> Result<Zone, Box<dyn Error>> {
    Zone::parse(&mut input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, data: RecordData) -> Record {
        Record {
            name: name.to_string(),
            data,
        }
    }

    #[test]
    fn keeps_records_used_by_audits() {
        let zone = parse_str(
            "example.com. 300 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 300
example.com. 300 IN NS ns.example.com.
example.com. 300 IN MX 10 mail.example.com.
example.com. 300 IN TXT \"v=spf1 \" \"-all\"
example.com. 300 IN A 192.0.2.1
example.com. 300 IN AAAA 2001:db8::1
WWW.Example.com. 300 IN CNAME Example.COM.
",
        )
        .unwrap();

        assert_eq!(
            zone,
            Zone {
                apex: "example.com".to_string(),
                records: vec![
                    record(
                        "example.com",
                        RecordData::Mx("mail.example.com".to_string())
                    ),
                    record("example.com", RecordData::Txt("v=spf1 -all".to_string())),
                    record("example.com", RecordData::A("192.0.2.1".parse().unwrap())),
                    record(
                        "example.com",
                        RecordData::Aaaa("2001:db8::1".parse().unwrap())
                    ),
                    record(
                        "www.example.com",
                        RecordData::Cname("example.com".to_string())
                    ),
                ],
            }
        );
    }

    #[test]
    fn resolves_relative_names_against_origin() {
        let zone = parse_str(
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

        assert_eq!(zone.apex, "example.com");
        assert_eq!(
            zone.records,
            vec![
                record("example.com", RecordData::A("192.0.2.1".parse().unwrap())),
                record(
                    "example.com",
                    RecordData::Aaaa("2001:db8::1".parse().unwrap())
                ),
                record(
                    "www.example.com",
                    RecordData::Cname("example.com".to_string())
                ),
                record(
                    "blog.example.com",
                    RecordData::Cname("www.example.com".to_string())
                ),
            ]
        );
    }

    #[test]
    fn rejects_zone_without_soa() {
        let err = parse_str("example.com. 300 IN A 192.0.2.1\n").unwrap_err();
        assert!(err.to_string().contains("no SOA record"), "{err}");
    }

    #[test]
    fn rejects_relative_name_without_origin() {
        let err = parse_str("www 300 IN A 192.0.2.1\n").unwrap_err();
        assert!(err.to_string().contains("missing origin"), "{err}");
    }

    #[test]
    fn rejects_include() {
        let err = parse_str("$INCLUDE other.zone\n").unwrap_err();
        assert!(err.to_string().contains("$INCLUDE"), "{err}");
    }
}
