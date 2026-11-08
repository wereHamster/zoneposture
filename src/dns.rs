use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;

use domain::base::iana::{Rcode, Rtype};
use domain::base::name::Name;
use domain::base::question::Question;
use domain::rdata::AllRecordData;
use domain::resolv::StubResolver;
use domain::resolv::stub::conf::ResolvConf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Qtype {
    Soa,
    Cname,
    A,
    Aaaa,
    Caa,
    Mx,
    Txt,
}

impl Qtype {
    fn rtype(self) -> Rtype {
        match self {
            Qtype::Soa => Rtype::SOA,
            Qtype::Cname => Rtype::CNAME,
            Qtype::A => Rtype::A,
            Qtype::Aaaa => Rtype::AAAA,
            Qtype::Caa => Rtype::CAA,
            Qtype::Mx => Rtype::MX,
            Qtype::Txt => Rtype::TXT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    Soa(Soa),
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    /// The exchange is `.` for a null MX (RFC 7505).
    Mx {
        preference: u16,
        exchange: String,
    },
    /// The character-strings of the record, concatenated.
    Txt(Vec<u8>),
}

impl Rdata {
    pub fn qtype(&self) -> Qtype {
        match self {
            Rdata::Soa(_) => Qtype::Soa,
            Rdata::A(_) => Qtype::A,
            Rdata::Aaaa(_) => Qtype::Aaaa,
            Rdata::Cname(_) => Qtype::Cname,
            Rdata::Caa { .. } => Qtype::Caa,
            Rdata::Mx { .. } => Qtype::Mx,
            Rdata::Txt(_) => Qtype::Txt,
        }
    }
}

/// A resource record. Names are lowercase and have no trailing dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rr {
    pub owner: String,
    pub ttl: u32,
    pub data: Rdata,
}

pub trait Resolve {
    /// The records of type `qtype` in the answer section, with any owner.
    /// A name that does not exist, or has no such records, yields an empty
    /// list. Failures to get an answer are errors, so that a lookup that
    /// did not happen is never mistaken for an empty result.
    async fn query(&self, name: &str, qtype: Qtype) -> Result<Vec<Rr>, String>;
}

/// The stub resolver sends each query once, and a single lost UDP packet
/// would otherwise fail a lookup.
const ATTEMPTS: usize = 3;

/// Per attempt, so a lookup that is never answered fails after
/// `ATTEMPTS * TIMEOUT` instead of the stub resolver's default of 5 seconds
/// per attempt.
const TIMEOUT: Duration = Duration::from_secs(2);

/// Resolves through the servers in the system's resolver configuration.
pub struct System(StubResolver);

impl System {
    pub fn new() -> Self {
        let mut conf = ResolvConf::default();
        conf.options.timeout = TIMEOUT;
        conf.finalize();
        System(StubResolver::from_conf(conf))
    }
}

impl Resolve for System {
    async fn query(&self, name: &str, qtype: Qtype) -> Result<Vec<Rr>, String> {
        let fail = |err: &dyn std::fmt::Display| format!("{name}: {qtype:?} query failed: {err}");

        let qname = Name::<Vec<u8>>::from_str(&format!("{name}.")).map_err(|e| fail(&e))?;
        let question = Question::new_in(qname, qtype.rtype());
        let mut attempt = 1;
        let answer = loop {
            match self.0.query(question.clone()).await {
                Ok(answer) => break answer,
                Err(err) if err.kind() == io::ErrorKind::TimedOut && attempt < ATTEMPTS => {
                    attempt += 1;
                }
                Err(err) => return Err(fail(&format!("{err} (attempt {attempt} of {ATTEMPTS})"))),
            }
        };
        match answer.header().rcode() {
            Rcode::NOERROR | Rcode::NXDOMAIN => {}
            rcode => return Err(fail(&rcode)),
        }

        let mut records = Vec::new();
        let section = answer.answer().map_err(|e| fail(&e))?;
        for record in section.limit_to::<AllRecordData<_, _>>() {
            let record = record.map_err(|e| fail(&e))?;
            let data = match record.data() {
                AllRecordData::Soa(soa) => Rdata::Soa(Soa {
                    mname: soa.mname().to_string().to_ascii_lowercase(),
                    rname: soa.rname().to_string().to_ascii_lowercase(),
                    serial: soa.serial().into_int(),
                    refresh: soa.refresh().as_secs(),
                    retry: soa.retry().as_secs(),
                    expire: soa.expire().as_secs(),
                    minimum: soa.minimum().as_secs(),
                }),
                AllRecordData::A(a) => Rdata::A(a.addr()),
                AllRecordData::Aaaa(aaaa) => Rdata::Aaaa(aaaa.addr()),
                AllRecordData::Cname(cname) => {
                    Rdata::Cname(cname.cname().to_string().to_ascii_lowercase())
                }
                AllRecordData::Caa(caa) => Rdata::Caa {
                    flags: caa.flags().bits(),
                    tag: caa.tag().to_string().to_ascii_lowercase(),
                    value: String::from_utf8_lossy(caa.value()).into_owned(),
                },
                AllRecordData::Mx(mx) => Rdata::Mx {
                    preference: mx.preference(),
                    exchange: mx.exchange().to_string().to_ascii_lowercase(),
                },
                AllRecordData::Txt(txt) => Rdata::Txt(txt.text::<Vec<u8>>()),
                _ => continue,
            };
            if data.qtype() == qtype {
                records.push(Rr {
                    owner: record.owner().to_string().to_ascii_lowercase(),
                    ttl: record.ttl().as_secs(),
                    data,
                });
            }
        }
        Ok(records)
    }
}
