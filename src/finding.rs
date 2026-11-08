use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Pass,
    Warn,
    Fail,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(match self {
            Severity::Info => "INFO",
            Severity::Pass => "PASS",
            Severity::Warn => "WARN",
            Severity::Fail => "FAIL",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The domain name the finding is about.
    pub subject: String,
    /// The id of the [`Rule`](crate::rules::Rule) that produced the finding.
    pub id: &'static str,
    pub severity: Severity,
    pub message: String,
}
