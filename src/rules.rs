/// A check that produces findings. The id is the stable name of the check:
/// findings carry it, and `explain` looks it up.
pub struct Rule {
    pub id: &'static str,
    pub docs: &'static str,
}

/// Declares one constant per rule, for findings to refer to, and `ALL`. Each
/// rule needs a document at `docs/rules/<id>.md`, which is embedded.
macro_rules! rules {
    ($($name:ident = $id:literal;)*) => {
        $(pub const $name: &str = $id;)*

        pub const ALL: &[Rule] = &[$(Rule {
            id: $id,
            docs: include_str!(concat!("../docs/rules/", $id, ".md")),
        }),*];
    };
}

rules! {
    CAA_MISSING = "caa-missing";
    CAA_CRITICAL_TAG = "caa-critical-tag";
    CAA_ISSUE = "caa-issue";
    CAA_ISSUEWILD = "caa-issuewild";
    CAA_IODEF = "caa-iodef";
    CERTIFICATE_CAA = "certificate-caa";
    SPF_RECORD = "spf-record";
    SPF_ALL = "spf-all";
    DMARC_RECORD = "dmarc-record";
    DMARC_POLICY = "dmarc-policy";
    DMARC_PCT = "dmarc-pct";
    DMARC_RUA = "dmarc-rua";
    HSTS_POLICY = "hsts-policy";
    HSTS_INCLUDE_SUBDOMAINS = "hsts-include-subdomains";
    CSP_ENFORCED = "csp-enforced";
    CSP_SCRIPT_SRC = "csp-script-src";
    CSP_OBJECT_SRC = "csp-object-src";
    CSP_FRAME_ANCESTORS = "csp-frame-ancestors";
    HTTPS_UNREACHABLE = "https-unreachable";
    HTTPS_REDIRECT = "https-redirect";
    DNS_WILDCARD = "dns-wildcard";
    DNS_NON_PUBLIC_ADDRESS = "dns-non-public-address";
    TLS_CONNECTION = "tls-connection";
    CERTIFICATE_VALIDITY_PERIOD = "certificate-validity-period";
    CERTIFICATE_HOSTNAME = "certificate-hostname";
    CERTIFICATE_TRUST = "certificate-trust";
    SECURITY_TXT_MISSING = "security-txt-missing";
    SECURITY_TXT_LOCATION = "security-txt-location";
    SECURITY_TXT_FORMAT = "security-txt-format";
    SECURITY_TXT_CONTACT = "security-txt-contact";
    SECURITY_TXT_EXPIRES = "security-txt-expires";
    SECURITY_TXT_CANONICAL = "security-txt-canonical";
}

pub fn find(id: &str) -> Option<&'static Rule> {
    ALL.iter().find(|rule| rule.id == id)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;

    #[test]
    fn ids_are_unique_lowercase_words() {
        let ids: BTreeSet<&str> = ALL.iter().map(|rule| rule.id).collect();
        assert_eq!(ids.len(), ALL.len());
        for id in ids {
            assert!(
                id.split('-').all(|word| !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())),
                "{id}"
            );
        }
    }

    #[test]
    fn every_document_starts_with_its_id() {
        for rule in ALL {
            assert_eq!(
                rule.docs.lines().next(),
                Some(format!("# {}", rule.id).as_str())
            );
        }
    }

    #[test]
    fn every_document_has_a_rule() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/rules");
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let id = path.file_stem().unwrap().to_str().unwrap();
            assert!(find(id).is_some(), "{} has no rule", path.display());
        }
    }

    #[test]
    fn find_matches_the_exact_id() {
        assert!(find("caa-missing").is_some());
        assert!(find("caa").is_none());
        assert!(find("CAA-MISSING").is_none());
    }
}
