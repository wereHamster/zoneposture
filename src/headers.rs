use reqwest::header::{
    CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY_REPORT_ONLY, HeaderMap, HeaderName,
    STRICT_TRANSPORT_SECURITY, X_FRAME_OPTIONS,
};

use crate::finding::{Finding, Severity};
use crate::http::Response;
use crate::rules;

const ONE_YEAR_SECONDS: u64 = 365 * 24 * 60 * 60;

/// Grades the security headers of the response to `https://<host>/`.
pub fn grade(host: &str, is_apex: bool, response: &Response) -> Vec<Finding> {
    let mut findings = check_hsts(host, is_apex, &response.headers);

    // Browsers sniff responses without a Content-Type, so those may render
    // as HTML too.
    let media_type = response.media_type();
    let is_html = media_type.as_deref().is_none_or(|media_type| {
        media_type == "text/html" || media_type == "application/xhtml+xml"
    });
    if is_html {
        let policies = enforced_policies(&response.headers);
        findings.extend(check_csp(host, &response.headers, &policies));
        findings.push(check_framing(host, &response.headers, &policies));
    } else {
        findings.push(finding(
            host,
            rules::CSP_ENFORCED,
            Severity::Pass,
            format!(
                "{} is {}, not HTML; CSP and framing checks do not apply",
                response.final_url,
                media_type.unwrap_or_default()
            ),
        ));
    }

    findings
}

fn finding(host: &str, id: &'static str, severity: Severity, message: String) -> Finding {
    Finding {
        subject: host.to_string(),
        id,
        severity,
        message,
    }
}

fn header_values<'a>(headers: &'a HeaderMap, name: &HeaderName) -> impl Iterator<Item = &'a str> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
}

fn check_hsts(host: &str, is_apex: bool, headers: &HeaderMap) -> Vec<Finding> {
    let hsts = |severity, message| finding(host, rules::HSTS_POLICY, severity, message);

    // Browsers only process the first Strict-Transport-Security header.
    let Some(value) = header_values(headers, &STRICT_TRANSPORT_SECURITY).next() else {
        return vec![hsts(
            Severity::Fail,
            "no Strict-Transport-Security header".to_string(),
        )];
    };

    let directives: Vec<(String, Option<&str>)> = value
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .map(|directive| match directive.split_once('=') {
            Some((name, value)) => (
                name.trim().to_ascii_lowercase(),
                Some(value.trim().trim_matches('"')),
            ),
            None => (directive.to_ascii_lowercase(), None),
        })
        .collect();
    let has = |name: &str| directives.iter().any(|(directive, _)| directive == name);

    let max_age = directives
        .iter()
        .find(|(name, _)| name == "max-age")
        .and_then(|(_, value)| value.and_then(|value| value.parse::<u64>().ok()));
    let Some(max_age) = max_age else {
        return vec![hsts(
            Severity::Fail,
            format!("Strict-Transport-Security {value:?} has no valid max-age"),
        )];
    };
    if max_age == 0 {
        return vec![hsts(
            Severity::Fail,
            "max-age=0 tells browsers to drop the HSTS policy".to_string(),
        )];
    }

    let include_subdomains = has("includesubdomains");
    let mut summary = format!("max-age={max_age}");
    if include_subdomains {
        summary.push_str("; includeSubDomains");
    }
    if has("preload") {
        summary.push_str("; preload");
    }

    let mut findings = vec![if max_age < ONE_YEAR_SECONDS {
        hsts(
            Severity::Warn,
            format!("{summary}; max-age is shorter than one year"),
        )
    } else {
        hsts(Severity::Pass, summary)
    }];
    if is_apex && !include_subdomains {
        findings.push(finding(
            host,
            rules::HSTS_INCLUDE_SUBDOMAINS,
            Severity::Warn,
            "no includeSubDomains; subdomains are not covered".to_string(),
        ));
    }
    findings
}

/// A parsed CSP: directive names are lowercase, and only the first occurrence
/// of a directive counts.
type Policy = Vec<(String, Vec<String>)>;

fn parse_policy(value: &str) -> Policy {
    let mut policy: Policy = Vec::new();
    for directive in value.split(';') {
        let mut tokens = directive.split_whitespace();
        let Some(name) = tokens.next() else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        if policy.iter().all(|(existing, _)| *existing != name) {
            policy.push((name, tokens.map(str::to_string).collect()));
        }
    }
    policy
}

fn directive<'a>(policy: &'a Policy, name: &str) -> Option<&'a [String]> {
    policy
        .iter()
        .find(|(directive, _)| directive == name)
        .map(|(_, sources)| sources.as_slice())
}

/// All enforced policies. A header may carry several comma-separated
/// policies, and the browser enforces every one of them.
fn enforced_policies(headers: &HeaderMap) -> Vec<Policy> {
    header_values(headers, &CONTENT_SECURITY_POLICY)
        .flat_map(|value| value.split(','))
        .map(parse_policy)
        .filter(|policy| !policy.is_empty())
        .collect()
}

fn has_source(sources: &[String], source: &str) -> bool {
    sources.iter().any(|s| s.eq_ignore_ascii_case(source))
}

fn script_source_weakness(sources: &[String], weakness: &str) -> bool {
    let strict_dynamic = has_source(sources, "'strict-dynamic'");
    match weakness {
        // Browsers ignore 'unsafe-inline' when a nonce or hash is present.
        "'unsafe-inline'" => {
            has_source(sources, weakness)
                && !strict_dynamic
                && !sources.iter().any(|s| {
                    let s = s.to_ascii_lowercase();
                    s.starts_with("'nonce-") || s.starts_with("'sha")
                })
        }
        "'unsafe-eval'" => has_source(sources, weakness),
        // Browsers ignore host and scheme sources when 'strict-dynamic' is
        // present.
        _ => has_source(sources, weakness) && !strict_dynamic,
    }
}

const SCRIPT_WEAKNESSES: &[(&str, &str)] = &[
    (
        "'unsafe-inline'",
        "inline scripts run, which defeats XSS protection",
    ),
    ("'unsafe-eval'", "eval() and similar functions are allowed"),
    ("*", "scripts load from any host"),
    ("https:", "scripts load from any HTTPS URL"),
    ("http:", "scripts load from any HTTP URL"),
    ("data:", "scripts load from data: URLs"),
];

fn check_csp(host: &str, headers: &HeaderMap, policies: &[Policy]) -> Vec<Finding> {
    let enforced = |severity, message| finding(host, rules::CSP_ENFORCED, severity, message);
    let script_src = |severity, message| finding(host, rules::CSP_SCRIPT_SRC, severity, message);
    let object_src = |severity, message| finding(host, rules::CSP_OBJECT_SRC, severity, message);

    if policies.is_empty() {
        return vec![
            if header_values(headers, &CONTENT_SECURITY_POLICY_REPORT_ONLY)
                .next()
                .is_some()
            {
                enforced(
                    Severity::Warn,
                    "only Content-Security-Policy-Report-Only is sent; nothing is enforced"
                        .to_string(),
                )
            } else {
                enforced(
                    Severity::Fail,
                    "no Content-Security-Policy header".to_string(),
                )
            },
        ];
    }

    let mut findings = Vec::new();

    let script_policies: Vec<(&str, &[String])> = policies
        .iter()
        .filter_map(|policy| {
            directive(policy, "script-src")
                .map(|sources| ("script-src", sources))
                .or_else(|| {
                    directive(policy, "default-src").map(|sources| ("default-src", sources))
                })
        })
        .collect();

    match script_policies.first() {
        None => findings.push(script_src(
            Severity::Warn,
            "does not restrict scripts; no script-src or default-src".to_string(),
        )),
        Some((name, sources)) => {
            findings.push(script_src(
                Severity::Pass,
                format!("{name} {}", sources.join(" ")),
            ));
            // With several policies, a script must pass all of them, so a
            // weakness only matters if every policy has it.
            for (weakness, consequence) in SCRIPT_WEAKNESSES {
                if script_policies
                    .iter()
                    .all(|(_, sources)| script_source_weakness(sources, weakness))
                {
                    findings.push(script_src(
                        Severity::Warn,
                        format!("{name} allows {weakness}; {consequence}"),
                    ));
                }
            }
        }
    }

    let restricts_objects = policies.iter().any(|policy| {
        directive(policy, "object-src").is_some() || directive(policy, "default-src").is_some()
    });
    if !restricts_objects {
        findings.push(object_src(
            Severity::Warn,
            "no object-src or default-src; <object> and <embed> are unrestricted".to_string(),
        ));
    }

    findings
}

fn check_framing(host: &str, headers: &HeaderMap, policies: &[Policy]) -> Finding {
    let framing = |severity, message| finding(host, rules::CSP_FRAME_ANCESTORS, severity, message);

    let frame_ancestors: Vec<&[String]> = policies
        .iter()
        .filter_map(|policy| directive(policy, "frame-ancestors"))
        .collect();

    if let Some(first) = frame_ancestors.first() {
        let summary = format!("frame-ancestors {}", first.join(" "));
        let allows_any = |sources: &&[String]| {
            ["*", "https:", "http:"]
                .iter()
                .any(|source| has_source(sources, source))
        };
        return if frame_ancestors.iter().all(allows_any) {
            framing(
                Severity::Warn,
                format!("{summary} lets any site frame the page"),
            )
        } else {
            framing(Severity::Pass, summary)
        };
    }

    let x_frame_options = header_values(headers, &X_FRAME_OPTIONS)
        .next()
        .map(|value| value.trim().to_ascii_uppercase());
    match x_frame_options.as_deref() {
        Some(value @ ("DENY" | "SAMEORIGIN")) => framing(
            Severity::Warn,
            format!(
                "framing is restricted only by the legacy X-Frame-Options: {value}; use CSP frame-ancestors"
            ),
        ),
        _ => framing(
            Severity::Fail,
            "no CSP frame-ancestors; any site can frame the page".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::response;

    const HTML: (&str, &str) = ("content-type", "text/html; charset=utf-8");
    const HSTS: (&str, &str) = (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    );
    const CSP: (&str, &str) = (
        "content-security-policy",
        "default-src 'self'; frame-ancestors 'none'",
    );

    const HSTS_IDS: &[&str] = &["hsts-policy", "hsts-include-subdomains"];
    const CSP_IDS: &[&str] = &["csp-enforced", "csp-script-src", "csp-object-src"];
    const FRAMING_IDS: &[&str] = &["csp-frame-ancestors"];

    fn results(is_apex: bool, headers: &[(&str, &str)]) -> Vec<(&'static str, Severity, String)> {
        grade("example.com", is_apex, &response(200, headers, ""))
            .into_iter()
            .map(|f| (f.id, f.severity, f.message))
            .collect()
    }

    fn check(
        results: &[(&'static str, Severity, String)],
        ids: &[&str],
    ) -> Vec<(Severity, String)> {
        results
            .iter()
            .filter(|(id, _, _)| ids.contains(id))
            .map(|(_, severity, message)| (*severity, message.clone()))
            .collect()
    }

    fn ids(results: &[(&'static str, Severity, String)]) -> Vec<&'static str> {
        results.iter().map(|(id, _, _)| *id).collect()
    }

    fn result(severity: Severity, message: &str) -> (Severity, String) {
        (severity, message.to_string())
    }

    #[test]
    fn strong_headers_pass() {
        assert_eq!(
            results(true, &[HTML, HSTS, CSP]),
            [
                (
                    "hsts-policy",
                    Severity::Pass,
                    "max-age=63072000; includeSubDomains; preload".to_string()
                ),
                (
                    "csp-script-src",
                    Severity::Pass,
                    "default-src 'self'".to_string()
                ),
                (
                    "csp-frame-ancestors",
                    Severity::Pass,
                    "frame-ancestors 'none'".to_string()
                ),
            ]
        );
    }

    #[test]
    fn hsts_grades() {
        for (value, is_apex, expected) in [
            (
                None,
                false,
                vec![result(
                    Severity::Fail,
                    "no Strict-Transport-Security header",
                )],
            ),
            (
                Some("max-age=0"),
                false,
                vec![result(
                    Severity::Fail,
                    "max-age=0 tells browsers to drop the HSTS policy",
                )],
            ),
            (
                Some("includeSubDomains"),
                false,
                vec![result(
                    Severity::Fail,
                    "Strict-Transport-Security \"includeSubDomains\" has no valid max-age",
                )],
            ),
            (
                Some("max-age=\"86400\"; includesubdomains"),
                false,
                vec![result(
                    Severity::Warn,
                    "max-age=86400; includeSubDomains; max-age is shorter than one year",
                )],
            ),
            (
                Some("max-age=31536000"),
                false,
                vec![result(Severity::Pass, "max-age=31536000")],
            ),
            (
                Some("max-age=31536000"),
                true,
                vec![
                    result(Severity::Pass, "max-age=31536000"),
                    result(
                        Severity::Warn,
                        "no includeSubDomains; subdomains are not covered",
                    ),
                ],
            ),
        ] {
            let mut headers = vec![HTML, CSP];
            if let Some(value) = value {
                headers.push(("strict-transport-security", value));
            }
            assert_eq!(
                check(&results(is_apex, &headers), HSTS_IDS),
                expected,
                "{value:?}"
            );
        }
    }

    #[test]
    fn missing_and_report_only_csp() {
        assert_eq!(
            check(&results(false, &[HTML, HSTS]), CSP_IDS),
            [result(Severity::Fail, "no Content-Security-Policy header")]
        );
        assert_eq!(
            check(
                &results(
                    false,
                    &[
                        HTML,
                        HSTS,
                        ("content-security-policy-report-only", "default-src 'self'")
                    ]
                ),
                CSP_IDS
            ),
            [result(
                Severity::Warn,
                "only Content-Security-Policy-Report-Only is sent; nothing is enforced"
            )]
        );
    }

    #[test]
    fn csp_script_weaknesses() {
        let findings = results(
            false,
            &[
                HTML,
                HSTS,
                (
                    "content-security-policy",
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:",
                ),
            ],
        );
        assert_eq!(
            ids(&findings),
            [
                "hsts-policy",
                "csp-script-src",
                "csp-script-src",
                "csp-script-src",
                "csp-script-src",
                "csp-script-src",
                "csp-object-src",
                "csp-frame-ancestors",
            ]
        );
        assert_eq!(
            check(&findings, CSP_IDS),
            [
                result(
                    Severity::Pass,
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:"
                ),
                result(
                    Severity::Warn,
                    "script-src allows 'unsafe-inline'; inline scripts run, which defeats XSS protection"
                ),
                result(
                    Severity::Warn,
                    "script-src allows 'unsafe-eval'; eval() and similar functions are allowed"
                ),
                result(
                    Severity::Warn,
                    "script-src allows https:; scripts load from any HTTPS URL"
                ),
                result(
                    Severity::Warn,
                    "script-src allows data:; scripts load from data: URLs"
                ),
                result(
                    Severity::Warn,
                    "no object-src or default-src; <object> and <embed> are unrestricted"
                ),
            ]
        );
    }

    #[test]
    fn csp_nonce_and_strict_dynamic_neutralize_allowlists() {
        let findings = results(
            false,
            &[
                HTML,
                HSTS,
                (
                    "content-security-policy",
                    "object-src 'none'; script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https:",
                ),
            ],
        );
        assert_eq!(check(&findings, CSP_IDS).len(), 1, "{findings:?}");
    }

    #[test]
    fn csp_weakness_must_be_in_every_policy() {
        let findings = results(
            false,
            &[
                HTML,
                HSTS,
                (
                    "content-security-policy",
                    "default-src 'self' 'unsafe-inline'",
                ),
                (
                    "content-security-policy",
                    "script-src 'self', object-src 'none'",
                ),
            ],
        );
        assert_eq!(
            check(&findings, CSP_IDS),
            [result(Severity::Pass, "default-src 'self' 'unsafe-inline'")]
        );
    }

    #[test]
    fn csp_without_script_restriction_warns() {
        let findings = results(
            false,
            &[HTML, HSTS, ("content-security-policy", "img-src 'self'")],
        );
        assert_eq!(
            check(&findings, CSP_IDS)[0],
            result(
                Severity::Warn,
                "does not restrict scripts; no script-src or default-src"
            )
        );
    }

    #[test]
    fn framing_grades() {
        for (headers, expected) in [
            (
                vec![(
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'self' https://partner.example",
                )],
                result(
                    Severity::Pass,
                    "frame-ancestors 'self' https://partner.example",
                ),
            ),
            (
                vec![(
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors *",
                )],
                result(
                    Severity::Warn,
                    "frame-ancestors * lets any site frame the page",
                ),
            ),
            (
                vec![
                    ("content-security-policy", "default-src 'self'"),
                    ("x-frame-options", "sameorigin"),
                ],
                result(
                    Severity::Warn,
                    "framing is restricted only by the legacy X-Frame-Options: SAMEORIGIN; use CSP frame-ancestors",
                ),
            ),
            (
                vec![
                    (
                        "content-security-policy-report-only",
                        "frame-ancestors 'none'",
                    ),
                    ("x-frame-options", "ALLOW-FROM https://partner.example"),
                ],
                result(
                    Severity::Fail,
                    "no CSP frame-ancestors; any site can frame the page",
                ),
            ),
        ] {
            let mut all = vec![HTML, HSTS];
            all.extend(headers.iter().copied());
            assert_eq!(
                check(&results(false, &all), FRAMING_IDS),
                [expected],
                "{headers:?}"
            );
        }
    }

    #[test]
    fn non_html_skips_csp_and_framing() {
        assert_eq!(
            results(false, &[("content-type", "application/json"), HSTS]),
            [
                (
                    "hsts-policy",
                    Severity::Pass,
                    "max-age=63072000; includeSubDomains; preload".to_string()
                ),
                (
                    "csp-enforced",
                    Severity::Pass,
                    "https://example.com/ is application/json, not HTML; CSP and framing checks do not apply"
                        .to_string()
                ),
            ]
        );
    }
}
