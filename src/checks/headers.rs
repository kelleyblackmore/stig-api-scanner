/// DISA API SRG V1R0.1 — Security Response Headers
///
/// V-274600 (MED): API must protect Session IDs (covered in transport.rs for HSTS).
/// V-274709 (HIGH): API must restrict data returned — checked via Cache-Control & content limits.
///
/// Additional baseline security headers derived from OWASP / NIST SP 800-53 SA-11:
///   X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Content-Security-Policy
use async_trait::async_trait;
use anyhow::Result;
use reqwest::Response;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, Severity},
};

pub struct HeadersCheck;

struct HeaderRule {
    header: &'static str,
    stig_id: &'static str,
    severity: Severity,
    fix: &'static str,
    /// Optional: required substring in the header value.
    required_value: Option<&'static str>,
}

fn header_rules() -> Vec<HeaderRule> {
    vec![
        HeaderRule {
            header: "strict-transport-security",
            stig_id: "V-274600",
            severity: Severity::Medium,
            fix: "Set: Strict-Transport-Security: max-age=31536000; includeSubDomains",
            required_value: None,
        },
        HeaderRule {
            header: "x-content-type-options",
            stig_id: "V-274497",
            severity: Severity::Medium,
            fix: "Set: X-Content-Type-Options: nosniff",
            required_value: Some("nosniff"),
        },
        HeaderRule {
            header: "x-frame-options",
            stig_id: "V-274497",
            severity: Severity::Medium,
            fix: "Set: X-Frame-Options: DENY (or SAMEORIGIN)",
            required_value: None,
        },
        HeaderRule {
            header: "referrer-policy",
            stig_id: "V-274615",
            severity: Severity::Medium,
            fix: "Set: Referrer-Policy: no-referrer or strict-origin-when-cross-origin",
            required_value: None,
        },
        HeaderRule {
            header: "content-security-policy",
            stig_id: "V-274767",
            severity: Severity::Medium,
            fix: "Set a Content-Security-Policy header appropriate for your API consumers.",
            required_value: None,
        },
    ]
}

fn check_header(resp: &Response, rule: &HeaderRule, endpoint: &str) -> Finding {
    let name = rule.header;
    let title_short = name
        .split('-')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                None => String::new(),
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join("-");

    if let Some(val) = resp.headers().get(name) {
        let val_str = val.to_str().unwrap_or("");
        if let Some(required) = rule.required_value {
            if val_str.to_lowercase().contains(&required.to_lowercase()) {
                Finding::pass(
                    rule.stig_id,
                    &format!("{} header present with correct value", title_short),
                    rule.severity.clone(),
                    rule.fix,
                )
                .with_endpoint(endpoint)
                .with_evidence(val_str)
            } else {
                Finding::fail(
                    rule.stig_id,
                    &format!("{} header has incorrect value", title_short),
                    rule.severity.clone(),
                    rule.fix,
                )
                .with_endpoint(endpoint)
                .with_evidence(val_str)
            }
        } else {
            Finding::pass(
                rule.stig_id,
                &format!("{} header present", title_short),
                rule.severity.clone(),
                rule.fix,
            )
            .with_endpoint(endpoint)
            .with_evidence(val_str)
        }
    } else {
        Finding::fail(
            rule.stig_id,
            &format!("{} security header is missing", title_short),
            rule.severity.clone(),
            rule.fix,
        )
        .with_endpoint(endpoint)
    }
}

/// Flag verbose Server / X-Powered-By disclosure.
fn check_server_disclosure(resp: &Response, endpoint: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(val) = resp.headers().get("server") {
        let s = val.to_str().unwrap_or("");
        // Flag if the value reveals a specific version number (digit after a slash or space)
        if s.chars().any(|c| c.is_ascii_digit()) {
            out.push(
                Finding::fail(
                    "V-274615",
                    "Server header discloses version information",
                    Severity::Medium,
                    "Configure the web server to return a generic 'Server' value or remove \
                     the header entirely to prevent fingerprinting.",
                )
                .with_endpoint(endpoint)
                .with_evidence(s),
            );
        }
    }

    if let Some(val) = resp.headers().get("x-powered-by") {
        out.push(
            Finding::fail(
                "V-274615",
                "X-Powered-By header discloses technology stack",
                Severity::Medium,
                "Remove the X-Powered-By header from all API responses.",
            )
            .with_endpoint(endpoint)
            .with_evidence(val.to_str().unwrap_or("(present)")),
        );
    }

    out
}

#[async_trait]
impl Check for HeadersCheck {
    fn name(&self) -> &str {
        "headers"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.headers
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let rules = header_rules();

        // Check headers on each configured endpoint; fall back to "/" if none defined.
        let paths: Vec<&str> = if config.endpoints.is_empty() {
            vec!["/"]
        } else {
            config.endpoints.iter().map(|e| e.path.as_str()).collect()
        };

        // Deduplicate — only hit each unique path once.
        let mut seen = std::collections::HashSet::new();
        for path in paths {
            if !seen.insert(path) {
                continue;
            }
            match client.get(path).await {
                Ok(resp) => {
                    for rule in &rules {
                        findings.push(check_header(&resp, rule, path));
                    }
                    findings.extend(check_server_disclosure(&resp, path));
                }
                Err(e) => {
                    findings.push(
                        Finding::fail(
                            "V-274497",
                            "Could not reach endpoint to check security headers",
                            Severity::Medium,
                            "Verify the endpoint is reachable from the scanner.",
                        )
                        .with_endpoint(path)
                        .with_details(&e.to_string()),
                    );
                }
            }
        }

        Ok(findings)
    }
}
