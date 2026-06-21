/// DISA API SRG V1R0.1 — Input Validation & Output Encoding
///
/// V-274714 (MED): The API must use parameterized queries (SQL injection prevention).
/// V-274715 (MED): The API must provide input validation.
/// V-274767 (MED): The API must encode outputs (XSS prevention).
///
/// All probes use SAFE, benign payloads designed to detect vulnerabilities without
/// executing destructive operations. Payloads are chosen to trigger detectable error
/// patterns without causing data modification.
use async_trait::async_trait;
use anyhow::Result;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, FindingStatus, Severity},
};

pub struct InputValidationCheck;

/// A safe probe: query string key → value, expected bad pattern in response that
/// indicates the input was reflected or caused a SQL error.
struct Probe {
    name: &'static str,
    stig_id: &'static str,
    param: &'static str,
    value: String,
    /// Strings that, if present in the response body, indicate a vulnerability.
    bad_patterns: &'static [&'static str],
    severity: Severity,
    fix: &'static str,
}

fn probes() -> Vec<Probe> {
    vec![
        // SQL error injection — safe string that triggers parse errors in SQL but can't modify data
        Probe {
            name: "SQL error injection",
            stig_id: "V-274714",
            param: "id",
            value: "1'--".to_string(),
            bad_patterns: &[
                "sql syntax",
                "you have an error in your sql",
                "ora-",
                "pg::syntaxerror",
                "sqlite3::exception",
                "unclosed quotation mark",
                "quoted string not properly terminated",
                "syntax error",
                "sqlexception",
                "odbc",
            ],
            severity: Severity::High,
            fix: "Use parameterized queries / prepared statements for all database operations. \
                  Never interpolate user input directly into SQL strings.",
        },
        // XSS reflection probe
        Probe {
            name: "XSS reflection",
            stig_id: "V-274767",
            param: "q",
            value: "<script>alert(1)</script>".to_string(),
            bad_patterns: &["<script>alert(1)</script>", "<script>alert("],
            severity: Severity::High,
            fix: "Encode all user-controlled output. Apply context-appropriate escaping \
                  (HTML entity encoding for HTML context, JSON escaping for JSON responses). \
                  Set Content-Security-Policy to prevent script execution.",
        },
        // Path traversal
        Probe {
            name: "Path traversal",
            stig_id: "V-274715",
            param: "file",
            value: "../../etc/passwd".to_string(),
            bad_patterns: &["root:x:", "root:!", "[boot loader]", "/bin/bash"],
            severity: Severity::High,
            fix: "Validate and sanitize all file path parameters. Use allowlists of permitted \
                  files/directories. Resolve paths and verify they are within the allowed root.",
        },
        // Oversized input (basic DoS resilience check)
        Probe {
            name: "Oversized input",
            stig_id: "V-274715",
            param: "data",
            value: "A".repeat(8192),
            bad_patterns: &["500", "internal server error", "out of memory"],
            severity: Severity::Medium,
            fix: "Enforce maximum input length limits at the API gateway and application layer. \
                  Return HTTP 400 or 413 for oversized requests.",
        },
    ]
}

fn body_contains_any(body: &str, patterns: &[&str]) -> bool {
    let lower = body.to_lowercase();
    patterns.iter().any(|p| lower.contains(p))
}

#[async_trait]
impl Check for InputValidationCheck {
    fn name(&self) -> &str {
        "input_validation"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.input_validation
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Find endpoints that have GET methods and are reachable
        let test_paths: Vec<&str> = if config.endpoints.is_empty() {
            vec!["/"]
        } else {
            config
                .endpoints
                .iter()
                .filter(|e| e.methods.iter().any(|m| m.eq_ignore_ascii_case("GET")))
                .map(|e| e.path.as_str())
                .collect()
        };

        if test_paths.is_empty() {
            findings.push(Finding {
                stig_id: "V-274715".to_string(),
                title: "No GET endpoints configured for input validation testing".to_string(),
                severity: Severity::Medium,
                status: FindingStatus::Skip,
                endpoint: None,
                evidence: None,
                fix: "Add endpoint entries with GET methods to config.yaml.".to_string(),
                details: None,
            });
            return Ok(findings);
        }

        let probe_path = test_paths[0];
        let all_probes = probes();

        for probe in &all_probes {
            let query = format!("{}={}", probe.param, urlencoding(&probe.value));
            match client.get_with_query(probe_path, &query).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // Read up to 8 KB of the body for pattern matching
                    let body_bytes = resp.bytes().await.unwrap_or_default();
                    let body = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(8192)]);

                    if body_contains_any(&body, probe.bad_patterns) {
                        findings.push(
                            Finding::fail(
                                probe.stig_id,
                                &format!("{} — vulnerable pattern detected in response", probe.name),
                                probe.severity.clone(),
                                probe.fix,
                            )
                            .with_endpoint(probe_path)
                            .with_evidence(&format!(
                                "Probe: ?{}={}\nHTTP {}\nResponse excerpt: {}",
                                probe.param,
                                &probe.value[..probe.value.len().min(40)],
                                status,
                                &body[..body.len().min(200)]
                            )),
                        );
                    } else if status == 400 || status == 422 || status == 413 {
                        findings.push(
                            Finding::pass(
                                probe.stig_id,
                                &format!("{} — input correctly rejected", probe.name),
                                probe.severity.clone(),
                                probe.fix,
                            )
                            .with_endpoint(probe_path)
                            .with_evidence(&format!("HTTP {} for malformed input", status)),
                        );
                    } else {
                        findings.push(
                            Finding::pass(
                                probe.stig_id,
                                &format!(
                                    "{} — no vulnerability pattern detected (HTTP {})",
                                    probe.name, status
                                ),
                                probe.severity.clone(),
                                probe.fix,
                            )
                            .with_endpoint(probe_path)
                            .with_details("No bad patterns found in response body"),
                        );
                    }
                }
                Err(e) => {
                    // Connection errors / timeouts are not a finding — server may have rejected
                    findings.push(Finding {
                        stig_id: probe.stig_id.to_string(),
                        title: format!("{} — probe inconclusive (request error)", probe.name),
                        severity: probe.severity.clone(),
                        status: FindingStatus::Skip,
                        endpoint: Some(probe_path.to_string()),
                        evidence: None,
                        fix: probe.fix.to_string(),
                        details: Some(e.to_string()),
                    });
                }
            }
        }

        Ok(findings)
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
