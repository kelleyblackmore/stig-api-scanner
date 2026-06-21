/// DISA API SRG V1R0.1 — Error Handling & Information Disclosure
///
/// V-274615 (MED): The API must not disclose sensitive data in error messages.
use async_trait::async_trait;
use anyhow::Result;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, Severity},
};

const STIG_ID: &str = "V-274615";
const FIX: &str = "Return generic error messages that do not include stack traces, internal \
                   paths, framework names, database errors, or version strings. Log detailed \
                   errors server-side with a correlation ID instead.";

/// Strings that should never appear in a production API error response.
const SENSITIVE_PATTERNS: &[&str] = &[
    // Stack traces
    "at org.",
    "at com.",
    "at java.",
    "at sun.",
    "traceback (most recent call last)",
    "stack trace",
    "exception in thread",
    "unhandled exception",
    "nativeexception",
    // Internal paths
    "/home/",
    "/var/www/",
    "/usr/local/",
    "c:\\users\\",
    "c:\\inetpub\\",
    // Framework/server disclosure
    "django",
    "flask",
    "rails",
    "laravel",
    "spring boot",
    "express.js",
    "php fatal error",
    "php warning",
    // Database errors
    "you have an error in your sql",
    "ora-",
    "pg::",
    "sqlstate[",
    "sqlite3",
    "mongodb::",
    // Version disclosure
    "php/",
    "apache/",
    "nginx/",
    "tomcat/",
];

pub struct ErrorHandlingCheck;

async fn probe_error_response(client: &HttpClient, path: &str) -> Option<(u16, String)> {
    // Try a 404 path
    let not_found_path = format!("{}/stig-scanner-nonexistent-probe-12345", path.trim_end_matches('/'));
    if let Ok(resp) = client.get_unauthed(&not_found_path).await {
        let status = resp.status().as_u16();
        let body = resp.bytes().await.unwrap_or_default();
        let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]).to_string();
        return Some((status, body_str));
    }
    None
}

#[async_trait]
impl Check for ErrorHandlingCheck {
    fn name(&self) -> &str {
        "error_handling"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.error_handling
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let probe_base = config.endpoints.first().map(|e| e.path.as_str()).unwrap_or("/");

        // --- Probe 1: 404 path ---
        if let Some((status, body)) = probe_error_response(client, probe_base).await {
            let lower = body.to_lowercase();
            let leaks: Vec<&str> = SENSITIVE_PATTERNS
                .iter()
                .filter(|&&p| lower.contains(p))
                .copied()
                .collect();

            if leaks.is_empty() {
                findings.push(
                    Finding::pass(
                        STIG_ID,
                        "Error response does not contain sensitive information",
                        Severity::Medium,
                        FIX,
                    )
                    .with_endpoint(probe_base)
                    .with_evidence(&format!("HTTP {} — no sensitive patterns found", status)),
                );
            } else {
                let evidence = format!(
                    "HTTP {}\nSensitive patterns found: {}\nBody excerpt: {}",
                    status,
                    leaks.join(", "),
                    &body[..body.len().min(300)]
                );
                findings.push(
                    Finding::fail(
                        STIG_ID,
                        "Error response leaks sensitive internal information",
                        Severity::Medium,
                        FIX,
                    )
                    .with_endpoint(probe_base)
                    .with_evidence(&evidence),
                );
            }
        } else {
            findings.push(
                Finding::manual(
                    STIG_ID,
                    "Could not probe error responses — manual review required",
                    Severity::Medium,
                    FIX,
                )
                .with_endpoint(probe_base)
                .with_details("Endpoint unreachable or returned no error response"),
            );
        }

        // --- Probe 2: Malformed JSON body on POST endpoints ---
        for ep in config.endpoints.iter().filter(|e| {
            e.methods.iter().any(|m| m.eq_ignore_ascii_case("POST"))
        }) {
            let malformed = serde_json::json!({"__stig_probe": null, "': DROP TABLE": 1});
            if let Ok(resp) = client.post_json(&ep.path, &malformed).await {
                let status = resp.status().as_u16();
                let body = resp.bytes().await.unwrap_or_default();
                let body_str = String::from_utf8_lossy(&body[..body.len().min(4096)]);
                let lower = body_str.to_lowercase();
                let leaks: Vec<&str> = SENSITIVE_PATTERNS
                    .iter()
                    .filter(|&&p| lower.contains(p))
                    .copied()
                    .collect();
                if !leaks.is_empty() {
                    findings.push(
                        Finding::fail(
                            STIG_ID,
                            "POST endpoint error response leaks sensitive information",
                            Severity::Medium,
                            FIX,
                        )
                        .with_endpoint(&ep.path)
                        .with_evidence(&format!(
                            "HTTP {} — leaked patterns: {}",
                            status,
                            leaks.join(", ")
                        )),
                    );
                }
            }
        }

        Ok(findings)
    }
}
