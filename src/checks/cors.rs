/// DISA API SRG V1R0.1 — CORS Policy
///
/// V-274613 (MED): The API must specify allowed origins when using CORS.
///   Access-Control-Allow-Origin must not be a wildcard (*) unless the API is
///   intentionally public and does not use cookies or credentials.
use async_trait::async_trait;
use anyhow::Result;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, Severity},
};

const STIG_ID: &str = "V-274613";
const FIX: &str = "Configure CORS to use an explicit allowlist of approved origins rather than \
                   a wildcard. Never combine 'Access-Control-Allow-Origin: *' with \
                   'Access-Control-Allow-Credentials: true'.";

pub struct CorsCheck;

#[async_trait]
impl Check for CorsCheck {
    fn name(&self) -> &str {
        "cors"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.cors
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let paths: Vec<&str> = if config.endpoints.is_empty() {
            vec!["/"]
        } else {
            config.endpoints.iter().map(|e| e.path.as_str()).collect()
        };

        // We probe with a synthetic foreign origin to trigger CORS headers.
        let probe_origin = "https://evil.example.com";
        let allowed_origins = &config.checks.allowed_origins;

        let mut seen = std::collections::HashSet::new();
        for path in paths {
            if !seen.insert(path) {
                continue;
            }

            match client.options_preflight(path, probe_origin).await {
                Ok(resp) => {
                    let acao = resp
                        .headers()
                        .get("access-control-allow-origin")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);

                    let acac = resp
                        .headers()
                        .get("access-control-allow-credentials")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.to_lowercase() == "true")
                        .unwrap_or(false);

                    match acao.as_deref() {
                        None => {
                            // No CORS headers at all — either not a CORS API or correctly restricted.
                            findings.push(
                                Finding::pass(
                                    STIG_ID,
                                    "No CORS headers returned for untrusted origin",
                                    Severity::Medium,
                                    FIX,
                                )
                                .with_endpoint(path)
                                .with_details("No Access-Control-Allow-Origin header in response"),
                            );
                        }
                        Some("*") => {
                            if acac {
                                // Wildcard + credentials is a protocol-level error AND a security risk
                                findings.push(
                                    Finding::fail(
                                        STIG_ID,
                                        "CORS wildcard combined with Allow-Credentials: true",
                                        Severity::High,
                                        "Remove the wildcard or remove Allow-Credentials. Browsers \
                                         reject this combination, but it signals a misconfiguration.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence("ACAO: * + ACAC: true"),
                                );
                            } else {
                                // Wildcard without credentials is only acceptable for public APIs
                                findings.push(
                                    Finding::fail(
                                        STIG_ID,
                                        "CORS allows any origin (*) — may expose sensitive data",
                                        Severity::Medium,
                                        FIX,
                                    )
                                    .with_endpoint(path)
                                    .with_evidence("Access-Control-Allow-Origin: *"),
                                );
                            }
                        }
                        Some(origin) => {
                            // Specific origin reflected — check if it's in the allowlist
                            if origin == probe_origin {
                                // The server reflected our evil origin back
                                findings.push(
                                    Finding::fail(
                                        STIG_ID,
                                        "CORS reflects arbitrary origin without allowlist validation",
                                        Severity::High,
                                        "Validate the Origin header against an explicit allowlist \
                                         before echoing it in Access-Control-Allow-Origin.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(&format!("ACAO: {}", origin)),
                                );
                            } else if allowed_origins.is_empty()
                                || allowed_origins.iter().any(|a| a == origin)
                            {
                                findings.push(
                                    Finding::pass(
                                        STIG_ID,
                                        "CORS origin is explicitly specified",
                                        Severity::Medium,
                                        FIX,
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(&format!("ACAO: {}", origin)),
                                );
                            } else {
                                findings.push(
                                    Finding::fail(
                                        STIG_ID,
                                        "CORS returns an origin not in the configured allowlist",
                                        Severity::Medium,
                                        FIX,
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(&format!(
                                        "ACAO: {} (not in allowed_origins)",
                                        origin
                                    )),
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    findings.push(
                        Finding::manual(
                            STIG_ID,
                            "CORS check could not complete — manual review required",
                            Severity::Medium,
                            FIX,
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
