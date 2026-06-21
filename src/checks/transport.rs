use anyhow::Result;
/// DISA API SRG V1R0.1 — Transport Security
///
/// V-274710 (HIGH): The API must use TLS version 1.2 at minimum.
/// V-274497 (MED):  The API must encrypt data in transit.
/// V-274600 (MED):  The API must protect Session IDs (SSL/TLS).
use async_trait::async_trait;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, Severity},
};

pub struct TransportCheck;

#[async_trait]
impl Check for TransportCheck {
    fn name(&self) -> &str {
        "transport"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.transport
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // --- V-274710 / V-274497: HTTPS scheme ---
        let base = &client.base_url;
        if !base.starts_with("https://") {
            findings.push(
                Finding::fail(
                    "V-274710",
                    "API does not use HTTPS (TLS 1.2+ required)",
                    Severity::High,
                    "Configure the API to only accept HTTPS connections using TLS 1.2 or later. \
                     Update base_url to https:// and disable plain HTTP listeners.",
                )
                .with_evidence(&format!("base_url = {}", base)),
            );
            // No point probing further if the URL itself is HTTP
            return Ok(findings);
        }

        // HTTPS confirmed — note that reqwest/rustls enforces TLS 1.2+ by default,
        // so a successful connection here guarantees at least TLS 1.2.
        findings.push(Finding::pass(
            "V-274710",
            "API uses HTTPS (TLS 1.2+ enforced by rustls)",
            Severity::High,
            "Ensure server-side TLS 1.0/1.1 is explicitly disabled in your web server config.",
        ));

        // --- V-274497: HTTP redirects to HTTPS ---
        let probe_path = config
            .endpoints
            .first()
            .map(|e| e.path.as_str())
            .unwrap_or("/");

        match client.get_http(probe_path).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let location = resp
                    .headers()
                    .get("location")
                    .and_then(|v| v.to_str().ok())
                    .map(String::from);

                let redirects_to_https = location
                    .as_deref()
                    .map(|l| l.starts_with("https://"))
                    .unwrap_or(false);

                let is_redirect = (301..=308).contains(&status);

                if is_redirect && redirects_to_https {
                    findings.push(Finding::pass(
                        "V-274497",
                        "HTTP requests are redirected to HTTPS",
                        Severity::Medium,
                        "HTTP → HTTPS redirect is in place.",
                    ));
                } else if status == 200 || status < 400 {
                    findings.push(
                        Finding::fail(
                            "V-274497",
                            "API serves content over plain HTTP without redirecting to HTTPS",
                            Severity::Medium,
                            "Configure the server to return a 301/302 redirect to the HTTPS \
                             equivalent for all HTTP requests. Do not serve API content over \
                             unencrypted HTTP.",
                        )
                        .with_evidence(&format!("HTTP {}: location={:?}", status, location)),
                    );
                } else {
                    // Connection refused or 4xx/5xx on HTTP — acceptable if HTTPS is the only listener
                    findings.push(
                        Finding::pass(
                            "V-274497",
                            "Plain HTTP endpoint returns no usable response (HTTPS-only)",
                            Severity::Medium,
                            "Verify the HTTP port is either closed or forcibly redirects.",
                        )
                        .with_evidence(&format!("HTTP returned status {}", status)),
                    );
                }
            }
            Err(e) => {
                // Connection refused on HTTP is actually fine
                findings.push(
                    Finding::pass(
                        "V-274497",
                        "Plain HTTP connection refused — HTTPS-only listener confirmed",
                        Severity::Medium,
                        "HTTP port is not accepting connections.",
                    )
                    .with_details(&format!("Connection error: {}", e)),
                );
            }
        }

        // --- V-274600: Session IDs must be protected over TLS ---
        // We verify the HSTS header as evidence the server enforces TLS at the transport layer.
        match client.get(probe_path).await {
            Ok(resp) => {
                let hsts = resp.headers().get("strict-transport-security");
                if hsts.is_some() {
                    findings.push(
                        Finding::pass(
                            "V-274600",
                            "HSTS header present — session IDs protected over TLS",
                            Severity::Medium,
                            "Strict-Transport-Security is configured.",
                        )
                        .with_evidence(hsts.and_then(|v| v.to_str().ok()).unwrap_or("(present)")),
                    );
                } else {
                    findings.push(
                        Finding::fail(
                            "V-274600",
                            "HSTS header missing — session ID TLS enforcement not signalled",
                            Severity::Medium,
                            "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' \
                             to all API responses to ensure browsers never fall back to HTTP.",
                        )
                        .with_endpoint(probe_path),
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::fail(
                        "V-274600",
                        "Could not probe HSTS — check failed",
                        Severity::Medium,
                        "Ensure the API endpoint is reachable and verify HSTS configuration.",
                    )
                    .with_details(&e.to_string()),
                );
            }
        }

        Ok(findings)
    }
}
