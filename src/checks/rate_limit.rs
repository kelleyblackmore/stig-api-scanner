use anyhow::Result;
/// DISA API SRG V1R0.1 — Rate Limiting & Throttling
///
/// V-274612 (MED): The API must employ throttling.
/// V-274525 (MED): The API must audit rate-limiting events.
/// V-274526 (MED): The API Gateway must audit rate-limiting events.
/// V-274682 (MED): API keys must have rate limits configured.
use async_trait::async_trait;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, FindingStatus, Severity},
};

const RATE_LIMIT_HEADERS: &[&str] = &[
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "retry-after",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
];

pub struct RateLimitCheck;

#[async_trait]
impl Check for RateLimitCheck {
    fn name(&self) -> &str {
        "rate_limit"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.rate_limiting
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let probe_path = config
            .endpoints
            .first()
            .map(|e| e.path.as_str())
            .unwrap_or("/");

        // --- V-274612 / V-274682: Check for rate-limit response headers ---
        match client.get(probe_path).await {
            Ok(resp) => {
                let found_headers: Vec<(&str, String)> = RATE_LIMIT_HEADERS
                    .iter()
                    .filter_map(|&h| {
                        resp.headers()
                            .get(h)
                            .and_then(|v| v.to_str().ok())
                            .map(|v| (h, v.to_string()))
                    })
                    .collect();

                if found_headers.is_empty() {
                    findings.push(
                        Finding::fail(
                            "V-274612",
                            "No rate-limiting headers present in API response",
                            Severity::Medium,
                            "Implement throttling at the API gateway and include \
                             X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset \
                             headers (or the RFC 6585 RateLimit-* equivalents) in responses.",
                        )
                        .with_endpoint(probe_path)
                        .with_details(
                            "Checked for: x-ratelimit-limit, x-ratelimit-remaining, \
                             ratelimit-limit, retry-after and variants — none found",
                        ),
                    );
                } else {
                    let evidence = found_headers
                        .iter()
                        .map(|(h, v)| format!("{}: {}", h, v))
                        .collect::<Vec<_>>()
                        .join(", ");
                    findings.push(
                        Finding::pass(
                            "V-274612",
                            "Rate-limiting headers present in API response",
                            Severity::Medium,
                            "Ensure rate limits are enforced server-side, not just signalled.",
                        )
                        .with_endpoint(probe_path)
                        .with_evidence(&evidence),
                    );
                }
            }
            Err(e) => {
                findings.push(
                    Finding::manual(
                        "V-274612",
                        "Could not probe endpoint for rate-limit headers",
                        Severity::Medium,
                        "Manually verify that the API enforces throttling and returns \
                         rate-limit headers in responses.",
                    )
                    .with_endpoint(probe_path)
                    .with_details(&e.to_string()),
                );
            }
        }

        // --- Active probe: send N rapid requests and check for 429 ---
        let probe_count = config.checks.rate_limit_probe_count;
        if probe_count > 0 {
            let results = client.rapid_requests(probe_path, probe_count).await;
            let got_429 = results.iter().any(|r| matches!(r, Ok(429)));
            let got_503 = results.iter().any(|r| matches!(r, Ok(503)));
            let errors = results.iter().filter(|r| r.is_err()).count();

            if got_429 || got_503 {
                findings.push(
                    Finding::pass(
                        "V-274682",
                        "API enforces rate limiting — returned 429/503 under rapid requests",
                        Severity::Medium,
                        "Rate limiting is active. Ensure limits are appropriate for each API key.",
                    )
                    .with_endpoint(probe_path)
                    .with_evidence(&format!(
                        "{} requests sent; got_429={} got_503={} errors={}",
                        probe_count, got_429, got_503, errors
                    )),
                );
            } else {
                findings.push(
                    Finding::fail(
                        "V-274682",
                        "API did not enforce rate limiting under rapid sequential requests",
                        Severity::Medium,
                        "Configure rate limits per API key. Return HTTP 429 with a \
                         Retry-After header when limits are exceeded.",
                    )
                    .with_endpoint(probe_path)
                    .with_evidence(&format!(
                        "{} requests sent; no 429/503 received (errors: {})",
                        probe_count, errors
                    )),
                );
            }
        } else {
            findings.push(Finding {
                stig_id: "V-274682".to_string(),
                title: "Active rate-limit probe disabled (rate_limit_probe_count: 0)".to_string(),
                severity: Severity::Medium,
                status: FindingStatus::Skip,
                endpoint: Some(probe_path.to_string()),
                evidence: None,
                fix: "Set 'checks.rate_limit_probe_count' to a non-zero value to enable \
                      active rate-limit probing."
                    .to_string(),
                details: None,
            });
        }

        // --- Manual controls ---
        let manual_controls = [
            (
                "V-274525",
                "API must generate audit records for rate-limiting events",
                "Verify that the API logs every rate-limit event with: timestamp, client \
                 identifier, endpoint, request count, and limit threshold.",
            ),
            (
                "V-274526",
                "API Gateway must audit rate-limiting events",
                "Verify gateway logs capture rate-limit events with threshold information \
                 for forensic and compliance purposes.",
            ),
        ];

        for (id, title, fix) in manual_controls {
            findings.push(Finding::manual(id, title, Severity::Medium, fix));
        }

        Ok(findings)
    }
}
