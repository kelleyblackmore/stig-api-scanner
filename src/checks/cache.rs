use anyhow::Result;
/// DISA API SRG V1R0.1 — Cache Security
///
/// V-274607 (HIGH): The API must encrypt sensitive cached data.
/// V-274677 (MED):  The API must have a cache invalidation mechanism for policy data.
/// V-274709 (HIGH): The amount of data returned by the API must be restricted
///                  (pagination / field filtering).
use async_trait::async_trait;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, Severity},
};

pub struct CacheCheck;

#[async_trait]
impl Check for CacheCheck {
    fn name(&self) -> &str {
        "cache"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.cache
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let paths: Vec<&str> = if config.endpoints.is_empty() {
            vec!["/"]
        } else {
            config.endpoints.iter().map(|e| e.path.as_str()).collect()
        };

        let mut seen = std::collections::HashSet::new();
        for path in &paths {
            if !seen.insert(*path) {
                continue;
            }

            match client.get(path).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let headers = resp.headers().clone();

                    // --- V-274607: Cache-Control must prevent caching of sensitive data ---
                    let cache_control = headers
                        .get("cache-control")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_lowercase());

                    match cache_control.as_deref() {
                        Some(cc) => {
                            let no_store = cc.contains("no-store");
                            let no_cache = cc.contains("no-cache");
                            let private = cc.contains("private");

                            if no_store {
                                findings.push(
                                    Finding::pass(
                                        "V-274607",
                                        "Cache-Control: no-store prevents caching of sensitive data",
                                        Severity::High,
                                        "Cache-Control: no-store is set — sensitive data will not \
                                         be stored by intermediate caches.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(cc),
                                );
                            } else if no_cache || private {
                                findings.push(
                                    Finding::pass(
                                        "V-274607",
                                        "Cache-Control restricts caching (no-cache or private)",
                                        Severity::High,
                                        "Consider upgrading to 'no-store' for endpoints that \
                                         return sensitive data to prevent any disk caching.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(cc),
                                );
                            } else if cc.contains("public") || cc.contains("max-age") {
                                findings.push(
                                    Finding::fail(
                                        "V-274607",
                                        "Cache-Control allows caching — sensitive data may persist \
                                         in intermediate caches",
                                        Severity::High,
                                        "For endpoints returning sensitive or user-specific data, \
                                         set 'Cache-Control: no-store, private'. For public \
                                         endpoints, use 'private' if the response is user-specific.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(cc),
                                );
                            } else {
                                findings.push(
                                    Finding::manual(
                                        "V-274607",
                                        "Cache-Control header present but intent unclear",
                                        Severity::High,
                                        "Verify the Cache-Control policy is appropriate for the \
                                         sensitivity of the data returned by this endpoint.",
                                    )
                                    .with_endpoint(path)
                                    .with_evidence(cc),
                                );
                            }
                        }
                        None => {
                            findings.push(
                                Finding::fail(
                                    "V-274607",
                                    "No Cache-Control header — responses may be cached by proxies",
                                    Severity::High,
                                    "Add 'Cache-Control: no-store, private' to responses that \
                                     contain sensitive or user-specific data.",
                                )
                                .with_endpoint(path),
                            );
                        }
                    }

                    // --- V-274709: Check for pagination indicators in large list responses ---
                    let content_type = headers
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    if content_type.contains("json") && status == 200 {
                        // Check if pagination headers or meta are present
                        let has_pagination_header = [
                            "link",
                            "x-total-count",
                            "x-page",
                            "x-per-page",
                            "x-next-page",
                        ]
                        .iter()
                        .any(|&h| headers.contains_key(h));

                        if has_pagination_header {
                            findings.push(
                                Finding::pass(
                                    "V-274709",
                                    "API returns pagination headers — data volume is restricted",
                                    Severity::High,
                                    "Pagination is implemented. Verify there is also a maximum \
                                     page size limit enforced server-side.",
                                )
                                .with_endpoint(path),
                            );
                        } else {
                            // We can't easily distinguish "this is not a list endpoint" vs
                            // "this list has no pagination", so mark as manual.
                            findings.push(
                                Finding::manual(
                                    "V-274709",
                                    "No pagination headers detected — verify data volume is restricted",
                                    Severity::High,
                                    "Implement cursor-based or page-number pagination. Enforce a \
                                     maximum page size (e.g., 100 records). Return total count in \
                                     headers (X-Total-Count) or response body metadata.",
                                )
                                .with_endpoint(path)
                                .with_details(
                                    "If this is not a list endpoint, mark this check N/A in your \
                                     attestation manifest.",
                                ),
                            );
                        }
                    }

                    // --- V-274677: Cache invalidation (Pragma / ETag / Expires) ---
                    let has_etag = headers.contains_key("etag");
                    let has_expires = headers.contains_key("expires");
                    let pragma = headers
                        .get("pragma")
                        .and_then(|v| v.to_str().ok())
                        .map(String::from);

                    if has_etag || has_expires || pragma.as_deref() == Some("no-cache") {
                        findings.push(
                            Finding::pass(
                                "V-274677",
                                "Cache invalidation mechanism present (ETag/Expires/Pragma)",
                                Severity::Medium,
                                "Ensure cached policy/token data is invalidated on policy change.",
                            )
                            .with_endpoint(path),
                        );
                    } else {
                        findings.push(
                            Finding::manual(
                                "V-274677",
                                "No explicit cache invalidation signal detected",
                                Severity::Medium,
                                "Implement cache invalidation for policy and authorization data. \
                                 Use short TTLs, ETags, or push-based invalidation to ensure \
                                 revoked permissions take effect promptly.",
                            )
                            .with_endpoint(path),
                        );
                    }
                }
                Err(e) => {
                    findings.push(
                        Finding::manual(
                            "V-274607",
                            "Could not probe endpoint for cache headers",
                            Severity::High,
                            "Manually verify Cache-Control headers on all API responses.",
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
