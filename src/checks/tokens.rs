use anyhow::Result;
/// DISA API SRG V1R0.1 — Token & Session Management
///
/// V-274678 (MED): API must configure tokens for stateless authentication (expiry + vault storage).
/// V-274680 (MED): API access tokens must expire within 30 minutes.
/// V-274681 (MED): API refresh tokens must expire within 90 days.
/// V-274712 (MED): API must audience-restrict access tokens.
/// V-274603 (MED): API keys must be securely generated using FIPS-validated RNG.
/// V-274606 (MED): API implementation must use FIPS-validated encryption/hashing for keys.
/// V-274783 (MED): API must use FIPS-validated cryptography for token signatures.
use async_trait::async_trait;
use base64::Engine as _;

use crate::{
    checks::Check,
    config::{AuthType, Config},
    http::HttpClient,
    types::{Finding, Severity},
};

pub struct TokensCheck;

/// Minimally decode a JWT to inspect its claims (no signature validation needed here —
/// we are checking policy fields, not authenticity).
fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    // JWT uses base64url without padding
    let payload = parts[1];
    let padded = match payload.len() % 4 {
        2 => format!("{}==", payload),
        3 => format!("{}=", payload),
        _ => payload.to_string(),
    };
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn seconds_to_human(secs: i64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[async_trait]
impl Check for TokensCheck {
    fn name(&self) -> &str {
        "tokens"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.tokens
    }

    async fn run(&self, _client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // --- JWT inspection (only when a bearer token is configured) ---
        if config.auth.auth_type == AuthType::Bearer {
            if let Some(token) = &config.auth.bearer_token {
                if let Some(claims) = decode_jwt_payload(token) {
                    // V-274680: exp claim must be ≤ 30 minutes from iat
                    let iat = claims.get("iat").and_then(|v| v.as_i64());
                    let exp = claims.get("exp").and_then(|v| v.as_i64());

                    if let (Some(iat), Some(exp)) = (iat, exp) {
                        let lifetime_secs = exp - iat;
                        let max_secs: i64 = 30 * 60; // 30 minutes
                        if lifetime_secs <= max_secs {
                            findings.push(
                                Finding::pass(
                                    "V-274680",
                                    "Access token lifetime is within 30 minutes",
                                    Severity::Medium,
                                    "Token lifetime policy is correctly configured.",
                                )
                                .with_evidence(&format!(
                                    "exp - iat = {} ({})",
                                    lifetime_secs,
                                    seconds_to_human(lifetime_secs)
                                )),
                            );
                        } else {
                            findings.push(
                                Finding::fail(
                                    "V-274680",
                                    "Access token lifetime exceeds 30 minutes",
                                    Severity::Medium,
                                    "Configure access tokens to expire within 30 minutes (1800s). \
                                     Use refresh tokens for longer sessions.",
                                )
                                .with_evidence(&format!(
                                    "exp - iat = {} ({})",
                                    lifetime_secs,
                                    seconds_to_human(lifetime_secs)
                                )),
                            );
                        }
                    } else {
                        findings.push(
                            Finding::fail(
                                "V-274680",
                                "JWT is missing iat or exp claims — no expiry enforced",
                                Severity::Medium,
                                "Ensure all issued JWTs contain 'iat' and 'exp' claims. \
                                 The access token must expire within 30 minutes.",
                            )
                            .with_evidence("No iat/exp found in JWT payload"),
                        );
                    }

                    // V-274712: aud claim must be present
                    if claims.get("aud").is_some() {
                        findings.push(Finding::pass(
                            "V-274712",
                            "JWT contains audience (aud) claim — token is audience-restricted",
                            Severity::Medium,
                            "Validate the 'aud' claim on every token verification.",
                        ));
                    } else {
                        findings.push(
                            Finding::fail(
                                "V-274712",
                                "JWT is missing audience (aud) claim",
                                Severity::Medium,
                                "Add an 'aud' claim to all issued tokens specifying the intended \
                                 recipient service(s). Reject tokens whose 'aud' doesn't match.",
                            )
                            .with_evidence("No 'aud' field in JWT payload"),
                        );
                    }

                    // V-274678: Ensure alg is not 'none'
                    let header_alg = {
                        let raw_header = token.split('.').next().unwrap_or("");
                        let padded = match raw_header.len() % 4 {
                            2 => format!("{}==", raw_header),
                            3 => format!("{}=", raw_header),
                            _ => raw_header.to_string(),
                        };
                        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode(raw_header)
                            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&padded))
                            .ok();
                        decoded
                            .as_deref()
                            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                            .and_then(|v| v.get("alg").and_then(|a| a.as_str()).map(String::from))
                    };

                    match header_alg.as_deref() {
                        Some("none") | Some("None") | Some("NONE") => {
                            findings.push(
                                Finding::fail(
                                    "V-274678",
                                    "JWT uses 'alg: none' — unsigned tokens accepted",
                                    Severity::High,
                                    "Never issue or accept tokens with alg=none. Use RS256, \
                                     ES256, or another FIPS-approved algorithm.",
                                )
                                .with_evidence("JWT header alg: none"),
                            );
                        }
                        Some(alg) => {
                            let is_fips = matches!(
                                alg,
                                "RS256"
                                    | "RS384"
                                    | "RS512"
                                    | "ES256"
                                    | "ES384"
                                    | "ES512"
                                    | "PS256"
                                    | "PS384"
                                    | "PS512"
                            );
                            if is_fips {
                                findings.push(
                                    Finding::pass(
                                        "V-274783",
                                        "JWT uses a FIPS-approved signing algorithm",
                                        Severity::Medium,
                                        "Continue using approved algorithms for token signatures.",
                                    )
                                    .with_evidence(&format!("alg: {}", alg)),
                                );
                            } else {
                                findings.push(
                                    Finding::fail(
                                        "V-274783",
                                        "JWT uses a non-FIPS-approved signing algorithm",
                                        Severity::Medium,
                                        "Use RS256, RS384, ES256, ES384, or another FIPS 140-3 \
                                         validated algorithm for token signatures.",
                                    )
                                    .with_evidence(&format!("alg: {}", alg)),
                                );
                            }
                        }
                        None => {
                            findings.push(Finding::manual(
                                "V-274783",
                                "Could not determine JWT signing algorithm",
                                Severity::Medium,
                                "Verify the JWT signing algorithm is FIPS 140-3 validated \
                                 (e.g., RS256, ES256).",
                            ));
                        }
                    }
                } else {
                    // Token present but not a JWT — could be an opaque token
                    findings.push(
                        Finding::manual(
                            "V-274680",
                            "Bearer token is opaque (not a JWT) — expiry cannot be inspected",
                            Severity::Medium,
                            "Ensure the token server enforces a maximum lifetime of 30 minutes \
                             for access tokens and validate this in your token endpoint tests.",
                        )
                        .with_details("Token did not decode as a valid JWT"),
                    );
                }
            }
        }

        // --- Manual controls that require architecture review ---
        let manual_controls = [
            (
                "V-274678",
                "Token secrets must be stored in a vault, not hard-coded",
                "Store all signing keys and secrets in an approved secrets manager (e.g., \
                 HashiCorp Vault, AWS Secrets Manager). Never embed secrets in source code.",
            ),
            (
                "V-274681",
                "Refresh tokens must expire within 90 days",
                "Configure refresh token TTL to ≤ 7776000 seconds (90 days). Rotate refresh \
                 tokens on each use and invalidate them on logout.",
            ),
            (
                "V-274603",
                "API keys must be generated using a FIPS-validated RNG",
                "Generate API keys using a FIPS 140-3 approved random number generator. \
                 Minimum recommended entropy: 128 bits.",
            ),
            (
                "V-274606",
                "API key confidentiality and integrity must be protected at rest",
                "Store API keys hashed (HMAC-SHA-256 or bcrypt) in the database, never in \
                 plaintext. Use FIPS-validated encryption for any stored credentials.",
            ),
        ];

        for (id, title, fix) in manual_controls {
            findings.push(Finding::manual(id, title, Severity::Medium, fix));
        }

        Ok(findings)
    }
}
