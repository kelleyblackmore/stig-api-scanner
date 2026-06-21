/// DISA API SRG V1R0.1 — Authentication & Authorization
///
/// V-274507 (MED): API must use approved authorizations for access control.
/// V-274557 (MED): API must limit endpoint exposure (auth-required endpoints must reject unauthed requests).
/// V-274559 (MED): API must use approved DoD enterprise ICAM solution.
/// V-274643 (MED): Access to API privileged features must be restricted.
/// V-274672 (MED): API must require periodic reauthentication.
/// V-274679 (MED): API's internal tokens must not be provided to users.
use async_trait::async_trait;
use anyhow::Result;

use crate::{
    checks::Check,
    config::Config,
    http::HttpClient,
    types::{Finding, FindingStatus, Severity},
};

pub struct AuthCheck;

#[async_trait]
impl Check for AuthCheck {
    fn name(&self) -> &str {
        "auth"
    }

    fn is_enabled(&self, config: &Config) -> bool {
        config.checks.auth
    }

    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Skip if no auth is configured — unauthenticated test is meaningless
        if config.auth.auth_type == crate::config::AuthType::None {
            findings.push(Finding {
                stig_id: "V-274557".to_string(),
                title: "No auth configured — skipping authentication bypass checks".to_string(),
                severity: Severity::Medium,
                status: FindingStatus::Skip,
                endpoint: None,
                evidence: None,
                fix: "Configure 'auth' in config.yaml to enable authentication bypass tests."
                    .to_string(),
                details: None,
            });
            return Ok(findings);
        }

        let auth_required_paths: Vec<&str> = config
            .endpoints
            .iter()
            .filter(|e| e.auth_required)
            .map(|e| e.path.as_str())
            .collect();

        if auth_required_paths.is_empty() {
            findings.push(Finding {
                stig_id: "V-274557".to_string(),
                title: "No auth-required endpoints defined — skipping bypass checks".to_string(),
                severity: Severity::Medium,
                status: FindingStatus::Skip,
                endpoint: None,
                evidence: None,
                fix: "Add endpoints with 'auth_required: true' to config.yaml.".to_string(),
                details: None,
            });
            return Ok(findings);
        }

        // --- V-274557: Auth-required endpoints must reject unauthenticated requests ---
        for path in &auth_required_paths {
            match client.get_unauthed(path).await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 401 || status == 403 {
                        let www_auth = resp
                            .headers()
                            .get("www-authenticate")
                            .and_then(|v| v.to_str().ok())
                            .map(String::from);

                        let mut f = Finding::pass(
                            "V-274557",
                            "Unauthenticated request correctly rejected",
                            Severity::Medium,
                            "Endpoint properly enforces authentication.",
                        )
                        .with_endpoint(path)
                        .with_evidence(&format!("HTTP {}", status));

                        if let Some(auth_hdr) = www_auth {
                            f = f.with_details(&format!("WWW-Authenticate: {}", auth_hdr));
                        }
                        findings.push(f);
                    } else if (200..300).contains(&status) {
                        findings.push(
                            Finding::fail(
                                "V-274557",
                                "Auth-required endpoint is accessible without credentials",
                                Severity::High,
                                "Enforce authentication on this endpoint. Return HTTP 401 with a \
                                 WWW-Authenticate header when credentials are missing.",
                            )
                            .with_endpoint(path)
                            .with_evidence(&format!("HTTP {} (expected 401/403)", status)),
                        );
                    } else {
                        findings.push(
                            Finding::pass(
                                "V-274557",
                                "Unauthenticated request did not succeed",
                                Severity::Medium,
                                "Verify the response is intentional and not a misconfiguration.",
                            )
                            .with_endpoint(path)
                            .with_evidence(&format!("HTTP {}", status)),
                        );
                    }
                }
                Err(e) => {
                    findings.push(
                        Finding::manual(
                            "V-274557",
                            "Could not probe endpoint without auth",
                            Severity::Medium,
                            "Manually verify the endpoint rejects unauthenticated requests.",
                        )
                        .with_endpoint(path)
                        .with_details(&e.to_string()),
                    );
                }
            }
        }

        // --- V-274507: Check that the authed response differs from unauthed (basic RBAC signal) ---
        for path in &auth_required_paths {
            let authed = client.get(path).await;
            let unauthed = client.get_unauthed(path).await;
            if let (Ok(a), Ok(u)) = (authed, unauthed) {
                if a.status() == u.status() && a.status().is_success() {
                    findings.push(
                        Finding::fail(
                            "V-274507",
                            "Authed and unauthed requests return identical success responses",
                            Severity::Medium,
                            "Verify access control is enforced. The API should return different \
                             data or status codes for authenticated vs unauthenticated clients.",
                        )
                        .with_endpoint(path)
                        .with_evidence(&format!(
                            "Both authed and unauthed return HTTP {}",
                            a.status().as_u16()
                        )),
                    );
                }
            }
        }

        // --- V-274559 / V-274672 / V-274643 / V-274679: Manual review items ---
        // These controls require design-level knowledge that cannot be probed via HTTP.
        let manual_controls = [
            ("V-274559", "API must use approved DoD enterprise ICAM solution",
             "Verify the authentication system is an approved DoD ICAM solution (e.g., CAC/PIV, \
              DoD SSO). Document the authentication provider in the system security plan."),
            ("V-274672", "API must require periodic reauthentication for sensitive operations",
             "Ensure tokens expire appropriately (see V-274680) and that sensitive operations \
              require step-up authentication. Document the reauthentication policy."),
            ("V-274643", "Access to privileged API features must be restricted to authorized users",
             "Implement and test role-based access control (RBAC) for privileged endpoints. \
              Verify that regular users cannot access admin-level functionality."),
            ("V-274679", "Internal API tokens must not be exposed to end users",
             "Ensure backend service-to-service tokens are never returned in API responses \
              accessible to end users. Audit all response payloads for token leakage."),
        ];

        for (id, title, fix) in manual_controls {
            findings.push(Finding::manual(id, title, Severity::Medium, fix));
        }

        Ok(findings)
    }
}
