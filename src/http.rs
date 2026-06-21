use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION},
    Client as ReqwestClient, Method, Response,
};
use std::{str::FromStr, time::Duration};
use url::Url;

use crate::config::{AuthConfig, AuthType, TargetConfig};

pub struct HttpClient {
    /// Client pre-configured with auth headers
    authed: ReqwestClient,
    /// Bare client — no auth, no redirects
    unauthed: ReqwestClient,
    /// Trimmed base URL (no trailing slash)
    pub base_url: String,
}

impl HttpClient {
    pub fn new(target: &TargetConfig, auth: &AuthConfig) -> Result<Self> {
        let timeout = Duration::from_secs(target.timeout_seconds);

        let mut auth_headers = HeaderMap::new();
        match auth.auth_type {
            AuthType::Bearer => {
                if let Some(tok) = &auth.bearer_token {
                    auth_headers.insert(
                        AUTHORIZATION,
                        HeaderValue::from_str(&format!("Bearer {}", tok))
                            .context("Invalid bearer token characters")?,
                    );
                }
            }
            AuthType::ApiKey => {
                if let (Some(h), Some(v)) = (&auth.api_key_header, &auth.api_key) {
                    auth_headers.insert(
                        HeaderName::from_str(h).context("Invalid API key header name")?,
                        HeaderValue::from_str(v).context("Invalid API key value")?,
                    );
                }
            }
            AuthType::Basic => {
                if let (Some(u), Some(p)) = (&auth.username, &auth.password) {
                    let encoded = STANDARD.encode(format!("{}:{}", u, p));
                    auth_headers.insert(
                        AUTHORIZATION,
                        HeaderValue::from_str(&format!("Basic {}", encoded))?,
                    );
                }
            }
            AuthType::None => {}
        }

        for (k, v) in &target.extra_headers {
            auth_headers.insert(
                HeaderName::from_str(k).context("Invalid extra header name")?,
                HeaderValue::from_str(v).context("Invalid extra header value")?,
            );
        }

        let authed = ReqwestClient::builder()
            .timeout(timeout)
            .default_headers(auth_headers)
            .danger_accept_invalid_certs(!target.verify_tls)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let unauthed = ReqwestClient::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(!target.verify_tls)
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        Ok(Self {
            authed,
            unauthed,
            base_url: target.base_url.trim_end_matches('/').to_string(),
        })
    }

    pub fn full_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Build an HTTP (non-TLS) variant of the same URL for redirect probing.
    pub fn http_url(&self, path: &str) -> Result<String> {
        let url_str = self.full_url(path);
        let mut parsed = Url::parse(&url_str)?;
        parsed
            .set_scheme("http")
            .map_err(|_| anyhow::anyhow!("Cannot set scheme to http"))?;
        Ok(parsed.to_string())
    }

    /// GET with configured auth.
    pub async fn get(&self, path: &str) -> Result<Response> {
        Ok(self.authed.get(self.full_url(path)).send().await?)
    }

    /// GET without any auth credentials.
    pub async fn get_unauthed(&self, path: &str) -> Result<Response> {
        Ok(self.unauthed.get(self.full_url(path)).send().await?)
    }

    /// GET over plain HTTP (for redirect checks).
    pub async fn get_http(&self, path: &str) -> Result<Response> {
        Ok(self.unauthed.get(self.http_url(path)?).send().await?)
    }

    /// OPTIONS preflight with a synthetic Origin header.
    pub async fn options_preflight(&self, path: &str, origin: &str) -> Result<Response> {
        Ok(self
            .unauthed
            .request(Method::OPTIONS, self.full_url(path))
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization")
            .send()
            .await?)
    }

    /// GET with a custom query string appended (for injection probes).
    pub async fn get_with_query(&self, path: &str, query: &str) -> Result<Response> {
        let url = format!("{}{}?{}", self.base_url, path, query);
        Ok(self.authed.get(url).send().await?)
    }

    /// POST JSON body with auth.
    pub async fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<Response> {
        Ok(self
            .authed
            .post(self.full_url(path))
            .json(body)
            .send()
            .await?)
    }

    /// Send N rapid sequential requests to the same endpoint (rate-limit probing).
    pub async fn rapid_requests(&self, path: &str, n: u32) -> Vec<Result<u16>> {
        let mut results = Vec::with_capacity(n as usize);
        for _ in 0..n {
            let status = self.get(path).await.map(|r| r.status().as_u16());
            results.push(status);
        }
        results
    }
}
