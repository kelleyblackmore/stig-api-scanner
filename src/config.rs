use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub target: TargetConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    #[serde(default)]
    pub checks: ChecksConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub pipeline: PipelineConfig,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Reading config: {}", path.display()))?;
        let expanded = expand_env_vars(&raw);
        serde_yaml::from_str(&expanded).with_context(|| "Parsing YAML config")
    }
}

/// Replace ${VAR_NAME} placeholders with environment variable values.
fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_string();
    loop {
        let Some(start) = result.find("${") else {
            break;
        };
        let Some(end_offset) = result[start..].find('}') else {
            break;
        };
        let var_name = result[start + 2..start + end_offset].to_string();
        let value = env::var(&var_name).unwrap_or_default();
        result = format!(
            "{}{}{}",
            &result[..start],
            value,
            &result[start + end_offset + 1..]
        );
    }
    result
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub base_url: String,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

fn default_timeout() -> u64 {
    30
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AuthConfig {
    #[serde(rename = "type", default)]
    pub auth_type: AuthType,
    pub bearer_token: Option<String>,
    pub api_key_header: Option<String>,
    pub api_key: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    #[default]
    None,
    Bearer,
    ApiKey,
    Basic,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndpointConfig {
    pub path: String,
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    #[serde(default = "default_true")]
    pub auth_required: bool,
    #[serde(default)]
    #[allow(dead_code)]
    pub tags: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub skip_checks: Vec<String>,
    /// POST body to use when testing this endpoint (JSON string)
    #[allow(dead_code)]
    pub body: Option<serde_json::Value>,
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChecksConfig {
    #[serde(default = "default_true")]
    pub transport: bool,
    #[serde(default = "default_true")]
    pub cors: bool,
    #[serde(default = "default_true")]
    pub auth: bool,
    #[serde(default = "default_true")]
    pub tokens: bool,
    #[serde(default = "default_true")]
    pub rate_limiting: bool,
    #[serde(default = "default_true")]
    pub input_validation: bool,
    #[serde(default = "default_true")]
    pub error_handling: bool,
    #[serde(default = "default_true")]
    pub cache: bool,
    #[serde(default = "default_true")]
    pub headers: bool,
    /// Explicit list of allowed CORS origins. Empty = flag any ACAO header value.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Number of rapid requests to send for rate-limit probing. 0 = disabled.
    #[serde(default)]
    pub rate_limit_probe_count: u32,
}

impl Default for ChecksConfig {
    fn default() -> Self {
        Self {
            transport: true,
            cors: true,
            auth: true,
            tokens: true,
            rate_limiting: true,
            input_validation: true,
            error_handling: true,
            cache: true,
            headers: true,
            allowed_origins: vec![],
            rate_limit_probe_count: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_format")]
    pub format: String,
    pub output_file: Option<String>,
    #[serde(default)]
    pub include_passed: bool,
    #[serde(default)]
    pub verbose: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: "text".to_string(),
            output_file: None,
            include_passed: false,
            verbose: false,
        }
    }
}

fn default_format() -> String {
    "text".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    /// Minimum severity level that causes a non-zero exit. Default: high.
    #[serde(default = "default_fail_severity")]
    pub fail_severity: String,
    #[serde(default = "default_exit_code")]
    pub exit_code_on_fail: i32,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            fail_severity: "high".to_string(),
            exit_code_on_fail: 1,
        }
    }
}

fn default_fail_severity() -> String {
    "high".to_string()
}
fn default_exit_code() -> i32 {
    1
}
