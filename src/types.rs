use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => Err(anyhow::anyhow!("Unknown severity: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Pass,
    Fail,
    Skip,
    Manual,
    NotApplicable,
    Error,
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingStatus::Pass => write!(f, "PASS"),
            FindingStatus::Fail => write!(f, "FAIL"),
            FindingStatus::Skip => write!(f, "SKIP"),
            FindingStatus::Manual => write!(f, "MANUAL"),
            FindingStatus::NotApplicable => write!(f, "N/A"),
            FindingStatus::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// DISA API SRG control ID (e.g. "V-274710")
    pub stig_id: String,
    pub title: String,
    pub severity: Severity,
    pub status: FindingStatus,
    /// The endpoint this finding applies to, if any
    pub endpoint: Option<String>,
    /// Raw evidence (response header, body excerpt, etc.)
    pub evidence: Option<String>,
    /// Recommended remediation
    pub fix: String,
    /// Additional detail about the check result
    pub details: Option<String>,
}

impl Finding {
    pub fn pass(stig_id: &str, title: &str, severity: Severity, fix: &str) -> Self {
        Self {
            stig_id: stig_id.to_string(),
            title: title.to_string(),
            severity,
            status: FindingStatus::Pass,
            endpoint: None,
            evidence: None,
            fix: fix.to_string(),
            details: None,
        }
    }

    pub fn fail(stig_id: &str, title: &str, severity: Severity, fix: &str) -> Self {
        Self {
            stig_id: stig_id.to_string(),
            title: title.to_string(),
            severity,
            status: FindingStatus::Fail,
            endpoint: None,
            evidence: None,
            fix: fix.to_string(),
            details: None,
        }
    }

    pub fn manual(stig_id: &str, title: &str, severity: Severity, fix: &str) -> Self {
        Self {
            stig_id: stig_id.to_string(),
            title: title.to_string(),
            severity,
            status: FindingStatus::Manual,
            endpoint: None,
            evidence: None,
            fix: fix.to_string(),
            details: None,
        }
    }

    pub fn with_endpoint(mut self, ep: &str) -> Self {
        self.endpoint = Some(ep.to_string());
        self
    }

    pub fn with_evidence(mut self, ev: &str) -> Self {
        self.evidence = Some(ev.to_string());
        self
    }

    pub fn with_details(mut self, d: &str) -> Self {
        self.details = Some(d.to_string());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub target: String,
    pub timestamp: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub manual: usize,
    pub skipped: usize,
}

impl ScanResult {
    pub fn new(target: String, timestamp: String, findings: Vec<Finding>) -> Self {
        let total = findings.len();
        let passed = findings.iter().filter(|f| f.status == FindingStatus::Pass).count();
        let failed = findings.iter().filter(|f| f.status == FindingStatus::Fail).count();
        let manual = findings.iter().filter(|f| f.status == FindingStatus::Manual).count();
        let skipped = findings
            .iter()
            .filter(|f| {
                f.status == FindingStatus::Skip
                    || f.status == FindingStatus::NotApplicable
                    || f.status == FindingStatus::Error
            })
            .count();
        Self { findings, target, timestamp, total, passed, failed, manual, skipped }
    }
}
