use anyhow::Result;
use colored::Colorize;
use std::io::Write;

use crate::{
    config::Config,
    types::{Finding, FindingStatus, ScanResult, Severity},
};

pub struct Reporter<'a> {
    config: &'a Config,
}

impl<'a> Reporter<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    pub fn report(&self, result: &ScanResult) -> Result<()> {
        let output: Box<dyn Write> = match &self.config.report.output_file {
            Some(path) => Box::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)?,
            ),
            None => Box::new(std::io::stdout()),
        };

        match self.config.report.format.as_str() {
            "json" => self.report_json(output, result),
            "sarif" => self.report_sarif(output, result),
            "junit" => self.report_junit(output, result),
            _ => self.report_text(output, result),
        }
    }

    // ── TEXT ─────────────────────────────────────────────────────────────────

    fn report_text(&self, mut out: Box<dyn Write>, result: &ScanResult) -> Result<()> {
        writeln!(
            out,
            "\n{}",
            "══════════════════════════════════════════════════════════════".cyan()
        )?;
        writeln!(out, "  {} — DISA API SRG V1R0.1", "STIG API SCANNER".bold())?;
        writeln!(out, "  Target   : {}", result.target.cyan())?;
        writeln!(out, "  Timestamp: {}", result.timestamp)?;
        writeln!(
            out,
            "{}",
            "══════════════════════════════════════════════════════════════".cyan()
        )?;

        let show_all = self.config.report.include_passed;
        let mut displayed = 0;

        for f in &result.findings {
            if !show_all && f.status == FindingStatus::Pass {
                continue;
            }
            self.print_finding(&mut out, f)?;
            displayed += 1;
        }

        if displayed == 0 {
            writeln!(out, "\n  {} No findings to display.", "✓".green())?;
        }

        // Summary
        writeln!(
            out,
            "\n{}",
            "──────────────────────────────────────────────────────────────".dimmed()
        )?;
        writeln!(out, "  SUMMARY")?;
        writeln!(out, "    Total   : {}", result.total.to_string().bold())?;
        writeln!(
            out,
            "    {}",
            format!("Failed  : {}", result.failed).red().bold()
        )?;
        writeln!(
            out,
            "    {}",
            format!("Passed  : {}", result.passed).green()
        )?;
        writeln!(
            out,
            "    {}",
            format!("Manual  : {}", result.manual).yellow()
        )?;
        writeln!(
            out,
            "    {}",
            format!("Skipped : {}", result.skipped).dimmed()
        )?;
        writeln!(
            out,
            "{}",
            "──────────────────────────────────────────────────────────────".dimmed()
        )?;

        if result.failed > 0 {
            writeln!(
                out,
                "\n  {} {} finding(s) require remediation.",
                "✗".red(),
                result.failed.to_string().red().bold()
            )?;
        } else {
            writeln!(out, "\n  {} All automated checks passed.", "✓".green())?;
        }

        if result.manual > 0 {
            writeln!(
                out,
                "  {} {} finding(s) require manual review.",
                "⚠".yellow(),
                result.manual.to_string().yellow().bold()
            )?;
        }

        writeln!(out)?;
        Ok(())
    }

    fn print_finding(&self, out: &mut Box<dyn Write>, f: &Finding) -> Result<()> {
        let status_str = match f.status {
            FindingStatus::Pass => format!("{}", "PASS".green().bold()),
            FindingStatus::Fail => format!("{}", "FAIL".red().bold()),
            FindingStatus::Manual => format!("{}", "MANUAL".yellow().bold()),
            FindingStatus::Skip => format!("{}", "SKIP".dimmed()),
            FindingStatus::NotApplicable => format!("{}", "N/A".dimmed()),
            FindingStatus::Error => format!("{}", "ERROR".magenta().bold()),
        };

        let sev_str = match f.severity {
            Severity::Critical => format!("{}", "CRITICAL".red().on_red().bold()),
            Severity::High => format!("{}", "HIGH".red().bold()),
            Severity::Medium => format!("{}", "MEDIUM".yellow()),
            Severity::Low => format!("{}", "LOW".blue()),
            Severity::Info => format!("{}", "INFO".dimmed()),
        };

        writeln!(out)?;
        writeln!(
            out,
            "  [{status_str}] [{sev_str}] {} — {}",
            f.stig_id.bold(),
            f.title
        )?;

        if let Some(ep) = &f.endpoint {
            writeln!(out, "         Endpoint : {}", ep.cyan())?;
        }
        if let Some(ev) = &f.evidence {
            writeln!(out, "         Evidence : {}", ev.dimmed())?;
        }
        if self.config.report.verbose {
            if let Some(d) = &f.details {
                writeln!(out, "         Details  : {}", d.dimmed())?;
            }
            writeln!(out, "         Fix      : {}", f.fix.italic())?;
        } else if f.status == FindingStatus::Fail || f.status == FindingStatus::Manual {
            writeln!(out, "         Fix      : {}", f.fix.italic())?;
        }
        Ok(())
    }

    // ── JSON ─────────────────────────────────────────────────────────────────

    fn report_json(&self, mut out: Box<dyn Write>, result: &ScanResult) -> Result<()> {
        let json = serde_json::to_string_pretty(result)?;
        writeln!(out, "{}", json)?;
        Ok(())
    }

    // ── SARIF 2.1.0 ──────────────────────────────────────────────────────────

    fn report_sarif(&self, mut out: Box<dyn Write>, result: &ScanResult) -> Result<()> {
        // Deduplicate rules by stig_id — multiple findings can share the same control ID.
        let mut seen_ids = std::collections::HashSet::new();
        let rules: Vec<serde_json::Value> = result
            .findings
            .iter()
            .filter(|f| seen_ids.insert(f.stig_id.clone()))
            .map(|f| {
                serde_json::json!({
                    "id": f.stig_id,
                    "name": f.title,
                    "shortDescription": { "text": f.title },
                    "fullDescription": { "text": f.fix },
                    "defaultConfiguration": {
                        "level": sarif_level(&f.severity)
                    },
                    "properties": {
                        "tags": ["security", "stig", "disa-api-srg-v1r0.1"]
                    }
                })
            })
            .collect();

        let results: Vec<serde_json::Value> = result
            .findings
            .iter()
            .map(|f| {
                let kind = sarif_kind(&f.status);
                let level = sarif_level(&f.severity);
                // Build message text: include fix advice so it surfaces in the Security tab.
                let msg = format!(
                    "{} | Fix: {}",
                    f.evidence.as_deref().unwrap_or(&f.title),
                    f.fix
                );
                // GitHub Code Scanning requires at least one physicalLocation per result.
                // For an API scanner there is no source file; use the config as the anchor URI
                // and carry the actual API endpoint in logicalLocations.
                let endpoint_name = f
                    .endpoint
                    .as_deref()
                    .unwrap_or(&self.config.target.base_url);
                serde_json::json!({
                    "ruleId": f.stig_id,
                    "kind": kind,
                    "level": level,
                    "message": { "text": msg },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "config.yaml",
                                "uriBaseId": "%SRCROOT%"
                            }
                        },
                        "logicalLocations": [{
                            "name": endpoint_name,
                            "kind": "namespace"
                        }]
                    }]
                })
            })
            .collect();

        let sarif = serde_json::json!({
            "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "stig-api-scanner",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/kelleyblackmore/stig-api-scanner",
                        "rules": rules
                    }
                },
                "results": results,
                "properties": {
                    "target": result.target,
                    "timestamp": result.timestamp,
                    "stig": "DISA Application Programming Interface (API) Security Requirements Guide V1R0.1"
                }
            }]
        });

        writeln!(out, "{}", serde_json::to_string_pretty(&sarif)?)?;
        Ok(())
    }

    fn report_junit(&self, mut out: Box<dyn Write>, result: &ScanResult) -> Result<()> {
        writeln!(out, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
        writeln!(
            out,
            r#"<testsuite name="STIG API Scanner — DISA API SRG V1R0.1" tests="{}" failures="{}" timestamp="{}" hostname="{}">"#,
            result.total, result.failed, result.timestamp, result.target
        )?;

        for f in &result.findings {
            let safe_name = f.title.replace('"', "'");
            writeln!(
                out,
                r#"  <testcase name="{} — {}" classname="{}">"#,
                f.stig_id, safe_name, f.severity
            )?;
            match f.status {
                FindingStatus::Fail => {
                    let msg = f.evidence.as_deref().unwrap_or(&f.title);
                    writeln!(
                        out,
                        r#"    <failure message="{}" type="STIGFinding">{}</failure>"#,
                        xml_escape(msg),
                        xml_escape(&f.fix)
                    )?;
                }
                FindingStatus::Skip | FindingStatus::NotApplicable => {
                    writeln!(out, "    <skipped/>")?;
                }
                FindingStatus::Manual => {
                    writeln!(
                        out,
                        r#"    <skipped message="Manual review required: {}"/>"#,
                        xml_escape(&f.fix)
                    )?;
                }
                _ => {}
            }
            writeln!(out, "  </testcase>")?;
        }

        writeln!(out, "</testsuite>")?;
        Ok(())
    }
}

fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn sarif_kind(status: &FindingStatus) -> &'static str {
    match status {
        FindingStatus::Pass => "pass",
        FindingStatus::Fail => "fail",
        FindingStatus::Manual | FindingStatus::Skip | FindingStatus::NotApplicable => "open",
        FindingStatus::Error => "notApplicable",
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
