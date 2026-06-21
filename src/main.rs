mod checks;
mod config;
mod http;
mod reporter;
mod runner;
mod types;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::process;

use config::Config;
use reporter::Reporter;
use runner::Runner;
use types::FindingStatus;

/// Automated DISA API Security Requirements Guide (SRG) V1R0.1 compliance scanner.
///
/// Runs a suite of black-box checks against a live API endpoint and reports
/// findings mapped to DISA control IDs. Designed for pipeline integration —
/// exits non-zero when findings meet or exceed the configured fail severity.
#[derive(Parser)]
#[command(name = "stig-api-scanner", version, about, long_about = None)]
struct Cli {
    /// Path to YAML configuration file
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Output format: text (default), json, sarif, junit
    #[arg(short, long)]
    format: Option<String>,

    /// Write report to file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Include PASS findings in the report
    #[arg(long)]
    include_passed: bool,

    /// Print extra detail (fix text, error context)
    #[arg(short, long)]
    verbose: bool,

    /// Minimum severity that causes a non-zero exit: critical|high|medium|low|info
    #[arg(long)]
    fail_severity: Option<String>,

    /// List all available STIG checks and exit
    #[arg(long)]
    list_checks: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.list_checks {
        print_checks();
        return Ok(());
    }

    let mut config = Config::from_file(&cli.config)
        .with_context(|| format!("Loading config from {}", cli.config.display()))?;

    // CLI flags override config file values
    if let Some(fmt) = cli.format {
        config.report.format = fmt;
    }
    if let Some(out) = cli.output {
        config.report.output_file = Some(out.to_string_lossy().to_string());
    }
    if cli.include_passed {
        config.report.include_passed = true;
    }
    if cli.verbose {
        config.report.verbose = true;
    }
    if let Some(sev) = cli.fail_severity {
        config.pipeline.fail_severity = sev;
    }

    let runner = Runner::new(config.clone())?;
    let result = runner.run().await?;

    let reporter = Reporter::new(&config);
    reporter.report(&result)?;

    // Pipeline exit code
    let fail_threshold: types::Severity = config
        .pipeline
        .fail_severity
        .parse()
        .unwrap_or(types::Severity::High);

    let has_failures = result.findings.iter().any(|f| {
        f.status == FindingStatus::Fail && f.severity >= fail_threshold
    });

    if has_failures {
        process::exit(config.pipeline.exit_code_on_fail);
    }

    Ok(())
}

fn print_checks() {
    println!("Available STIG API SRG V1R0.1 checks:\n");
    let checks: &[(&str, &[(&str, &str)])] = &[
        (
            "transport",
            &[
                ("V-274710", "TLS 1.2+ required (HIGH)"),
                ("V-274497", "Encrypt data in transit / HTTP->HTTPS redirect (MED)"),
                ("V-274600", "Protect Session IDs -- HSTS (MED)"),
            ],
        ),
        (
            "headers",
            &[
                ("V-274600", "Strict-Transport-Security (MED)"),
                ("V-274497", "X-Content-Type-Options, X-Frame-Options (MED)"),
                ("V-274615", "Server header disclosure (MED)"),
                ("V-274767", "Content-Security-Policy (MED)"),
            ],
        ),
        (
            "cors",
            &[("V-274613", "CORS origin allowlist / no wildcard (MED)")],
        ),
        (
            "auth",
            &[
                ("V-274557", "Auth-required endpoints reject unauthenticated requests (MED)"),
                ("V-274507", "Access control enforced (authed != unauthed) (MED)"),
                ("V-274559", "DoD ICAM solution -- manual (MED)"),
                ("V-274643", "Privileged access restricted -- manual (MED)"),
                ("V-274672", "Periodic reauthentication -- manual (MED)"),
                ("V-274679", "Internal tokens not exposed -- manual (MED)"),
            ],
        ),
        (
            "tokens",
            &[
                ("V-274680", "Access token lifetime <= 30 min (MED)"),
                ("V-274712", "Audience claim present in JWT (MED)"),
                ("V-274678", "Token alg != none; secrets in vault -- manual (MED)"),
                ("V-274783", "FIPS-validated signing algorithm (MED)"),
                ("V-274681", "Refresh token TTL <= 90 days -- manual (MED)"),
                ("V-274603", "API keys from FIPS RNG -- manual (MED)"),
                ("V-274606", "API keys encrypted at rest -- manual (MED)"),
            ],
        ),
        (
            "rate_limit",
            &[
                ("V-274612", "Rate-limit headers present (MED)"),
                ("V-274682", "Active 429 enforcement (when probe_count > 0) (MED)"),
                ("V-274525", "Audit rate-limit events -- manual (MED)"),
                ("V-274526", "Gateway audit rate-limit events -- manual (MED)"),
            ],
        ),
        (
            "input_validation",
            &[
                ("V-274714", "SQL error injection resilience (HIGH)"),
                ("V-274767", "XSS reflection resilience (HIGH)"),
                ("V-274715", "Path traversal / oversized input (HIGH/MED)"),
            ],
        ),
        (
            "error_handling",
            &[("V-274615", "Error responses do not leak stack traces / paths (MED)")],
        ),
        (
            "cache",
            &[
                ("V-274607", "Cache-Control prevents caching sensitive data (HIGH)"),
                ("V-274709", "Pagination / data volume restriction (HIGH)"),
                ("V-274677", "Cache invalidation mechanism present (MED)"),
            ],
        ),
    ];

    for (check, controls) in checks {
        println!("  {} (disable in config: checks.{}: false)", check.to_uppercase(), check);
        for (id, desc) in *controls {
            println!("    {:<12} {}", id, desc);
        }
        println!();
    }
}
