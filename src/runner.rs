use anyhow::Result;

use crate::{
    checks,
    config::Config,
    http::HttpClient,
    types::{Finding, ScanResult},
};

pub struct Runner {
    config: Config,
    client: HttpClient,
}

impl Runner {
    pub fn new(config: Config) -> Result<Self> {
        let client = HttpClient::new(&config.target, &config.auth)?;
        Ok(Self { config, client })
    }

    pub async fn run(&self) -> Result<ScanResult> {
        let all_checks = checks::all_checks();
        let mut findings: Vec<Finding> = Vec::new();

        for check in &all_checks {
            if !check.is_enabled(&self.config) {
                if self.config.report.verbose {
                    eprintln!("[skip] {} (disabled in config)", check.name());
                }
                continue;
            }

            if self.config.report.verbose {
                eprintln!("[run]  {}", check.name());
            }

            match check.run(&self.client, &self.config).await {
                Ok(mut f) => findings.append(&mut f),
                Err(e) => {
                    eprintln!(
                        "[warn] check '{}' encountered an error: {}",
                        check.name(),
                        e
                    );
                }
            }
        }

        let timestamp = chrono::Utc::now().to_rfc3339();
        Ok(ScanResult::new(
            client_target(&self.config),
            timestamp,
            findings,
        ))
    }
}

fn client_target(config: &Config) -> String {
    config.target.base_url.clone()
}
