use anyhow::Result;
use async_trait::async_trait;

use crate::{config::Config, http::HttpClient, types::Finding};

pub mod auth;
pub mod cache;
pub mod cors;
pub mod error_handling;
pub mod headers;
pub mod input;
pub mod rate_limit;
pub mod tokens;
pub mod transport;

#[async_trait]
pub trait Check: Send + Sync {
    fn name(&self) -> &str;
    fn is_enabled(&self, config: &Config) -> bool;
    async fn run(&self, client: &HttpClient, config: &Config) -> Result<Vec<Finding>>;
}

pub fn all_checks() -> Vec<Box<dyn Check>> {
    vec![
        Box::new(transport::TransportCheck),
        Box::new(headers::HeadersCheck),
        Box::new(cors::CorsCheck),
        Box::new(auth::AuthCheck),
        Box::new(tokens::TokensCheck),
        Box::new(rate_limit::RateLimitCheck),
        Box::new(input::InputValidationCheck),
        Box::new(error_handling::ErrorHandlingCheck),
        Box::new(cache::CacheCheck),
    ]
}
