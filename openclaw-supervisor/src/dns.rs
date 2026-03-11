//! DNS resolution and wildcard domain support

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

/// DNS resolver with caching and wildcard support
pub struct DnsResolver {
    resolver: TokioAsyncResolver,
    cache: Arc<RwLock<HashMap<String, Vec<IpAddr>>>>,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            resolver,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Resolve a domain to IP addresses
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(ips) = cache.get(domain) {
                return Ok(ips.clone());
            }
        }

        debug!("Resolving domain: {}", domain);

        let response = self
            .resolver
            .lookup_ip(domain)
            .await
            .with_context(|| format!("Failed to resolve: {}", domain))?;

        let ips: Vec<IpAddr> = response.iter().collect();

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(domain.to_string(), ips.clone());
        }

        info!("Resolved {} to {:?}", domain, ips);
        Ok(ips)
    }

    /// Resolve a wildcard domain pattern
    /// For `*.example.com`, this resolves common subdomains
    pub async fn resolve_wildcard(&self, pattern: &str) -> Result<Vec<(String, Vec<IpAddr>)>> {
        if !pattern.starts_with("*.") {
            let ips = self.resolve(pattern).await?;
            return Ok(vec![(pattern.to_string(), ips)]);
        }

        let base_domain = &pattern[2..]; // Remove "*."
        let mut results = Vec::new();

        // Common subdomains to try for wildcard patterns
        let common_subdomains = ["www", "api", "cdn", "static", "assets", "media"];

        for subdomain in &common_subdomains {
            let full_domain = format!("{}.{}", subdomain, base_domain);
            match self.resolve(&full_domain).await {
                Ok(ips) => {
                    if !ips.is_empty() {
                        results.push((full_domain, ips));
                    }
                }
                Err(e) => {
                    debug!("Failed to resolve {}: {}", full_domain, e);
                }
            }
        }

        // Also try the base domain itself
        if let Ok(ips) = self.resolve(base_domain).await {
            if !ips.is_empty() {
                results.push((base_domain.to_string(), ips));
            }
        }

        if results.is_empty() {
            warn!(
                "No IPs resolved for wildcard pattern: {} (this may be expected)",
                pattern
            );
        }

        Ok(results)
    }

    /// Check if a domain matches a pattern (including wildcards)
    pub fn matches_pattern(domain: &str, pattern: &str) -> bool {
        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // Keep the dot: ".example.com"
            domain.ends_with(suffix) || domain == &pattern[2..]
        } else {
            domain == pattern
        }
    }

    /// Clear the DNS cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("DNS cache cleared");
    }

    /// Get current cache size
    pub async fn cache_size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_matching() {
        assert!(DnsResolver::matches_pattern("api.openai.com", "*.openai.com"));
        assert!(DnsResolver::matches_pattern("www.openai.com", "*.openai.com"));
        assert!(DnsResolver::matches_pattern("openai.com", "*.openai.com"));
        assert!(!DnsResolver::matches_pattern("openai.com.evil.com", "*.openai.com"));
        assert!(!DnsResolver::matches_pattern("notaopenai.com", "*.openai.com"));
    }

    #[test]
    fn test_exact_matching() {
        assert!(DnsResolver::matches_pattern("api.openai.com", "api.openai.com"));
        assert!(!DnsResolver::matches_pattern("www.openai.com", "api.openai.com"));
    }
}
