//! Configuration parsing and hot-reload support

#![allow(dead_code)]

use anyhow::{Context, Result};
use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Root configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub containers: Vec<ContainerConfig>,
    #[serde(default)]
    pub audit: AuditConfig,
}

/// Per-container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container ID (short or full)
    pub id: String,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
}

/// Network policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub rules: Vec<NetworkRule>,
}

/// A single network rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NetworkRule {
    Domain {
        domain: String,
        #[serde(default)]
        ports: Vec<u16>,
    },
    Ip {
        ip: String,
        #[serde(default)]
        ports: Vec<u16>,
    },
}

impl NetworkRule {
    pub fn ports(&self) -> &[u16] {
        match self {
            NetworkRule::Domain { ports, .. } => ports,
            NetworkRule::Ip { ports, .. } => ports,
        }
    }
}

/// Filesystem policy configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub mode: PolicyMode,
    #[serde(default)]
    pub rules: Vec<FilesystemRule>,
}

/// A single filesystem rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemRule {
    pub path: String,
    #[serde(default = "default_permission")]
    pub permission: String,
    #[serde(default)]
    pub deny_extensions: Vec<String>,
}

fn default_permission() -> String {
    "r".to_string()
}

impl FilesystemRule {
    /// Parse permission string to flags
    pub fn permission_flags(&self) -> u8 {
        let mut flags = 0u8;
        if self.permission.contains('r') {
            flags |= 1; // PERM_READ
        }
        if self.permission.contains('w') {
            flags |= 2; // PERM_WRITE
        }
        flags
    }
}

/// Policy mode: allowlist or denylist
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    #[default]
    Allowlist,
    Denylist,
}

/// Audit logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_log_path")]
    pub log_path: String,
    #[serde(default)]
    pub log_format: LogFormat,
}

fn default_log_path() -> String {
    "/var/log/openclaw-supervisor.log".to_string()
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_path: default_log_path(),
            log_format: LogFormat::default(),
        }
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Json,
    Text,
}

impl Config {
    /// Load configuration from a file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {:?}", path))?;
        let config: Config =
            serde_yaml::from_str(&content).context("Failed to parse YAML config")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration
    fn validate(&self) -> Result<()> {
        let mut seen_ids = HashSet::new();
        for container in &self.containers {
            if !seen_ids.insert(&container.id) {
                anyhow::bail!("Duplicate container ID: {}", container.id);
            }

            // Validate network rules
            for rule in &container.network.rules {
                match rule {
                    NetworkRule::Ip { ip, .. } => {
                        // Validate IP/CIDR format
                        ip.parse::<ipnetwork::IpNetwork>()
                            .with_context(|| format!("Invalid IP/CIDR: {}", ip))?;
                    }
                    NetworkRule::Domain { domain, .. } => {
                        // Basic domain validation
                        if domain.is_empty() {
                            anyhow::bail!("Empty domain in network rule");
                        }
                    }
                }
            }

            // Validate filesystem rules
            for rule in &container.filesystem.rules {
                if rule.path.is_empty() {
                    anyhow::bail!("Empty path in filesystem rule");
                }
                if !rule.path.starts_with('/') {
                    anyhow::bail!("Filesystem path must be absolute: {}", rule.path);
                }
            }
        }
        Ok(())
    }

    /// Get container IDs
    pub fn container_ids(&self) -> Vec<&str> {
        self.containers.iter().map(|c| c.id.as_str()).collect()
    }
}

/// Configuration file watcher for hot-reload
pub struct ConfigWatcher;

impl ConfigWatcher {
    /// Watch a configuration file for changes and send updated configs
    pub async fn watch(path: std::path::PathBuf, tx: mpsc::Sender<Config>) -> Result<()> {
        let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel(1);

        let mut watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| {
                if let Ok(event) = res {
                    if event.kind.is_modify() {
                        let _ = notify_tx.blocking_send(());
                    }
                }
            },
            NotifyConfig::default(),
        )?;

        watcher.watch(&path, RecursiveMode::NonRecursive)?;

        info!("Watching config file for changes: {:?}", path);

        // Keep watcher alive and process notifications
        loop {
            if notify_rx.recv().await.is_some() {
                // Small delay to handle multiple rapid writes
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

                match Config::load(&path) {
                    Ok(config) => {
                        if tx.send(config).await.is_err() {
                            warn!("Failed to send config update");
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to reload config: {}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_example_config() {
        let yaml = r#"
containers:
  - id: "abc123"
    network:
      mode: allowlist
      rules:
        - domain: "*.openai.com"
          ports: [443]
        - ip: "192.168.1.0/24"
          ports: [80, 443]
    filesystem:
      mode: allowlist
      rules:
        - path: "/data"
          permission: rw
        - path: "/tmp"
          permission: r
          deny_extensions: [".sh"]

audit:
  enabled: true
  log_path: "/var/log/test.log"
  log_format: json
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.containers.len(), 1);
        assert_eq!(config.containers[0].network.rules.len(), 2);
        assert!(config.audit.enabled);
    }

    #[test]
    fn test_permission_flags() {
        let rule = FilesystemRule {
            path: "/test".to_string(),
            permission: "rw".to_string(),
            deny_extensions: vec![],
        };
        assert_eq!(rule.permission_flags(), 3);

        let rule_r = FilesystemRule {
            path: "/test".to_string(),
            permission: "r".to_string(),
            deny_extensions: vec![],
        };
        assert_eq!(rule_r.permission_flags(), 1);
    }
}
