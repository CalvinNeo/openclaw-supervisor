//! BPF program management
//!
//! This module provides the BPF manager for loading and managing eBPF programs.
//! On non-Linux platforms, a stub implementation is provided for development.

#![allow(dead_code)]
#![allow(unused_imports)]

#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod filesystem;

use anyhow::{Context, Result};
use std::collections::HashMap as StdHashMap;
use tracing::{debug, info, warn};

use crate::audit::AuditLogger;
use crate::config::{Config, ContainerConfig, PolicyMode};
use crate::dns::DnsResolver;
use openclaw_supervisor_common::{
    ContainerPolicy, FileEvent, NetworkEvent, PolicyMode as BpfPolicyMode,
};

/// Event received from eBPF programs
#[allow(dead_code)]
pub enum BpfEvent {
    Network(NetworkEvent),
    File(FileEvent),
}

// ============================================================================
// Linux implementation with real eBPF
// ============================================================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use aya::maps::{HashMap, RingBuf};
    use aya::{Ebpf, EbpfLoader};
    use std::path::Path;
    use tokio::io::unix::AsyncFd;
    use openclaw_supervisor_common::NetworkRuleKey;

    /// Manages eBPF programs and maps
    pub struct BpfManager {
        pub(crate) bpf: Ebpf,
        pub(crate) dns_resolver: DnsResolver,
        pub(crate) audit_logger: Option<AuditLogger>,
        pub(crate) cgroup_to_container: StdHashMap<u64, String>,
        pub(crate) container_to_cgroup: StdHashMap<String, u64>,
        events_fd: Option<AsyncFd<RingBuf<&'static mut aya::maps::MapData>>>,
    }

    impl BpfManager {
        /// Create a new BPF manager and load programs
        pub async fn new(audit_logger: Option<AuditLogger>) -> Result<Self> {
            info!("Loading eBPF programs...");

            let bpf = Self::load_bpf_programs().await?;

            let dns_resolver = DnsResolver::new()
                .await
                .context("Failed to create DNS resolver")?;

            Ok(Self {
                bpf,
                dns_resolver,
                audit_logger,
                cgroup_to_container: StdHashMap::new(),
                container_to_cgroup: StdHashMap::new(),
                events_fd: None,
            })
        }

        async fn load_bpf_programs() -> Result<Ebpf> {
            let bpf_path = "/usr/lib/openclaw-supervisor/openclaw-supervisor-ebpf";

            if Path::new(bpf_path).exists() {
                let data = std::fs::read(bpf_path)
                    .context("Failed to read eBPF program")?;
                EbpfLoader::new()
                    .load(&data)
                    .context("Failed to load eBPF program")
            } else {
                let dev_path = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../target/bpfel-unknown-none/release/openclaw-supervisor-ebpf"
                );

                if Path::new(dev_path).exists() {
                    let data = std::fs::read(dev_path)
                        .context("Failed to read eBPF program")?;
                    EbpfLoader::new()
                        .load(&data)
                        .context("Failed to load eBPF program")
                } else {
                    warn!("eBPF program not found, running in stub mode");
                    anyhow::bail!("eBPF program not found at {} or {}", bpf_path, dev_path)
                }
            }
        }

        /// Apply configuration to eBPF maps
        pub async fn apply_config(&mut self, config: &Config) -> Result<()> {
            info!("Applying configuration...");

            self.clear_maps()?;

            for container in &config.containers {
                if let Err(e) = self.configure_container(container).await {
                    warn!("Failed to configure container {}: {}", container.id, e);
                }
            }

            info!("Configuration applied successfully");
            Ok(())
        }

        async fn configure_container(&mut self, container: &ContainerConfig) -> Result<()> {
            info!("Configuring container: {}", container.id);

            let cgroup_id = self
                .resolve_container_cgroup(&container.id)
                .await
                .with_context(|| format!("Failed to resolve cgroup for container {}", container.id))?;

            self.cgroup_to_container
                .insert(cgroup_id, container.id.clone());
            self.container_to_cgroup
                .insert(container.id.clone(), cgroup_id);

            self.add_tracked_cgroup(cgroup_id)?;

            let policy = ContainerPolicy {
                network_mode: match container.network.mode {
                    PolicyMode::Allowlist => BpfPolicyMode::Allowlist as u8,
                    PolicyMode::Denylist => BpfPolicyMode::Denylist as u8,
                },
                filesystem_mode: match container.filesystem.mode {
                    PolicyMode::Allowlist => BpfPolicyMode::Allowlist as u8,
                    PolicyMode::Denylist => BpfPolicyMode::Denylist as u8,
                },
                _pad: [0; 6],
            };
            self.set_container_policy(cgroup_id, policy)?;

            super::network::configure_network_rules(self, cgroup_id, &container.network).await?;
            super::filesystem::configure_filesystem_rules(self, cgroup_id, &container.filesystem)?;

            Ok(())
        }

        async fn resolve_container_cgroup(&self, container_id: &str) -> Result<u64> {
            let docker_cgroup = format!(
                "/sys/fs/cgroup/system.slice/docker-{}.scope",
                container_id
            );
            if let Ok(id) = Self::get_cgroup_id(&docker_cgroup) {
                return Ok(id);
            }

            let containerd_cgroup = format!(
                "/sys/fs/cgroup/system.slice/containerd-{}.scope",
                container_id
            );
            if let Ok(id) = Self::get_cgroup_id(&containerd_cgroup) {
                return Ok(id);
            }

            let cgroup_v2 = format!("/sys/fs/cgroup/docker/{}", container_id);
            if let Ok(id) = Self::get_cgroup_id(&cgroup_v2) {
                return Ok(id);
            }

            if container_id.len() < 64 {
                if let Some(full_id) = Self::find_full_container_id(container_id).await? {
                    return self.resolve_container_cgroup(&full_id).await;
                }
            }

            anyhow::bail!("Could not find cgroup for container: {}", container_id)
        }

        fn get_cgroup_id(path: &str) -> Result<u64> {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(path)?;
            Ok(metadata.ino())
        }

        async fn find_full_container_id(short_id: &str) -> Result<Option<String>> {
            let output = tokio::process::Command::new("docker")
                .args(["inspect", "--format", "{{.Id}}", short_id])
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    let full_id = String::from_utf8_lossy(&output.stdout)
                        .trim()
                        .to_string();
                    if !full_id.is_empty() {
                        return Ok(Some(full_id));
                    }
                }
            }

            Ok(None)
        }

        fn add_tracked_cgroup(&mut self, cgroup_id: u64) -> Result<()> {
            let mut tracked: HashMap<_, u64, u8> = self
                .bpf
                .map_mut("TRACKED_CGROUPS")
                .context("TRACKED_CGROUPS map not found")?
                .try_into()?;
            tracked.insert(cgroup_id, 1, 0)?;
            Ok(())
        }

        fn set_container_policy(&mut self, cgroup_id: u64, policy: ContainerPolicy) -> Result<()> {
            let mut policies: HashMap<_, u64, ContainerPolicy> = self
                .bpf
                .map_mut("CONTAINER_POLICIES")
                .context("CONTAINER_POLICIES map not found")?
                .try_into()?;
            policies.insert(cgroup_id, policy, 0)?;
            Ok(())
        }

        fn clear_maps(&mut self) -> Result<()> {
            self.cgroup_to_container.clear();
            self.container_to_cgroup.clear();
            Ok(())
        }

        /// Wait for and return the next event from eBPF
        pub async fn next_event(&mut self) -> Option<BpfEvent> {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            None
        }

        /// Handle an event from eBPF
        pub async fn handle_event(&mut self, event: BpfEvent) {
            match event {
                BpfEvent::Network(net_event) => {
                    let container_id = self
                        .cgroup_to_container
                        .get(&net_event.cgroup_id)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    if let Some(ref logger) = self.audit_logger {
                        if let Err(e) = logger.log_network_event(&net_event, container_id, None) {
                            warn!("Failed to log network event: {}", e);
                        }
                    }
                }
                BpfEvent::File(file_event) => {
                    let container_id = self
                        .cgroup_to_container
                        .get(&file_event.cgroup_id)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    if let Some(ref logger) = self.audit_logger {
                        if let Err(e) = logger.log_file_event(&file_event, container_id) {
                            warn!("Failed to log file event: {}", e);
                        }
                    }
                }
            }
        }

        pub fn dns_resolver(&self) -> &DnsResolver {
            &self.dns_resolver
        }

        pub fn bpf_mut(&mut self) -> &mut Ebpf {
            &mut self.bpf
        }

        pub async fn cleanup(&mut self) -> Result<()> {
            info!("Cleaning up BPF programs...");
            Ok(())
        }
    }
}

// ============================================================================
// Stub implementation for non-Linux platforms (development only)
// ============================================================================

#[cfg(not(target_os = "linux"))]
mod stub_impl {
    use super::*;

    /// Stub BPF manager for non-Linux platforms
    pub struct BpfManager {
        dns_resolver: DnsResolver,
        audit_logger: Option<AuditLogger>,
        cgroup_to_container: StdHashMap<u64, String>,
        container_to_cgroup: StdHashMap<String, u64>,
    }

    impl BpfManager {
        pub async fn new(audit_logger: Option<AuditLogger>) -> Result<Self> {
            warn!("Running on non-Linux platform - eBPF features are disabled (stub mode)");

            let dns_resolver = DnsResolver::new()
                .await
                .context("Failed to create DNS resolver")?;

            Ok(Self {
                dns_resolver,
                audit_logger,
                cgroup_to_container: StdHashMap::new(),
                container_to_cgroup: StdHashMap::new(),
            })
        }

        pub async fn apply_config(&mut self, config: &Config) -> Result<()> {
            info!("[STUB] Applying configuration with {} containers...", config.containers.len());

            for container in &config.containers {
                info!("[STUB] Would configure container: {}", container.id);

                // Resolve DNS for network rules
                for rule in &container.network.rules {
                    match rule {
                        crate::config::NetworkRule::Domain { domain, ports } => {
                            info!("[STUB] Would resolve domain: {} for ports {:?}", domain, ports);
                            if domain.starts_with("*.") {
                                if let Ok(results) = self.dns_resolver.resolve_wildcard(domain).await {
                                    for (resolved_domain, ips) in results {
                                        debug!("[STUB] Resolved {} -> {:?}", resolved_domain, ips);
                                    }
                                }
                            } else {
                                if let Ok(ips) = self.dns_resolver.resolve(domain).await {
                                    debug!("[STUB] Resolved {} -> {:?}", domain, ips);
                                }
                            }
                        }
                        crate::config::NetworkRule::Ip { ip, ports } => {
                            info!("[STUB] Would add IP rule: {} for ports {:?}", ip, ports);
                        }
                    }
                }
            }

            info!("[STUB] Configuration applied (no actual eBPF enforcement)");
            Ok(())
        }

        pub async fn next_event(&mut self) -> Option<BpfEvent> {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            None
        }

        pub async fn handle_event(&mut self, event: BpfEvent) {
            match event {
                BpfEvent::Network(net_event) => {
                    let container_id = self
                        .cgroup_to_container
                        .get(&net_event.cgroup_id)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    if let Some(ref logger) = self.audit_logger {
                        if let Err(e) = logger.log_network_event(&net_event, container_id, None) {
                            warn!("Failed to log network event: {}", e);
                        }
                    }
                }
                BpfEvent::File(file_event) => {
                    let container_id = self
                        .cgroup_to_container
                        .get(&file_event.cgroup_id)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");

                    if let Some(ref logger) = self.audit_logger {
                        if let Err(e) = logger.log_file_event(&file_event, container_id) {
                            warn!("Failed to log file event: {}", e);
                        }
                    }
                }
            }
        }

        pub fn dns_resolver(&self) -> &DnsResolver {
            &self.dns_resolver
        }

        pub async fn cleanup(&mut self) -> Result<()> {
            info!("[STUB] Cleanup complete");
            Ok(())
        }
    }
}

// Re-export the appropriate implementation
#[cfg(target_os = "linux")]
pub use linux_impl::BpfManager;

#[cfg(not(target_os = "linux"))]
pub use stub_impl::BpfManager;
