//! Network policy configuration for eBPF

use anyhow::{Context, Result};
use aya::maps::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use tracing::{debug, info, warn};

use crate::bpf::BpfManager;
use crate::config::{NetworkConfig, NetworkRule, PolicyMode};
use openclaw_supervisor_common::NetworkRuleKey;

/// Configure network rules for a container
pub async fn configure_network_rules(
    manager: &mut BpfManager,
    cgroup_id: u64,
    config: &NetworkConfig,
) -> Result<()> {
    info!(
        "Configuring network rules for cgroup {} (mode: {:?})",
        cgroup_id, config.mode
    );

    let map_name = match config.mode {
        PolicyMode::Allowlist => "NETWORK_ALLOWLIST",
        PolicyMode::Denylist => "NETWORK_DENYLIST",
    };

    for rule in &config.rules {
        if let Err(e) = add_network_rule(manager, cgroup_id, rule, map_name).await {
            warn!("Failed to add network rule: {}", e);
        }
    }

    Ok(())
}

async fn add_network_rule(
    manager: &mut BpfManager,
    cgroup_id: u64,
    rule: &NetworkRule,
    map_name: &str,
) -> Result<()> {
    let ips = resolve_rule_ips(manager, rule).await?;
    let ports = rule.ports();

    // If no ports specified, use port 0 as wildcard
    let ports_to_add: Vec<u16> = if ports.is_empty() {
        vec![0]
    } else {
        ports.to_vec()
    };

    let mut map: HashMap<_, NetworkRuleKey, u8> = manager
        .bpf_mut()
        .map_mut(map_name)
        .with_context(|| format!("{} map not found", map_name))?
        .try_into()?;

    for ip in &ips {
        let daddr = match ip {
            IpAddr::V4(v4) => u32::from(*v4),
            IpAddr::V6(_) => {
                debug!("Skipping IPv6 address: {}", ip);
                continue;
            }
        };

        for &port in &ports_to_add {
            let key = NetworkRuleKey {
                cgroup_id,
                daddr,
                dport: port,
                _pad: 0,
            };

            map.insert(key, 1, 0)?;
            debug!("Added network rule: {} port {} for cgroup {}", ip, port, cgroup_id);
        }
    }

    Ok(())
}

async fn resolve_rule_ips(manager: &BpfManager, rule: &NetworkRule) -> Result<Vec<IpAddr>> {
    match rule {
        NetworkRule::Domain { domain, .. } => {
            info!("Resolving domain: {}", domain);

            if domain.starts_with("*.") {
                // Wildcard domain
                let results = manager.dns_resolver().resolve_wildcard(domain).await?;
                let ips: Vec<IpAddr> = results.into_iter().flat_map(|(_, ips)| ips).collect();
                Ok(ips)
            } else {
                // Exact domain
                manager.dns_resolver().resolve(domain).await
            }
        }
        NetworkRule::Ip { ip, .. } => {
            // Parse IP or CIDR
            let network: ipnetwork::IpNetwork = ip.parse()?;

            match network {
                ipnetwork::IpNetwork::V4(v4_net) => {
                    if v4_net.prefix() == 32 {
                        // Single IP
                        Ok(vec![IpAddr::V4(v4_net.ip())])
                    } else {
                        // CIDR range - expand to individual IPs
                        // For large ranges, we just add the network address
                        // (proper CIDR matching would need LPM trie in eBPF)
                        let ips: Vec<IpAddr> = v4_net.iter().map(IpAddr::V4).collect();
                        if ips.len() > 256 {
                            warn!(
                                "Large CIDR range {} ({} IPs), using LPM would be more efficient",
                                ip,
                                ips.len()
                            );
                        }
                        Ok(ips)
                    }
                }
                ipnetwork::IpNetwork::V6(v6_net) => {
                    if v6_net.prefix() == 128 {
                        Ok(vec![IpAddr::V6(v6_net.ip())])
                    } else {
                        // IPv6 CIDR ranges can be huge, just return network address
                        warn!("IPv6 CIDR ranges are not fully supported yet");
                        Ok(vec![IpAddr::V6(v6_net.ip())])
                    }
                }
            }
        }
    }
}

/// Add a single IP to the network map
pub fn add_ip_to_map(
    manager: &mut BpfManager,
    cgroup_id: u64,
    ip: Ipv4Addr,
    port: u16,
    is_allowlist: bool,
) -> Result<()> {
    let map_name = if is_allowlist {
        "NETWORK_ALLOWLIST"
    } else {
        "NETWORK_DENYLIST"
    };

    let mut map: HashMap<_, NetworkRuleKey, u8> = manager
        .bpf_mut()
        .map_mut(map_name)
        .with_context(|| format!("{} map not found", map_name))?
        .try_into()?;

    let key = NetworkRuleKey {
        cgroup_id,
        daddr: u32::from(ip),
        dport: port,
        _pad: 0,
    };

    map.insert(key, 1, 0)?;
    Ok(())
}

/// Remove an IP from the network map
pub fn remove_ip_from_map(
    manager: &mut BpfManager,
    cgroup_id: u64,
    ip: Ipv4Addr,
    port: u16,
    is_allowlist: bool,
) -> Result<()> {
    let map_name = if is_allowlist {
        "NETWORK_ALLOWLIST"
    } else {
        "NETWORK_DENYLIST"
    };

    let mut map: HashMap<_, NetworkRuleKey, u8> = manager
        .bpf_mut()
        .map_mut(map_name)
        .with_context(|| format!("{} map not found", map_name))?
        .try_into()?;

    let key = NetworkRuleKey {
        cgroup_id,
        daddr: u32::from(ip),
        dport: port,
        _pad: 0,
    };

    map.remove(&key)?;
    Ok(())
}
