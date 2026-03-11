//! Filesystem policy configuration for eBPF

use anyhow::{Context, Result};
use aya::maps::HashMap;
use tracing::{debug, info, warn};

use crate::bpf::BpfManager;
use crate::config::{FilesystemConfig, FilesystemRule, PolicyMode};
use openclaw_supervisor_common::{FileRule, MAX_PATH_LEN};

/// Configure filesystem rules for a container
pub fn configure_filesystem_rules(
    manager: &mut BpfManager,
    cgroup_id: u64,
    config: &FilesystemConfig,
) -> Result<()> {
    info!(
        "Configuring filesystem rules for cgroup {} (mode: {:?})",
        cgroup_id, config.mode
    );

    for rule in &config.rules {
        if let Err(e) = add_filesystem_rule(manager, cgroup_id, rule) {
            warn!("Failed to add filesystem rule for {}: {}", rule.path, e);
        }
    }

    Ok(())
}

fn add_filesystem_rule(
    manager: &mut BpfManager,
    cgroup_id: u64,
    rule: &FilesystemRule,
) -> Result<()> {
    let mut file_rule = FileRule {
        cgroup_id,
        path_prefix: [0u8; MAX_PATH_LEN],
        path_len: 0,
        permission: rule.permission_flags(),
        _pad: [0; 3],
    };

    // Copy path to fixed-size array
    let path_bytes = rule.path.as_bytes();
    let copy_len = path_bytes.len().min(MAX_PATH_LEN);
    file_rule.path_prefix[..copy_len].copy_from_slice(&path_bytes[..copy_len]);
    file_rule.path_len = copy_len as u32;

    // Create a unique key for this rule (hash of cgroup_id + path)
    let key = hash_file_rule_key(cgroup_id, &rule.path);

    let mut map: HashMap<_, u64, FileRule> = manager
        .bpf_mut()
        .map_mut("FILE_RULES")
        .context("FILE_RULES map not found")?
        .try_into()?;

    map.insert(key, file_rule, 0)?;
    debug!(
        "Added filesystem rule: {} (perm: {}) for cgroup {}",
        rule.path,
        rule.permission,
        cgroup_id
    );

    // Handle denied extensions
    for ext in &rule.deny_extensions {
        add_extension_deny_rule(manager, cgroup_id, &rule.path, ext)?;
    }

    Ok(())
}

/// Create a hash key for file rules
/// Must match the hash function in eBPF (hash_path_key)
fn hash_file_rule_key(cgroup_id: u64, path: &str) -> u64 {
    let path_bytes = path.as_bytes();
    let mut hash = cgroup_id;
    // FNV-1a style hash matching eBPF implementation
    for &byte in path_bytes.iter().take(MAX_PATH_LEN) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn add_extension_deny_rule(
    _manager: &mut BpfManager,
    cgroup_id: u64,
    base_path: &str,
    extension: &str,
) -> Result<()> {
    // Extension denial is complex to implement in eBPF efficiently
    // For now, we log this and note that full implementation would require:
    // 1. A separate map for denied extensions per path prefix
    // 2. String suffix matching in eBPF (limited by verifier)
    //
    // Alternative approaches:
    // - Use userspace for extension checking (slower but flexible)
    // - Pre-compute common filenames with denied extensions
    debug!(
        "Extension deny rule: {} under {} for cgroup {} (userspace enforcement)",
        extension, base_path, cgroup_id
    );
    Ok(())
}

/// Check if a path matches any filesystem rule for a container
pub fn check_path_permission(
    manager: &mut BpfManager,
    cgroup_id: u64,
    path: &str,
    is_write: bool,
) -> Result<bool> {
    let map: HashMap<_, u64, FileRule> = manager
        .bpf_mut()
        .map_mut("FILE_RULES")
        .context("FILE_RULES map not found")?
        .try_into()?;

    // This is a simplified check - in production, we'd need to:
    // 1. Find all rules for this cgroup
    // 2. Check path prefix matching
    // 3. Check most specific match

    let key = hash_file_rule_key(cgroup_id, path);
    if let Ok(rule) = map.get(&key, 0) {
        let required_perm = if is_write { 2 } else { 1 }; // PERM_WRITE or PERM_READ
        return Ok((rule.permission & required_perm) != 0);
    }

    // No exact match, check parent paths
    let mut current_path = path.to_string();
    while let Some(parent_end) = current_path.rfind('/') {
        if parent_end == 0 {
            current_path = "/".to_string();
        } else {
            current_path.truncate(parent_end);
        }

        let parent_key = hash_file_rule_key(cgroup_id, &current_path);
        if let Ok(rule) = map.get(&parent_key, 0) {
            let required_perm = if is_write { 2 } else { 1 };
            return Ok((rule.permission & required_perm) != 0);
        }

        if current_path == "/" {
            break;
        }
    }

    // No matching rule found
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_file_rule_key() {
        let key1 = hash_file_rule_key(12345, "/data");
        let key2 = hash_file_rule_key(12345, "/data");
        let key3 = hash_file_rule_key(12345, "/tmp");
        let key4 = hash_file_rule_key(67890, "/data");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
    }
}
