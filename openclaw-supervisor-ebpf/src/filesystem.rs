//! Filesystem control eBPF programs
//!
//! Uses LSM hooks (file_open) to intercept file operations.
//! Falls back to kprobe on older kernels.

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes},
    macros::lsm,
    programs::LsmContext,
};
use openclaw_supervisor_common::{EventType, FileEvent, FileRule, PolicyMode, PERM_READ, PERM_WRITE, MAX_PATH_LEN};

use crate::{CONTAINER_POLICIES, EVENTS, FILE_RULES, TRACKED_CGROUPS};

/// LSM file_open hook
#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // Allow on error (LSM returns 0 for allow)
    }
}

fn try_file_open(ctx: &LsmContext) -> Result<i32, c_long> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Check if this cgroup is being tracked
    if unsafe { TRACKED_CGROUPS.get(&cgroup_id).is_none() } {
        return Ok(0); // Not tracked, allow
    }

    // Get policy for this container
    let policy = match unsafe { CONTAINER_POLICIES.get(&cgroup_id) } {
        Some(p) => p,
        None => return Ok(0), // No policy, allow
    };

    // For now, simplified implementation that checks FILE_RULES map
    // In real implementation, we would:
    // 1. Get file path from struct file argument
    // 2. Check against rules with path prefix matching
    // 3. Check file extension against deny list

    // Placeholder: allow all for now
    // Full implementation requires BTF and reading file->f_path.dentry->d_name
    Ok(0)
}

fn send_file_event(cgroup_id: u64, path: &[u8], flags: u32, event_type: EventType) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let mut event = FileEvent {
        event_type: event_type as u32,
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        flags,
        cgroup_id,
        path_len: 0,
        path: [0u8; MAX_PATH_LEN],
    };

    let len = path.len().min(MAX_PATH_LEN);
    event.path[..len].copy_from_slice(&path[..len]);
    event.path_len = len as u32;

    if let Some(mut buf) = EVENTS.reserve::<FileEvent>(0) {
        unsafe {
            core::ptr::write(buf.as_mut_ptr(), event);
        }
        buf.submit(0);
    }
}

/// Check if a path matches a rule's prefix
fn path_matches_prefix(path: &[u8], prefix: &[u8], prefix_len: usize) -> bool {
    if path.len() < prefix_len {
        return false;
    }
    &path[..prefix_len] == &prefix[..prefix_len]
}

/// Check if a path has a denied extension
fn has_denied_extension(path: &[u8], _deny_extensions: &[&[u8]]) -> bool {
    // Find the last '.' in the path
    let mut last_dot = None;
    for (i, &b) in path.iter().enumerate() {
        if b == b'.' {
            last_dot = Some(i);
        }
    }

    // TODO: Implement extension checking against deny list
    // This would require passing extension list through eBPF map
    false
}
