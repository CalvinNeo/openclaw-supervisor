//! Filesystem control eBPF programs
//!
//! Uses LSM hooks (file_open) to intercept file operations.
//! Falls back to kprobe on older kernels.

use aya_ebpf::{
    cty::c_long,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_kernel_str_bytes,
    },
    macros::lsm,
    programs::LsmContext,
};
use openclaw_supervisor_common::{
    EventType, FileEvent, PolicyMode, PERM_READ, PERM_WRITE, MAX_PATH_LEN,
    O_WRONLY, O_RDWR, O_CREAT, O_TRUNC,
};

use crate::{CONTAINER_POLICIES, EVENTS, FILE_RULES, TRACKED_CGROUPS};

// Kernel struct definitions for file path traversal
#[repr(C)]
struct KernelFile {
    // Simplified - we only need f_path offset
    _padding: [u8; 16], // Offset to f_path varies by kernel, typically 16-24 bytes
    f_path: KernelPath,
    f_flags: u32,
}

#[repr(C)]
struct KernelPath {
    mnt: *const (),
    dentry: *const KernelDentry,
}

#[repr(C)]
struct KernelDentry {
    d_flags: u32,
    d_seq: u32,
    d_hash: u64,
    d_parent: *const KernelDentry,
    d_name: KernelQstr,
}

#[repr(C)]
struct KernelQstr {
    hash_len: u64, // Combined hash and length
    name: *const u8,
}

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

    // Get the file struct from LSM context
    // LSM file_open hook signature: int file_open(struct file *file)
    let file_ptr: *const KernelFile = unsafe { ctx.arg(0) };
    if file_ptr.is_null() {
        return Ok(0);
    }

    // Read file flags to determine operation type
    let flags = unsafe {
        let flags_ptr = &(*file_ptr).f_flags as *const u32;
        bpf_probe_read_kernel_str_bytes(flags_ptr as *const u8, &mut [0u8; 4])
            .map(|_| core::ptr::read_volatile(flags_ptr))
            .unwrap_or(0)
    };
    let is_write = (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) != 0;

    // Read file path by walking dentry
    let mut path_buf = [0u8; MAX_PATH_LEN];
    let path_len = unsafe { read_file_path(file_ptr, &mut path_buf) };

    if path_len == 0 {
        // Could not read path, allow the operation
        return Ok(0);
    }

    // Check file rules - iterate through possible path prefixes
    let allowed = check_file_permission(cgroup_id, &path_buf, path_len, is_write, policy.filesystem_mode);

    if !allowed {
        // Send block event to userspace
        send_file_event(cgroup_id, &path_buf, path_len, flags, EventType::FileBlock);
        return Ok(-1); // Block (EPERM)
    }

    // Optionally log allowed file operations (can be disabled for performance)
    // send_file_event(cgroup_id, &path_buf, path_len, flags, EventType::FileOpen);
    Ok(0) // Allow
}

/// Read file path by walking the dentry tree
/// Returns the path length or 0 on failure
unsafe fn read_file_path(file_ptr: *const KernelFile, path_buf: &mut [u8; MAX_PATH_LEN]) -> usize {
    // This is a simplified implementation
    // In production, you'd use bpf_d_path helper (kernel 5.10+) or BTF-based approach

    // For now, we'll use a placeholder that doesn't read the actual path
    // This would require BTF support for proper implementation
    // The full implementation needs:
    // 1. Reading f_path.dentry from file struct
    // 2. Walking d_parent chain to root
    // 3. Collecting d_name.name strings
    // 4. Reversing to get full path

    // Placeholder: return 0 to indicate we couldn't read the path
    // This will allow all operations (fail-open for safety)
    0
}

/// Check if file access is permitted based on rules
fn check_file_permission(
    cgroup_id: u64,
    path: &[u8; MAX_PATH_LEN],
    path_len: usize,
    is_write: bool,
    mode: u8,
) -> bool {
    let required_perm = if is_write { PERM_WRITE } else { PERM_READ };

    // In allowlist mode, we need to find a matching rule that permits the operation
    // In denylist mode, we allow unless we find a rule that explicitly denies
    let is_allowlist = mode == PolicyMode::Allowlist as u8;

    // Check each possible path prefix by creating lookup keys
    // We use a simple hash-based lookup for efficiency
    let mut current_len = path_len;

    // Bounded loop for eBPF verifier
    for _ in 0..MAX_PATH_LEN {
        if current_len == 0 {
            break;
        }

        // Create a lookup key using cgroup_id and path hash
        let key = hash_path_key(cgroup_id, path, current_len);

        if let Some(rule) = unsafe { FILE_RULES.get(&key) } {
            let has_permission = (rule.permission & required_perm) != 0;
            if is_allowlist {
                return has_permission;
            } else {
                // Denylist mode: if rule exists and denies permission, block
                if !has_permission {
                    return false;
                }
            }
        }

        // Move to parent path (find last '/')
        current_len = find_parent_path_len(path, current_len);
    }

    // No matching rule found
    if is_allowlist {
        false // Allowlist mode: no rule = deny
    } else {
        true // Denylist mode: no rule = allow
    }
}

/// Find the length of the parent path
fn find_parent_path_len(path: &[u8; MAX_PATH_LEN], current_len: usize) -> usize {
    if current_len <= 1 {
        return 0;
    }

    let mut i = current_len - 1;
    // Bounded loop for eBPF verifier
    for _ in 0..MAX_PATH_LEN {
        if i == 0 {
            break;
        }
        if path[i] == b'/' {
            return i;
        }
        i -= 1;
    }
    0
}

/// Simple hash function for path lookup key
fn hash_path_key(cgroup_id: u64, path: &[u8; MAX_PATH_LEN], len: usize) -> u64 {
    let mut hash = cgroup_id;
    // Simple FNV-1a style hash, bounded for verifier
    for i in 0..MAX_PATH_LEN {
        if i >= len {
            break;
        }
        hash ^= path[i] as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn send_file_event(
    cgroup_id: u64,
    path: &[u8; MAX_PATH_LEN],
    path_len: usize,
    flags: u32,
    event_type: EventType,
) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let mut event = FileEvent {
        event_type: event_type as u32,
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        flags,
        cgroup_id,
        path_len: path_len as u32,
        path: *path,
    };

    if let Some(mut buf) = EVENTS.reserve::<FileEvent>(0) {
        unsafe {
            core::ptr::write(buf.as_mut_ptr(), event);
        }
        buf.submit(0);
    }
}
