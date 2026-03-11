//! Network control eBPF programs
//!
//! Uses cgroup/connect4 and cgroup/connect6 hooks to intercept outgoing connections.

use aya_ebpf::{
    cty::c_long,
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::cgroup_sock_addr,
    programs::SockAddrContext,
};
use aya_log_ebpf::info;
use openclaw_supervisor_common::{EventType, NetworkEvent, NetworkRuleKey, PolicyMode};

use crate::{CONTAINER_POLICIES, EVENTS, NETWORK_ALLOWLIST, NETWORK_DENYLIST, TRACKED_CGROUPS};

/// IPv4 connect hook
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i64 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // Allow on error
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Result<i64, c_long> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    // Check if this cgroup is being tracked
    if unsafe { TRACKED_CGROUPS.get(&cgroup_id).is_none() } {
        return Ok(1); // Not tracked, allow
    }

    // Get destination address and port
    let sock_addr = unsafe { &*ctx.sock_addr };
    let daddr = u32::from_be(unsafe { (*sock_addr).user_ip4 });
    let dport = u16::from_be(unsafe { (*sock_addr).user_port as u16 });

    // Get policy for this container
    let policy = match unsafe { CONTAINER_POLICIES.get(&cgroup_id) } {
        Some(p) => p,
        None => return Ok(1), // No policy, allow
    };

    let key = NetworkRuleKey {
        cgroup_id,
        daddr,
        dport,
        _pad: 0,
    };

    // Also check with port 0 (wildcard port)
    let key_any_port = NetworkRuleKey {
        cgroup_id,
        daddr,
        dport: 0,
        _pad: 0,
    };

    let allowed = if policy.network_mode == PolicyMode::Allowlist as u8 {
        // Allowlist mode: must be in allowlist
        unsafe {
            NETWORK_ALLOWLIST.get(&key).is_some() || NETWORK_ALLOWLIST.get(&key_any_port).is_some()
        }
    } else {
        // Denylist mode: must NOT be in denylist
        unsafe {
            NETWORK_DENYLIST.get(&key).is_none() && NETWORK_DENYLIST.get(&key_any_port).is_none()
        }
    };

    if !allowed {
        // Send block event to userspace
        send_network_event(ctx, cgroup_id, daddr, dport, EventType::NetworkBlock);
        return Ok(0); // Block
    }

    // Optionally log allowed connections
    send_network_event(ctx, cgroup_id, daddr, dport, EventType::NetworkConnect);
    Ok(1) // Allow
}

fn send_network_event(
    _ctx: &SockAddrContext,
    cgroup_id: u64,
    daddr: u32,
    dport: u16,
    event_type: EventType,
) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let uid_gid = unsafe { bpf_get_current_uid_gid() };

    let event = NetworkEvent {
        event_type: event_type as u32,
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        daddr,
        dport,
        protocol: 6, // TCP
        _pad: 0,
        cgroup_id,
    };

    if let Some(mut buf) = EVENTS.reserve::<NetworkEvent>(0) {
        unsafe {
            core::ptr::write(buf.as_mut_ptr(), event);
        }
        buf.submit(0);
    }
}

/// IPv6 connect hook (placeholder - can be extended)
#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i64 {
    // For now, allow all IPv6 connections
    // TODO: Implement IPv6 filtering
    1
}
