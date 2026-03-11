//! OpenClaw Supervisor eBPF Programs
//!
//! This module contains the eBPF programs for network and filesystem control.

#![no_std]
#![no_main]

mod network;
mod filesystem;

use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf};
use openclaw_supervisor_common::{
    ContainerPolicy, FileRule, NetworkEvent, NetworkRuleKey, MAX_PATH_LEN,
};

/// Ring buffer for sending events to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Map from cgroup_id to container policy
#[map]
static CONTAINER_POLICIES: HashMap<u64, ContainerPolicy> =
    HashMap::with_max_entries(1024, 0);

/// Network allowlist: (cgroup_id, ip, port) -> 1 (allowed)
#[map]
static NETWORK_ALLOWLIST: HashMap<NetworkRuleKey, u8> =
    HashMap::with_max_entries(65536, 0);

/// Network denylist: (cgroup_id, ip, port) -> 1 (denied)
#[map]
static NETWORK_DENYLIST: HashMap<NetworkRuleKey, u8> =
    HashMap::with_max_entries(65536, 0);

/// File rules: cgroup_id -> array of file rules (simplified, using hash)
/// Key format: cgroup_id + path hash
#[map]
static FILE_RULES: HashMap<u64, FileRule> = HashMap::with_max_entries(65536, 0);

/// Tracked cgroup IDs - if a cgroup is not in this map, we don't enforce
#[map]
static TRACKED_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(1024, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
