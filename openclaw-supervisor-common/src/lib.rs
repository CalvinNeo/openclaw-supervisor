//! Common types shared between userspace and eBPF programs.
//!
//! This crate is `#![no_std]` compatible to be usable in eBPF context.

#![cfg_attr(not(feature = "user"), no_std)]

/// Maximum path length for file rules
pub const MAX_PATH_LEN: usize = 256;

/// Maximum extension length
pub const MAX_EXT_LEN: usize = 16;

/// Event types for audit logging
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum EventType {
    NetworkConnect = 1,
    NetworkBlock = 2,
    FileOpen = 3,
    FileBlock = 4,
}

/// Network event data passed from eBPF to userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub daddr: u32,         // destination IPv4 address
    pub dport: u16,         // destination port
    pub protocol: u8,       // IPPROTO_TCP or IPPROTO_UDP
    pub _pad: u8,
    pub cgroup_id: u64,
}

/// File event data passed from eBPF to userspace
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileEvent {
    pub event_type: u32,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,         // file open flags
    pub cgroup_id: u64,
    pub path_len: u32,
    pub path: [u8; MAX_PATH_LEN],
}

/// Network rule key for eBPF map lookup
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetworkRuleKey {
    pub cgroup_id: u64,
    pub daddr: u32,
    pub dport: u16,
    pub _pad: u16,
}

/// File rule for eBPF map
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileRule {
    pub cgroup_id: u64,
    pub path_prefix: [u8; MAX_PATH_LEN],
    pub path_len: u32,
    pub permission: u8,     // 1=read, 2=write, 3=rw
    pub _pad: [u8; 3],
}

/// Permission flags
pub const PERM_READ: u8 = 1;
pub const PERM_WRITE: u8 = 2;
pub const PERM_RW: u8 = 3;

/// Policy mode
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PolicyMode {
    #[default]
    Allowlist = 0,
    Denylist = 1,
}

/// Container policy metadata stored in eBPF map
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ContainerPolicy {
    pub network_mode: u8,   // PolicyMode
    pub filesystem_mode: u8,
    pub _pad: [u8; 6],
}

// Pod implementations for aya (Linux only with user feature)
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for NetworkEvent {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for FileEvent {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for NetworkRuleKey {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for FileRule {}
#[cfg(all(feature = "user", target_os = "linux"))]
unsafe impl aya::Pod for ContainerPolicy {}
