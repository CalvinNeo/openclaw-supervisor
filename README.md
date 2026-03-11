# OpenClaw Supervisor

eBPF-based container access control supervisor for fine-grained network and filesystem policy enforcement.

## Features

- **Network Control**: IP/domain allowlist/denylist with wildcard support (`*.example.com`)
- **Filesystem Control**: Path-based access control with read/write permissions
- **Multi-container Support**: Independent policies per container
- **Hot Reload**: Configuration changes apply without restart
- **Audit Logging**: JSON/text format logging of blocked operations

## Requirements

- Linux kernel 5.7+ (for LSM BPF support)
- Rust nightly toolchain
- Root privileges (for eBPF)

## Quick Start

```bash
# Build eBPF programs
cargo xtask build-ebpf --release

# Build userspace daemon
cargo build --release

# Run (requires root)
sudo ./target/release/openclaw-supervisor --config config.yaml.example
```

## Configuration

See `config.yaml.example` for full documentation. Basic example:

```yaml
containers:
  - id: "container-id-here"
    network:
      mode: allowlist
      rules:
        - domain: "*.openai.com"
          ports: [443]
    filesystem:
      mode: allowlist
      rules:
        - path: "/data"
          permission: rw

audit:
  enabled: true
  log_path: "/var/log/openclaw-supervisor.log"
  log_format: json
```

## Architecture

```
User Space                    Kernel Space
+-----------------+          +------------------+
| openclaw-       |  perf    | eBPF Programs    |
| supervisor      |<-------->| - cgroup/connect |
| - Config Parser |  buffer  | - LSM/file_open  |
| - DNS Resolver  |          +------------------+
| - Audit Logger  |
+-----------------+
```

## Testing

```bash
# Run unit tests (works on any platform)
cargo test

# Run with example config (stub mode on non-Linux)
cargo run -- --config config.yaml.example -v
```

## License

MIT OR Apache-2.0
