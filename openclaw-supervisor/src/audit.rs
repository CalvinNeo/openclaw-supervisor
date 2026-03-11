//! Audit logging module

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Mutex;
use tracing::info;

use crate::config::{AuditConfig, LogFormat};
use openclaw_supervisor_common::{FileEvent, NetworkEvent};

/// Audit event for logging
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub container_id: String,
    pub pid: u32,
    pub uid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkAuditData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileAuditData>,
}

#[derive(Debug, Serialize)]
pub struct NetworkAuditData {
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_domain: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FileAuditData {
    pub path: String,
    pub operation: String,
}

/// Audit logger
pub struct AuditLogger {
    writer: Mutex<BufWriter<File>>,
    format: LogFormat,
    stdout_mirror: bool,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(config: &AuditConfig) -> Result<Self> {
        let path = Path::new(&config.log_path);

        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {:?}", parent))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open audit log: {:?}", path))?;

        let writer = BufWriter::new(file);

        info!("Audit logging enabled, writing to: {}", config.log_path);

        Ok(Self {
            writer: Mutex::new(writer),
            format: config.log_format,
            stdout_mirror: config.log_path == "-" || config.log_path == "stdout",
        })
    }

    /// Log a network event
    pub fn log_network_event(
        &self,
        event: &NetworkEvent,
        container_id: &str,
        resolved_domain: Option<&str>,
    ) -> Result<()> {
        let event_type = match event.event_type {
            1 => "network_connect",
            2 => "network_block",
            _ => "network_unknown",
        };

        let ip = Ipv4Addr::from(event.daddr);
        let protocol = match event.protocol {
            6 => "TCP",
            17 => "UDP",
            _ => "UNKNOWN",
        };

        let audit_event = AuditEvent {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            container_id: container_id.to_string(),
            pid: event.pid,
            uid: event.uid,
            network: Some(NetworkAuditData {
                destination_ip: ip.to_string(),
                destination_port: event.dport,
                protocol: protocol.to_string(),
                resolved_domain: resolved_domain.map(|s| s.to_string()),
            }),
            file: None,
        };

        self.write_event(&audit_event)
    }

    /// Log a file event
    pub fn log_file_event(&self, event: &FileEvent, container_id: &str) -> Result<()> {
        let event_type = match event.event_type {
            3 => "file_open",
            4 => "file_block",
            _ => "file_unknown",
        };

        let path_len = (event.path_len as usize).min(event.path.len());
        let path = String::from_utf8_lossy(&event.path[..path_len]).to_string();

        let operation = if event.flags & libc::O_WRONLY as u32 != 0
            || event.flags & libc::O_RDWR as u32 != 0
        {
            "write"
        } else {
            "read"
        };

        let audit_event = AuditEvent {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            container_id: container_id.to_string(),
            pid: event.pid,
            uid: event.uid,
            network: None,
            file: Some(FileAuditData {
                path,
                operation: operation.to_string(),
            }),
        };

        self.write_event(&audit_event)
    }

    /// Write an event to the log
    fn write_event(&self, event: &AuditEvent) -> Result<()> {
        let line = match self.format {
            LogFormat::Json => {
                serde_json::to_string(event).context("Failed to serialize audit event")?
            }
            LogFormat::Text => {
                format!(
                    "{} [{}] container={} pid={} uid={} {}",
                    event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    event.event_type,
                    event.container_id,
                    event.pid,
                    event.uid,
                    self.format_details(event)
                )
            }
        };

        let mut writer = self.writer.lock().unwrap();
        writeln!(writer, "{}", line)?;
        writer.flush()?;

        if self.stdout_mirror {
            println!("{}", line);
        }

        Ok(())
    }

    fn format_details(&self, event: &AuditEvent) -> String {
        if let Some(ref net) = event.network {
            let domain_info = net
                .resolved_domain
                .as_ref()
                .map(|d| format!(" ({})", d))
                .unwrap_or_default();
            format!(
                "{}:{}/{}{}",
                net.destination_ip, net.destination_port, net.protocol, domain_info
            )
        } else if let Some(ref file) = event.file {
            format!("{} {}", file.operation, file.path)
        } else {
            String::new()
        }
    }
}
