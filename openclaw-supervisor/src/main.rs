//! OpenClaw Supervisor Daemon
//!
//! Main entry point for the userspace daemon that manages eBPF programs
//! for container network and filesystem access control.

mod audit;
mod bpf;
mod config;
mod dns;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::bpf::BpfManager;
use crate::config::{Config, ConfigWatcher};

#[derive(Parser, Debug)]
#[command(name = "openclaw-supervisor")]
#[command(about = "eBPF-based container access control supervisor")]
#[command(version)]
struct Args {
    /// Path to configuration file
    #[arg(short, long, default_value = "/etc/openclaw-supervisor/config.yaml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Run in foreground (don't daemonize)
    #[arg(short, long)]
    foreground: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("OpenClaw Supervisor starting...");

    // Load configuration
    let config = Config::load(&args.config)
        .with_context(|| format!("Failed to load config from {:?}", args.config))?;

    info!(
        "Loaded configuration with {} containers",
        config.containers.len()
    );

    // Initialize audit logger if enabled
    let audit_logger = if config.audit.enabled {
        Some(
            audit::AuditLogger::new(&config.audit)
                .context("Failed to initialize audit logger")?,
        )
    } else {
        None
    };

    // Initialize BPF manager
    let mut bpf_manager = BpfManager::new(audit_logger)
        .await
        .context("Failed to initialize BPF manager")?;

    // Apply initial configuration
    bpf_manager
        .apply_config(&config)
        .await
        .context("Failed to apply initial configuration")?;

    info!("BPF programs loaded and configured");

    // Start config file watcher for hot-reload
    let config_path = args.config.clone();
    let (config_tx, mut config_rx) = tokio::sync::mpsc::channel::<Config>(1);

    let watcher_handle = tokio::spawn(async move {
        if let Err(e) = ConfigWatcher::watch(config_path, config_tx).await {
            warn!("Config watcher error: {}", e);
        }
    });

    // Main event loop
    info!("Supervisor ready, entering main loop");

    loop {
        tokio::select! {
            // Handle config updates
            Some(new_config) = config_rx.recv() => {
                info!("Configuration changed, applying updates...");
                if let Err(e) = bpf_manager.apply_config(&new_config).await {
                    warn!("Failed to apply config update: {}", e);
                } else {
                    info!("Configuration updated successfully");
                }
            }

            // Handle BPF events
            event = bpf_manager.next_event() => {
                if let Some(event) = event {
                    bpf_manager.handle_event(event).await;
                }
            }

            // Handle shutdown signals
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
        }
    }

    info!("Shutting down...");
    watcher_handle.abort();
    bpf_manager.cleanup().await?;

    info!("Goodbye!");
    Ok(())
}
