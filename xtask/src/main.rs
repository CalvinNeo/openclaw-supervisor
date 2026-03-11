//! Build helper tasks for openclaw-supervisor
//!
//! This xtask crate provides build helpers for compiling eBPF programs.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask")]
#[command(about = "Build helpers for openclaw-supervisor")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build eBPF programs
    BuildEbpf {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Build everything (eBPF + userspace)
    Build {
        /// Build in release mode
        #[arg(long)]
        release: bool,
    },
    /// Run the supervisor
    Run {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::BuildEbpf { release } => build_ebpf(release),
        Commands::Build { release } => {
            build_ebpf(release)?;
            build_userspace(release)
        }
        Commands::Run { config } => run(config),
    }
}

fn build_ebpf(release: bool) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);

    cmd.current_dir(project_root().join("openclaw-supervisor-ebpf"));

    cmd.args([
        "+nightly",
        "build",
        "--target=bpfel-unknown-none",
        "-Z",
        "build-std=core",
    ]);

    if release {
        cmd.arg("--release");
    }

    // Set required environment variables for eBPF compilation
    cmd.env("RUSTFLAGS", "");

    println!("Building eBPF programs...");
    let status = cmd.status().context("Failed to run cargo build for eBPF")?;

    if !status.success() {
        bail!("eBPF build failed");
    }

    println!("eBPF programs built successfully");
    Ok(())
}

fn build_userspace(release: bool) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);

    cmd.current_dir(project_root());
    cmd.args(["build", "-p", "openclaw-supervisor"]);

    if release {
        cmd.arg("--release");
    }

    println!("Building userspace daemon...");
    let status = cmd.status().context("Failed to run cargo build")?;

    if !status.success() {
        bail!("Userspace build failed");
    }

    println!("Userspace daemon built successfully");
    Ok(())
}

fn run(config: Option<PathBuf>) -> Result<()> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);

    cmd.current_dir(project_root());
    cmd.args(["run", "-p", "openclaw-supervisor", "--"]);

    if let Some(config_path) = config {
        cmd.args(["--config", config_path.to_str().unwrap()]);
    }

    let status = cmd.status().context("Failed to run supervisor")?;

    if !status.success() {
        bail!("Supervisor exited with error");
    }

    Ok(())
}

fn project_root() -> PathBuf {
    let dir = std::env::var("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    PathBuf::from(dir).parent().unwrap().to_path_buf()
}
