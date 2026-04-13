mod ca;
mod gateway;
mod inject;
mod local;

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::ca::CertificateAuthority;
use crate::gateway::{GatewayServer, UpstreamProxy};

#[derive(Parser)]
#[command(
    name = "crinj",
    about = "Local MITM proxy for credential injection"
)]
struct Cli {
    /// Port to listen on.
    #[arg(long, default_value = "10255")]
    port: u16,

    /// Address to bind to.
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Data directory for CA certificates.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Path to the config TOML file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Permit starting with zero host rules. Without this flag, an empty
    /// config is rejected because it would tunnel all traffic unchanged.
    #[arg(long)]
    allow_empty_rules: bool,

    /// Write log output to a file instead of stderr.
    #[arg(long)]
    log_file: Option<PathBuf>,
}

// ── XDG path resolution ─────────────────────────────────────────────────

fn resolve_data_dir(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    let legacy = expand_tilde(Path::new("~/.crinj"));
    if legacy.is_dir() {
        return legacy;
    }
    xdg_data_home().join("crinj")
}

fn resolve_config_file(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    let legacy = expand_tilde(Path::new("~/.crinj/rules.toml"));
    if legacy.is_file() {
        return legacy;
    }
    xdg_config_home().join("crinj").join("rules.toml")
}

fn xdg_data_home() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| expand_tilde(Path::new("~/.local/share")))
}

fn xdg_config_home() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| expand_tilde(Path::new("~/.config")))
}

// ── main ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider");

    let cli = Cli::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if let Some(ref log_file) = cli.log_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_file)
            .with_context(|| format!("opening log file {}", log_file.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(file)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    let data_dir = resolve_data_dir(cli.data_dir.as_deref());
    let config_path = resolve_config_file(cli.config.as_deref());

    info!(data_dir = %data_dir.display(), "starting crinj");

    let ca = CertificateAuthority::load_or_generate(&data_dir).await?;

    let upstream_proxy = UpstreamProxy::from_env()?;
    if let Some(ref p) = upstream_proxy {
        info!(addr = %p.addr(), "upstream proxy: routing outbound CONNECT through parent");
    }

    let hosts = local::load(&config_path)?;
    if hosts.is_empty() && !cli.allow_empty_rules {
        bail!(
            "config {} has no host rules. Refusing to start: this would tunnel \
             all traffic unchanged. If that is intended, pass --allow-empty-rules.",
            config_path.display()
        );
    }
    info!(
        config = %config_path.display(),
        host_count = hosts.len(),
        "loaded config (send SIGHUP to reload)"
    );
    if hosts.is_empty() {
        info!(
            config = %config_path.display(),
            "starting in passthrough mode: --allow-empty-rules set and config has no rules; all traffic will tunnel through unchanged"
        );
    }

    info!(port = cli.port, bind = %cli.bind, "ready");

    let server = GatewayServer::new(
        ca,
        cli.port,
        cli.bind,
        hosts,
        config_path,
        cli.allow_empty_rules,
        upstream_proxy,
    );
    server.run().await
}

/// Expand `~` at the start of a path to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s.starts_with("~/") || s == "~" {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(s.strip_prefix("~/").unwrap_or(""));
        }
    }
    path.to_path_buf()
}
