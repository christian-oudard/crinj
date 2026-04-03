mod ca;
mod gateway;
mod inject;
mod local;

use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::ca::CertificateAuthority;
use crate::gateway::GatewayServer;

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

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let cli = Cli::parse();

    let data_dir = resolve_data_dir(cli.data_dir.as_deref());
    let config_path = resolve_config_file(cli.config.as_deref());

    info!(data_dir = %data_dir.display(), "starting crinj");

    let ca = CertificateAuthority::load_or_generate(&data_dir).await?;

    let hosts = local::load(&config_path)?;
    info!(
        config = %config_path.display(),
        host_count = hosts.len(),
        "loaded config (send SIGHUP to reload)"
    );

    info!(port = cli.port, bind = %cli.bind, "ready");

    let server = GatewayServer::new(ca, cli.port, cli.bind, hosts, config_path);
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
