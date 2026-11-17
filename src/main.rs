//! MeshVault command line and service entry point.

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use serde_json::{Value, json};
use std::path::PathBuf;

use meshvault::config::Config;
use meshvault::control;
use meshvault::hash::ContentHash;
use meshvault::manifest::{DirEntry, ObjectKind, ObjectSummary};
use meshvault::node::{DirListing, Node, PeerInfo, destination_name, load_identity};
use reticulum_sdk::destination::SingleInputDestination;

#[derive(Parser)]
#[command(
    name = "meshvault",
    version,
    about = "Content-addressed file sharing over Reticulum meshes",
    long_about = "MeshVault stores files by BLAKE3 hash, advertises them to Reticulum \
peers, and fetches files or whole directory trees from the mesh. It runs as a \
local service with a Unix-socket RPC interface."
)]
struct Cli {
    /// Configuration file (default: XDG config directory).
    #[arg(short, long, global = true, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Override the repository/state directory.
    #[arg(long, global = true, value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// Increase log verbosity (-v, -vv).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the service in the foreground.
    Daemon {
        /// Reticulum TCP endpoints to connect to (repeatable).
        #[arg(long = "connect", value_name = "HOST:PORT")]
        connect: Vec<String>,
        /// Reticulum TCP endpoints to listen on (repeatable).
        #[arg(long = "listen", value_name = "HOST:PORT")]
        listen: Vec<String>,
        /// Override the announce interval in seconds.
        #[arg(long)]
        announce_interval: Option<u64>,
        /// Override the maximum number of outbound peer links.
        #[arg(long)]
        max_peers: Option<usize>,
        /// Friendly node name announced to peers.
        #[arg(long)]
        name: Option<String>,
        /// Act as a Reticulum transport node.
        #[arg(long)]
        transport_node: bool,
    },

    /// Create the default configuration and show repository paths.
    Init,

    /// Show daemon and repository status.
    Status,

    /// Print this node's destination and identity hashes.
    Id,

    /// Add a file or directory tree to the local repository.
    Add {
        path: PathBuf,
        /// Override the stored file name.
        #[arg(long)]
        name: Option<String>,
    },

    /// Fetch a file or directory tree by BLAKE3 hash.
    Get {
        hash: String,
        /// Output path (file or directory).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// List local objects, or list a directory by hash.
    Ls { hash: Option<String> },

    /// Remove an object from the local repository.
    Remove { hash: String },

    /// List known peers.
    Peers,

    /// Announce this node immediately.
    Announce,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    let (mut config, paths) = Config::load(cli.config.as_deref(), cli.data_dir.as_deref())?;

    match cli.command {
        Command::Daemon {
            connect,
            listen,
            announce_interval,
            max_peers,
            name,
            transport_node,
        } => {
            if !connect.is_empty() {
                config.interfaces.connect.extend(connect);
            }
            if !listen.is_empty() {
                config.interfaces.listen.extend(listen);
            }
            if let Some(interval) = announce_interval {
                config.announce_interval_secs = interval;
            }
            if let Some(max_peers) = max_peers {
                config.max_peers = max_peers;
            }
            if let Some(name) = name {
                config.name = Some(name);
            }
            if transport_node {
                config.transport_node = true;
            }
            config.validate()?;
            run_daemon(config, paths).await
        }
        Command::Init => {
            let identity_path = paths.data_dir.join("identity.hex");
            println!("config:  {}", paths.config_file.display());
            println!("data:    {}", paths.data_dir.display());
            println!("rpc:     {}", paths.control_socket.display());
            println!(
                "identity: {}",
                if identity_path.exists() {
                    "present"
                } else {
                    "created on first daemon start"
                }
            );
            Ok(())
        }
        Command::Id => {
            let identity = load_identity(&paths.data_dir)?;
            let destination = SingleInputDestination::new(identity.clone(), destination_name());
            println!("identity:    {}", identity.address_hash().to_hex_string());
            println!(
                "destination: {}",
                destination.desc.address_hash.to_hex_string()
            );
            Ok(())
        }
        Command::Status => {
            let mut client = control::client_for(&paths).await?;
            let status = client.call("status", json!({})).await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Command::Add { path, name } => {
            let path = std::fs::canonicalize(&path)
                .with_context(|| format!("resolve {}", path.display()))?;
            let mut client = control::client_for(&paths).await?;
            let result = client
                .call("add", json!({"path": path, "name": name}))
                .await?;
            let object: ObjectSummary = serde_json::from_value(
                result
                    .get("object")
                    .cloned()
                    .context("add response missing object")?,
            )?;
            print_object(&object);
            Ok(())
        }
        Command::Get { hash, output } => {
            let root = ContentHash::from_hex(&hash)?;
            let mut client = control::client_for(&paths).await?;
            let result = client
                .call("get", json!({"hash": root, "output": output}))
                .await?;
            let path = result.get("path").and_then(Value::as_str).unwrap_or("?");
            let bytes = result.get("bytes").and_then(Value::as_u64).unwrap_or(0);
            println!("saved {path} ({})", human_size(bytes));
            Ok(())
        }
        Command::Ls { hash } => {
            let mut client = control::client_for(&paths).await?;
            match hash {
                Some(hash) => {
                    let root = ContentHash::from_hex(&hash)?;
                    let value = client.call("ls", json!({"hash": root})).await?;
                    let listing: DirListing = serde_json::from_value(value)?;
                    println!(
                        "directory {} ({}{})",
                        listing.root,
                        listing.entries.len(),
                        listing
                            .name
                            .as_deref()
                            .map(|name| format!(", {name}"))
                            .unwrap_or_default()
                    );
                    for entry in &listing.entries {
                        print!("  ");
                        print_entry(entry);
                    }
                }
                None => {
                    let value = client.call("ls", json!({})).await?;
                    let objects: Vec<ObjectSummary> = serde_json::from_value(value)?;
                    if objects.is_empty() {
                        println!("repository is empty");
                    }
                    for object in &objects {
                        print_object(object);
                    }
                }
            }
            Ok(())
        }
        Command::Remove { hash } => {
            let root = ContentHash::from_hex(&hash)?;
            let mut client = control::client_for(&paths).await?;
            let removed = client.call("remove", json!({"hash": root})).await?;
            if removed.as_bool().unwrap_or(false) {
                println!("removed {root}");
            } else {
                println!("not found locally: {root}");
            }
            Ok(())
        }
        Command::Peers => {
            let mut client = control::client_for(&paths).await?;
            let value = client.call("peers", json!({})).await?;
            let peers: Vec<PeerInfo> = serde_json::from_value(value)?;
            if peers.is_empty() {
                println!("no peers discovered yet");
            } else {
                println!(
                    "{:<8} {:<5} {:<8} {:<10} DESTINATION",
                    "STATE", "HOPS", "OBJECTS", "SNR"
                );
                for peer in peers {
                    println!(
                        "{:<8} {:<5} {:<8} {:<10} {}{}",
                        if peer.connected { "linked" } else { "known" },
                        peer.hops,
                        peer.objects,
                        peer.snr
                            .map(|snr| format!("{snr:.1}"))
                            .unwrap_or_else(|| "-".into()),
                        peer.address,
                        peer.name
                            .as_deref()
                            .map(|name| format!("  ({name})"))
                            .unwrap_or_default()
                    );
                }
            }
            Ok(())
        }
        Command::Announce => {
            let mut client = control::client_for(&paths).await?;
            client.call("announce", json!({})).await?;
            println!("announce queued");
            Ok(())
        }
    }
}

async fn run_daemon(config: Config, paths: meshvault::config::Paths) -> Result<()> {
    let node = Node::start(config, paths.clone()).await?;
    log::info!(
        "node ready: destination {} identity {}",
        node.destination_hash().to_hex_string(),
        node.identity_hash().to_hex_string()
    );
    log::info!("control socket: {}", paths.control_socket.display());

    let socket = paths.control_socket.clone();
    let rpc_node = node.clone();
    tokio::spawn(async move {
        if let Err(err) = control::serve(rpc_node, &socket).await {
            log::error!("RPC server failed: {err:#}");
        }
    });

    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("install SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("wait for Ctrl-C")?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")?;

    log::info!("shutting down");
    Ok(())
}

fn init_logging(verbosity: u8) {
    let default = match verbosity {
        0 => "meshvault=info,reticulum_sdk=warn",
        1 => "meshvault=debug,reticulum_sdk=info",
        _ => "debug",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default))
        .format_timestamp_secs()
        .init();
}

fn print_object(object: &ObjectSummary) {
    print!(
        "{:<10} {}  {:<9} {}",
        kind_label(object.kind()),
        object.root(),
        human_size(object.size()),
        meshvault::store::sanitize_name(&object.display_name())
            .unwrap_or_else(|| object.root().short())
    );
    if let ObjectSummary::Directory(dir) = object {
        println!("  ({} entries)", dir.entries);
    } else {
        println!();
    }
}

fn print_entry(entry: &DirEntry) {
    println!(
        "{:<10} {}  {:<9} {}",
        kind_label(entry.kind),
        entry.hash,
        human_size(entry.size),
        meshvault::store::sanitize_name(&entry.name).unwrap_or_else(|| entry.name.clone())
    );
}

fn kind_label(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::File => "file",
        ObjectKind::Directory => "directory",
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
