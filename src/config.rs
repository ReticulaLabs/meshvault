//! Configuration and well-known paths.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};

use crate::manifest::{MAX_PIECE_SIZE, MIN_PIECE_SIZE};

pub const APP_NAME: &str = "meshvault";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Override the repository/state directory.
    pub data_dir: Option<PathBuf>,
    /// Override the local RPC socket path.
    pub control_socket: Option<PathBuf>,

    /// Friendly node name announced to peers (optional).
    pub name: Option<String>,

    /// How often to announce this node on the mesh.
    pub announce_interval_secs: u64,
    /// Maximum number of outbound peer links.
    pub max_peers: usize,
    /// Maximum total links (inbound + outbound).
    pub max_links: usize,
    /// Maximum peer records retained (connected or discovered).
    pub max_known_peers: usize,

    /// Piece size used when importing files. Hashes in manifests depend on
    /// this value.
    pub piece_size: u32,
    /// Largest chunk requested in one transfer message.
    pub max_chunk_bytes: u64,
    /// How long `get` waits for a peer/inventory to show up.
    pub fetch_wait_secs: u64,
    /// Abort a fetch after this long without verified progress.
    pub fetch_stall_timeout_secs: u64,
    /// Maximum number of peers used in parallel for one file fetch.
    pub fetch_parallelism: usize,
    /// Maximum inventory entries accepted from one peer.
    pub max_inventory_objects: usize,
    /// Maximum inventory entries retained across all peers.
    pub max_inventory_objects_total: usize,
    /// Maximum directory entries visited by one recursive get or pin.
    pub max_extract_entries: usize,
    /// Maximum file bytes materialized by one recursive get.
    pub max_extract_bytes: u64,
    /// Process-wide budget for inbound reassembly buffers.
    pub max_inbound_memory_bytes: u64,
    /// Sustained per-peer service bandwidth (bytes/second).
    pub peer_service_bytes_per_sec: u64,
    /// Per-peer service burst allowance (bytes).
    pub peer_service_burst_bytes: u64,
    /// Keep and advertise files fetched from the mesh by `get`.  `pin`
    /// always retains its content regardless of this setting.
    pub cache_fetched: bool,

    /// Participate in Reticulum transport (forward other nodes' traffic).
    pub transport_node: bool,

    /// Use Reticulum link-MTU discovery.  Disabled by default because the
    /// interoperable 500-byte MTU is reliable across every interface; enable
    /// only if every peer in the mesh supports larger link packets.
    pub link_mtu_discovery: bool,

    pub interfaces: Interfaces,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Interfaces {
    /// Reticulum TCP endpoints to connect to, e.g. `["127.0.0.1:4242"]`.
    pub connect: Vec<String>,
    /// Local Reticulum TCP endpoints to listen on, e.g. `["0.0.0.0:4243"]`.
    pub listen: Vec<String>,
    /// Optional bitrate applied to all configured TCP interfaces (bps).
    pub assumed_bitrate_bps: Option<f64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: None,
            control_socket: None,
            name: None,
            announce_interval_secs: 1800,
            max_peers: 8,
            max_links: 64,
            max_known_peers: 512,
            piece_size: crate::manifest::DEFAULT_PIECE_SIZE,
            max_chunk_bytes: 1024 * 1024,
            fetch_wait_secs: 20,
            fetch_stall_timeout_secs: 3600,
            fetch_parallelism: 4,
            max_inventory_objects: 16_384,
            max_inventory_objects_total: 65_536,
            max_extract_entries: 100_000,
            max_extract_bytes: 10 * 1024 * 1024 * 1024,
            max_inbound_memory_bytes: 64 * 1024 * 1024,
            peer_service_bytes_per_sec: 4 * 1024 * 1024,
            peer_service_burst_bytes: 8 * 1024 * 1024,
            cache_fetched: true,
            transport_node: false,
            link_mtu_discovery: false,
            interfaces: Interfaces::default(),
        }
    }
}

#[derive(Clone)]
pub struct Paths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
    pub control_socket: PathBuf,
}

impl Config {
    /// Load configuration, creating a commented default file on first use.
    pub fn load(
        explicit_config: Option<&Path>,
        data_override: Option<&Path>,
    ) -> Result<(Self, Paths)> {
        let default_config = default_config_path()?;
        let config_file = explicit_config
            .map(Path::to_path_buf)
            .unwrap_or(default_config);

        if !config_file.exists() {
            if let Some(parent) = config_file.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            fs::write(&config_file, DEFAULT_CONFIG_TOML)
                .with_context(|| format!("write default config {}", config_file.display()))?;
            log::info!("wrote default configuration to {}", config_file.display());
        }

        let config_file = fs::canonicalize(&config_file).unwrap_or(config_file);
        let text = fs::read_to_string(&config_file)
            .with_context(|| format!("read config {}", config_file.display()))?;
        let mut config: Config = toml::from_str(&text)
            .with_context(|| format!("parse config {}", config_file.display()))?;
        config.normalize_paths(&config_file)?;

        if let Some(data_dir) = data_override {
            config.data_dir = Some(data_dir.to_path_buf());
        }
        let data_dir = config.data_dir.clone().unwrap_or_else(default_data_dir);
        let control_socket = config
            .control_socket
            .clone()
            .unwrap_or_else(|| data_dir.join("control.sock"));
        if control_socket.to_string_lossy().len() > 100 {
            bail!(
                "control socket path is too long for a Unix socket: {} (set control_socket to a shorter path)",
                control_socket.display()
            );
        }

        config.validate()?;

        let paths = Paths {
            config_file,
            data_dir,
            control_socket,
        };
        Ok((config, paths))
    }

    fn normalize_paths(&mut self, config_file: &Path) -> Result<()> {
        let base = config_file.parent().unwrap_or_else(|| Path::new("."));
        if let Some(data_dir) = &self.data_dir
            && data_dir.is_relative()
        {
            self.data_dir = Some(base.join(data_dir));
        }
        if let Some(socket) = &self.control_socket
            && socket.is_relative()
        {
            self.control_socket = Some(base.join(socket));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.announce_interval_secs < 900 {
            bail!("announce_interval_secs must be at least 900");
        }
        if self.max_peers == 0 {
            bail!("max_peers must be at least 1");
        }
        if self.max_links == 0 || self.max_links < self.max_peers {
            bail!("max_links must be at least max_peers");
        }
        if self.max_known_peers < self.max_peers {
            bail!("max_known_peers must be at least max_peers");
        }
        if self.max_known_peers > 1_000_000 {
            bail!("max_known_peers is unreasonably large");
        }
        if self.max_inventory_objects == 0
            || self.max_inventory_objects_total < self.max_inventory_objects
        {
            bail!("max_inventory_objects_total must be at least max_inventory_objects");
        }
        if self.max_inventory_objects_total > 4_000_000 {
            bail!("max_inventory_objects_total is unreasonably large");
        }
        if self.fetch_stall_timeout_secs < 60 {
            bail!("fetch_stall_timeout_secs must be at least 60");
        }
        if self.max_extract_entries == 0 || self.max_extract_bytes == 0 {
            bail!("max_extract_entries and max_extract_bytes must be positive");
        }
        if !(4 * 1024 * 1024..=1024 * 1024 * 1024).contains(&self.max_inbound_memory_bytes) {
            bail!("max_inbound_memory_bytes must be between 4 MiB and 1 GiB");
        }
        if !(16 * 1024..=1024 * 1024 * 1024).contains(&self.peer_service_bytes_per_sec) {
            bail!("peer_service_bytes_per_sec must be between 16 KiB/s and 1 GiB/s");
        }
        if !(1024 * 1024..=1024 * 1024 * 1024).contains(&self.peer_service_burst_bytes) {
            bail!("peer_service_burst_bytes must be between 1 MiB and 1 GiB");
        }
        if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&self.piece_size) {
            bail!("piece_size must be between {MIN_PIECE_SIZE} and {MAX_PIECE_SIZE}");
        }
        if self.max_chunk_bytes < self.piece_size as u64 {
            bail!("max_chunk_bytes must be at least piece_size");
        }
        if self
            .name
            .as_ref()
            .is_some_and(|name| name.chars().count() > 64)
        {
            bail!("name must be at most 64 characters");
        }
        if let Some(bitrate) = self.interfaces.assumed_bitrate_bps
            && (!bitrate.is_finite() || bitrate <= 0.0)
        {
            bail!("interfaces.assumed_bitrate_bps must be a positive number");
        }
        Ok(())
    }

    pub fn control_socket(&self, data_dir: &Path) -> PathBuf {
        self.control_socket
            .clone()
            .unwrap_or_else(|| data_dir.join("control.sock"))
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", APP_NAME)
        .context("cannot determine user configuration directory")?;
    Ok(dirs.config_dir().join("config.toml"))
}

pub fn default_data_dir() -> PathBuf {
    ProjectDirs::from("", "", APP_NAME)
        .map(|dirs| dirs.data_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".").join(".meshvault"))
}

pub const DEFAULT_CONFIG_TOML: &str = r#"# MeshVault configuration
#
# MeshVault runs as a local service.  It connects to one or more Reticulum
# transport nodes, announces a `meshvault.node` destination, and exposes a
# local RPC socket for adding/listing/removing files and fetching content from
# the mesh.

# Repository and identity live here.  Relative paths are resolved against
# this configuration file's directory.  Defaults to the XDG data directory.
# data_dir = "/var/lib/meshvault"

# Friendly name shown by peers (optional).
# name = "my-node"

# Local RPC socket.  Defaults to <data_dir>/control.sock.
# control_socket = "/run/user/1000/meshvault.sock"

# Reticulum announce cadence in seconds (minimum 900).
announce_interval_secs = 1800

# Maximum outbound peer links, and maximum links in total.
max_peers = 8
max_links = 64

# Maximum peer records retained. Stale disconnected peers are evicted.
max_known_peers = 512

# Inventory caps. Peers with larger inventories will not be fully synced;
# raise these for repositories with many files.
max_inventory_objects = 16384
max_inventory_objects_total = 65536

# Recursive directory extraction limits (one `get` operation).
max_extract_entries = 100000
max_extract_bytes = 10737418240

# Process-wide budget for inbound message reassembly. Individual links are
# additionally capped at 4 MiB in flight.
max_inbound_memory_bytes = 67108864

# Per-peer service limits for inventory, manifests, directories, and chunks.
# Requests are charged an estimated response cost; exhausted peers receive 429.
peer_service_bytes_per_sec = 4194304
peer_service_burst_bytes = 8388608

# Files are stored as fixed-size hashed pieces.  16 KiB is a good default for
# mixed LAN/LoRa meshes.
piece_size = 16384

# Upper bound for one adaptive transfer chunk (bytes).
max_chunk_bytes = 1048576

# How long `meshvault get` and `meshvault pin` wait for a peer to advertise
# the requested hash.
fetch_wait_secs = 20

# Abort a fetch after this many seconds without verified progress.
fetch_stall_timeout_secs = 3600

# Fetch one file from up to this many peers in parallel.  Set to 1 to disable
# multi-source fetching.
fetch_parallelism = 4

# Keep files fetched by `get` and advertise them to other peers.  `pin` always
# keeps and advertises its content regardless of this setting.
cache_fetched = true

# Act as a Reticulum transport node (forward traffic for other nodes).
transport_node = false

# Link-MTU discovery can use larger packets on fast links, but larger link
# packets are not reliable on every Reticulum interface/version.  Leave this
# off for maximum interoperability; enables better throughput on a controlled
# all-modern mesh.
link_mtu_discovery = false

[interfaces]
# Reticulum TCP endpoints to connect to.  Repeat as needed.
# connect = ["127.0.0.1:4242"]
connect = []

# Local Reticulum TCP listeners.  Share this port with nearby mesh nodes.
# listen = ["0.0.0.0:4243"]
listen = []

# Optional fixed bitrate for the TCP interfaces above.  When omitted,
# MeshVault measures throughput itself and adapts chunk sizes.
# assumed_bitrate_bps = 1000000
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_parses() {
        let config: Config = toml::from_str(DEFAULT_CONFIG_TOML).unwrap();
        config.validate().unwrap();
        assert_eq!(config.piece_size, 16 * 1024);
    }

    #[test]
    fn relative_data_dir_is_resolved() {
        let mut config = Config {
            data_dir: Some(PathBuf::from("repo")),
            ..Default::default()
        };
        config
            .normalize_paths(Path::new("/etc/meshvault/config.toml"))
            .unwrap();
        assert_eq!(
            config.data_dir.unwrap(),
            PathBuf::from("/etc/meshvault/repo")
        );
    }
}
