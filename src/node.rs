//! MeshVault node: Reticulum service, peer manager, inventory sync, transfer.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use fs2::FileExt;

use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info, warn};
use reticulum_sdk::destination::link::{LinkEvent, LinkId};
use reticulum_sdk::destination::{
    DestinationDesc, DestinationName, SingleInputDestination, SingleOutputDestination,
};
use reticulum_sdk::hash::AddressHash;
use reticulum_sdk::identity::{Identity, PrivateIdentity};
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::transport::{AnnounceEvent, Transport, TransportConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, mpsc};

use crate::config::{Config, Paths};
use crate::fetch::PieceProgress;
use crate::hash::ContentHash;
use crate::limits::{MIN_REQUEST_COST, ServiceLimiter};
use crate::manifest::{
    DirEntry, DirManifest, DirSummary, Manifest, ManifestSummary, ObjectKind, ObjectSummary,
};
use crate::session::{Incoming, LinkSession, MAX_LINK_MTU, MemoryBudget, PeerHello};
use crate::store::{MAX_PIECES_PER_REQUEST, Store, sanitize_name};
use crate::wire::{
    CHUNK_HEADER_LEN, ChunkMessage, Control, INVENTORY_PAGE_SIZE, NodeAnnounce, PROTOCOL_VERSION,
};

const IDENTITY_FILE: &str = "identity.hex";
const DAEMON_LOCK_FILE: &str = "daemon.lock";
const ANNOUNCE_PAYLOAD_LIMIT: usize = 280;
const MAX_DIRECTORY_DEPTH: usize = 64;
const SESSION_INCOMING_QUEUE: usize = 32;
const PEER_RETENTION: Duration = Duration::from_secs(60 * 60);

/// Set when the local RPC client disconnects, aborting in-flight fetches.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, AtomicOrdering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(AtomicOrdering::Relaxed)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProgressEvent {
    pub stage: String,
    pub message: String,
    pub current: Option<u64>,
    pub total: Option<u64>,
}

pub type ProgressSender = tokio::sync::mpsc::Sender<ProgressEvent>;

#[derive(Clone, Copy)]
struct TransferControl<'a> {
    cancel: &'a CancelToken,
    progress: Option<&'a ProgressSender>,
}

fn send_progress(
    sender: Option<&ProgressSender>,
    stage: &str,
    message: impl Into<String>,
    current: Option<u64>,
    total: Option<u64>,
) {
    if let Some(sender) = sender {
        let _ = sender.try_send(ProgressEvent {
            stage: stage.to_string(),
            message: message.into(),
            current,
            total,
        });
    }
}

struct ExtractionBudget {
    entries: usize,
    bytes: u64,
}

impl ExtractionBudget {
    fn new(entries: usize, bytes: u64) -> Self {
        Self { entries, bytes }
    }

    fn consume_entry(&mut self) -> Result<()> {
        if self.entries == 0 {
            bail!("directory extraction entry budget exhausted");
        }
        self.entries -= 1;
        Ok(())
    }

    fn consume_bytes(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.bytes {
            bail!("directory extraction byte budget exhausted");
        }
        self.bytes -= bytes;
        Ok(())
    }
}

pub fn destination_name() -> DestinationName {
    DestinationName::new("meshvault", "node")
}

fn clean_name(name: Option<String>) -> Option<String> {
    name.map(|name| {
        name.chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect::<String>()
    })
    .filter(|name| !name.is_empty())
}

fn ensure_peer_slot(
    peers: &mut HashMap<AddressHash, PeerState>,
    address: AddressHash,
    limit: usize,
) -> bool {
    if peers.contains_key(&address) || peers.len() < limit {
        return true;
    }
    let victim = peers
        .values()
        .filter(|peer| peer.link.is_none())
        .min_by_key(|peer| peer.last_seen)
        .map(|peer| peer.address);
    match victim {
        Some(victim) => {
            peers.remove(&victim);
            true
        }
        None => false,
    }
}

/// Held for the daemon's lifetime.  The OS releases the lock on process exit.
struct DataDirLock {
    _file: fs::File,
}

impl DataDirLock {
    fn acquire(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(DAEMON_LOCK_FILE);
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("open daemon lock {}", path.display()))?;
        file.try_lock_exclusive().map_err(|err| {
            anyhow!(
                "another meshvault daemon is already running for {} ({err})",
                data_dir.display()
            )
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("secure daemon lock {}", path.display()))?;
        }
        file.set_len(0).context("truncate daemon lock")?;
        writeln!(file, "{}", std::process::id()).context("write daemon lock pid")?;
        file.sync_data().context("sync daemon lock")?;
        Ok(Self { _file: file })
    }
}

struct HelloPayload {
    version: u8,
    dest: String,
    identity: String,
    name: Option<String>,
    objects: u32,
    inventory: ContentHash,
}

#[derive(Clone)]
struct PeerState {
    address: AddressHash,
    desc: Option<DestinationDesc>,
    identity: Option<Identity>,
    identity_hash: Option<AddressHash>,
    name: Option<String>,
    hops: u8,
    snr: Option<f32>,
    rssi: Option<i16>,
    last_seen: Instant,
    link: Option<LinkId>,
    verified: bool,
    inventory_digest: Option<ContentHash>,
    objects: u32,
    inventory: HashMap<ContentHash, ObjectSummary>,
    inventory_synced: bool,
    service: Arc<ServiceLimiter>,
    last_error: Option<String>,
}

impl PeerState {
    fn new(address: AddressHash, service_rate: u64, service_burst: u64) -> Self {
        Self {
            address,
            desc: None,
            identity: None,
            identity_hash: None,
            name: None,
            hops: 0,
            snr: None,
            rssi: None,
            last_seen: Instant::now(),
            link: None,
            verified: false,
            inventory_digest: None,
            objects: 0,
            inventory: HashMap::new(),
            inventory_synced: false,
            service: Arc::new(ServiceLimiter::new(service_rate, service_burst)),
            last_error: None,
        }
    }

    fn object_summary(&self, root: ContentHash) -> Option<&ObjectSummary> {
        self.inventory.get(&root)
    }

    fn info(&self) -> PeerInfo {
        PeerInfo {
            address: self.address.to_hex_string(),
            name: self.name.clone(),
            hops: self.hops,
            snr: self.snr,
            rssi: self.rssi,
            connected: self.link.is_some(),
            verified: self.verified,
            objects: self.objects,
            inventory_synced: self.inventory_synced,
            inventory: self.inventory_digest.map(|hash| hash.to_hex()),
            last_seen_secs: self.last_seen.elapsed().as_secs(),
            link: self.link.map(|id| id.to_hex_string()),
            last_error: self.last_error.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInfo {
    pub address: String,
    pub name: Option<String>,
    pub hops: u8,
    pub snr: Option<f32>,
    pub rssi: Option<i16>,
    pub connected: bool,
    pub verified: bool,
    pub objects: u32,
    pub inventory_synced: bool,
    pub inventory: Option<String>,
    pub last_seen_secs: u64,
    pub link: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceInfo {
    pub root: ContentHash,
    /// Known holders: the local store plus linked peers advertising the object.
    pub copies: usize,
    pub remote_copies: usize,
    pub local: bool,
    pub sources: Vec<SourceEntry>,
    /// Linked peers whose inventories have not been synchronized yet, so the
    /// copy count is a lower bound.
    pub unknown_peers: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceEntry {
    pub local: bool,
    /// Peer destination hash, absent for the local copy.
    pub address: Option<String>,
    /// Friendly node name from the peer's announce, if any.
    pub node_name: Option<String>,
    pub hops: Option<u8>,
    pub snr: Option<f32>,
    pub rssi: Option<i16>,
    pub object: ObjectSummary,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub name: Option<String>,
    pub destination: String,
    pub identity: String,
    pub data_dir: String,
    pub config_file: String,
    pub control_socket: String,
    pub uptime_secs: u64,
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    pub inventory: String,
    pub peers_known: usize,
    pub peers_connected: usize,
    pub links: usize,
    pub outbound_links: usize,
    pub inbound_buffer_bytes: usize,
    pub inbound_buffer_limit: usize,
    pub known_peer_limit: usize,
    pub inventory_object_limit: usize,
    pub peer_service_bytes_per_sec: u64,
    pub peer_service_burst_bytes: u64,
    pub transport_node: bool,
    pub connect: Vec<String>,
    pub listen: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddResult {
    pub object: ObjectSummary,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FetchResult {
    pub object: ObjectSummary,
    pub path: PathBuf,
    pub bytes: u64,
    pub resumed: bool,
    /// Peers that contributed data to this fetch.
    pub sources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GetResult {
    pub object: ObjectSummary,
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DirListing {
    pub root: ContentHash,
    pub name: Option<String>,
    pub entries: Vec<DirEntry>,
}

#[derive(Clone, Debug)]
struct FetchCandidate {
    peer: AddressHash,
    link: LinkId,
    hops: u8,
    snr: Option<f32>,
    manifest_hash: ContentHash,
}

struct SharedFetch {
    manifest: Manifest,
    progress: Arc<StdMutex<PieceProgress>>,
    progress_tx: Option<ProgressSender>,
    label: String,
}

#[derive(Default)]
struct WorkerStats {
    chunks: u64,
    bytes: u64,
}

pub struct Node {
    pub config: Config,
    pub paths: Paths,
    pub identity: PrivateIdentity,
    pub destination: Arc<Mutex<SingleInputDestination>>,
    pub transport: Transport,
    pub store: Arc<Store>,
    memory_budget: Arc<MemoryBudget>,
    _daemon_lock: DataDirLock,
    destination_hash: AddressHash,
    started_at: Instant,
    peers: Mutex<HashMap<AddressHash, PeerState>>,
    sessions: Mutex<HashMap<LinkId, Arc<LinkSession>>>,
    session_tasks: Mutex<HashMap<LinkId, tokio::task::JoinHandle<()>>>,
    connecting: Mutex<HashMap<AddressHash, Instant>>,
    link_peers: Mutex<HashMap<LinkId, AddressHash>>,
    syncing: Mutex<HashSet<LinkId>>,
    fetch_locks: Mutex<HashMap<ContentHash, Arc<Mutex<()>>>>,
    handshake_lock: Mutex<()>,
    announce_now: Notify,
    inventory_changed: Notify,
}

impl Node {
    pub async fn start(config: Config, paths: Paths) -> Result<Arc<Self>> {
        fs::create_dir_all(&paths.data_dir)
            .with_context(|| format!("create data directory {}", paths.data_dir.display()))?;
        let daemon_lock = DataDirLock::acquire(&paths.data_dir)?;
        let identity = load_identity(&paths.data_dir)?;
        let store = Arc::new(Store::open(&paths.data_dir)?);
        let memory_budget = Arc::new(MemoryBudget::new(config.max_inbound_memory_bytes as usize));

        let mut transport_config =
            TransportConfig::new("meshvault", &identity, config.transport_node);
        transport_config.set_event_channel_capacity(16_384);
        transport_config.set_restart_outlinks(true);
        transport_config.set_link_mtu_discovery(config.link_mtu_discovery);
        let mut transport = Transport::new(transport_config);

        for address in &config.interfaces.listen {
            let mut server = TcpServer::new(address.clone(), transport.iface_manager())
                .with_name(format!("listen-{address}"));
            if let Some(bitrate) = config.interfaces.assumed_bitrate_bps {
                server = server.with_bitrate(bitrate);
            }
            let iface = transport
                .iface_manager()
                .lock()
                .await
                .spawn(server, TcpServer::spawn);
            info!("listening on Reticulum TCP {address} ({iface})");
        }
        for address in &config.interfaces.connect {
            let mut client =
                TcpClient::new(address.clone()).with_name(format!("connect-{address}"));
            if let Some(bitrate) = config.interfaces.assumed_bitrate_bps {
                client = client.with_bitrate(bitrate);
            }
            let iface = transport
                .iface_manager()
                .lock()
                .await
                .spawn(client, TcpClient::spawn);
            info!("connecting to Reticulum TCP {address} ({iface})");
        }
        if config.interfaces.listen.is_empty() && config.interfaces.connect.is_empty() {
            warn!("no Reticulum interfaces configured; node will be isolated");
        }

        let destination = transport
            .add_destination(identity.clone(), destination_name())
            .await;
        let destination_hash = destination.lock().await.desc.address_hash;

        let node = Arc::new(Self {
            config,
            paths,
            identity,
            destination,
            transport,
            store,
            memory_budget,
            _daemon_lock: daemon_lock,
            destination_hash,
            started_at: Instant::now(),
            peers: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            session_tasks: Mutex::new(HashMap::new()),
            connecting: Mutex::new(HashMap::new()),
            link_peers: Mutex::new(HashMap::new()),
            syncing: Mutex::new(HashSet::new()),
            fetch_locks: Mutex::new(HashMap::new()),
            handshake_lock: Mutex::new(()),
            announce_now: Notify::new(),
            inventory_changed: Notify::new(),
        });
        node.spawn_tasks();
        Ok(node)
    }

    fn spawn_tasks(self: &Arc<Self>) {
        tokio::spawn(announce_loop(self.clone()));
        tokio::spawn(announce_listener(self.clone()));
        tokio::spawn(link_event_loop(self.clone(), false));
        tokio::spawn(link_event_loop(self.clone(), true));
        tokio::spawn(reconnect_loop(self.clone()));
        tokio::spawn(inventory_broadcast_loop(self.clone()));
    }

    pub fn destination_hash(&self) -> AddressHash {
        self.destination_hash
    }

    pub fn identity_hash(&self) -> AddressHash {
        *self.identity.address_hash()
    }

    async fn hello(&self) -> Result<Control> {
        let dest = self.destination.lock().await.desc.address_hash;
        Ok(Control::Hello {
            version: PROTOCOL_VERSION,
            dest: dest.to_hex_string(),
            identity: self.identity.address_hash().to_hex_string(),
            name: self.config.name.clone(),
            objects: (self.store.file_count() + self.store.dir_count()) as u32,
            inventory: self.store.inventory_digest(),
        })
    }

    async fn announce_payload(&self) -> Result<Vec<u8>> {
        let dest = self.destination.lock().await.desc.address_hash;
        let mut payload = NodeAnnounce {
            version: PROTOCOL_VERSION,
            dest: dest.to_hex_string(),
            identity: self.identity.address_hash().to_hex_string(),
            name: clean_name(self.config.name.clone()),
            objects: (self.store.file_count() + self.store.dir_count()) as u32,
            inventory: self.store.inventory_digest(),
        };
        let mut bytes = payload.encode()?;
        if bytes.len() > ANNOUNCE_PAYLOAD_LIMIT {
            payload.name = None;
            bytes = payload.encode()?;
        }
        if bytes.len() > ANNOUNCE_PAYLOAD_LIMIT {
            bail!("announce payload exceeds size limit");
        }
        Ok(bytes)
    }

    pub async fn announce(&self) {
        match self.announce_payload().await {
            Ok(payload) => {
                self.transport
                    .send_announce(&self.destination, Some(&payload))
                    .await;
                debug!(
                    "announced destination {}",
                    self.destination_hash().to_hex_string()
                );
            }
            Err(err) => warn!("cannot announce: {err:#}"),
        }
    }

    pub fn request_announce(&self) {
        self.announce_now.notify_one();
    }

    fn notify_inventory_changed(&self) {
        self.inventory_changed.notify_one();
    }

    // ─── Public repository operations ──────────────────────────────────────

    pub fn list_local(&self) -> Vec<ObjectSummary> {
        self.store.root_inventory()
    }

    pub fn list_all(&self) -> Vec<ObjectSummary> {
        self.store.inventory()
    }

    pub async fn add_path(&self, path: PathBuf, name: Option<String>) -> Result<AddResult> {
        let metadata = fs::metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        let store = self.store.clone();
        let piece_size = self.config.piece_size;

        let object = if metadata.is_dir() {
            let path = path.clone();
            let mut summary =
                tokio::task::spawn_blocking(move || store.import_dir(&path, piece_size))
                    .await
                    .context("import task panicked")??;
            if let Some(name) = name {
                self.store.set_dir_name(summary.root, Some(name.clone()))?;
                summary.name = Some(name);
            }
            ObjectSummary::Directory(summary)
        } else if metadata.is_file() {
            let path = path.clone();
            let manifest =
                tokio::task::spawn_blocking(move || store.import_file(&path, piece_size, name))
                    .await
                    .context("import task panicked")??;
            ObjectSummary::File(manifest.summary()?)
        } else {
            bail!("{} is not a regular file or directory", path.display());
        };

        self.notify_inventory_changed();
        Ok(AddResult { object, path })
    }

    pub async fn remove(&self, root: ContentHash, recursive: bool) -> Result<bool> {
        let store = self.store.clone();
        let removed = tokio::task::spawn_blocking(move || {
            if recursive {
                store.remove_tree(root).map(|removed| removed > 0)
            } else {
                store.remove(root)
            }
        })
        .await
        .context("remove task panicked")??;
        if removed {
            self.notify_inventory_changed();
        }
        Ok(removed)
    }

    /// List a local or remote directory.
    pub async fn list_directory(
        self: &Arc<Self>,
        root: ContentHash,
        cancel: CancelToken,
    ) -> Result<DirListing> {
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        if let Ok(manifest) = self.store.read_dir_manifest(root) {
            let summary = self.store.dir_summary(root);
            return Ok(DirListing {
                root,
                name: summary.and_then(|s| s.name),
                entries: manifest.entries,
            });
        }
        let object = self
            .resolve_object(
                root,
                Duration::from_secs(self.config.fetch_wait_secs.max(5)),
                &cancel,
            )
            .await?;
        let ObjectSummary::Directory(summary) = object else {
            bail!("{} is a file, not a directory", root.short());
        };
        let manifest = self.get_dir_manifest(root, Some(&summary), &cancel).await?;
        Ok(DirListing {
            root,
            name: summary.name,
            entries: manifest.entries,
        })
    }

    /// Fetch a file or directory tree.  Directory hashes cause a recursive
    /// retrieval of the manifest and all referenced children.
    pub async fn get(
        self: &Arc<Self>,
        root: ContentHash,
        output: Option<PathBuf>,
        cancel: CancelToken,
        progress: Option<ProgressSender>,
    ) -> Result<GetResult> {
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        send_progress(
            progress.as_ref(),
            "resolving",
            "resolving object",
            None,
            None,
        );
        let object = self
            .resolve_object(
                root,
                Duration::from_secs(self.config.fetch_wait_secs.max(5)),
                &cancel,
            )
            .await?;
        match object {
            ObjectSummary::File(_) => {
                send_progress(progress.as_ref(), "file", "fetching file", Some(0), None);
                let result = self
                    .fetch_file(
                        root,
                        output,
                        None,
                        TransferControl {
                            cancel: &cancel,
                            progress: progress.as_ref(),
                        },
                    )
                    .await?;
                Ok(GetResult {
                    object: result.object,
                    path: result.path,
                    bytes: result.bytes,
                })
            }
            ObjectSummary::Directory(summary) => {
                let name =
                    sanitize_name(&summary.display_name()).unwrap_or_else(|| summary.root.short());
                let target = match output {
                    Some(path) => match fs::symlink_metadata(&path) {
                        Ok(meta) if meta.file_type().is_symlink() => {
                            bail!("refusing symlink output path {}", path.display());
                        }
                        Ok(meta) if meta.is_dir() => path.join(name),
                        Ok(_) => path,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => path,
                        Err(err) => {
                            return Err(err).with_context(|| format!("inspect {}", path.display()));
                        }
                    },
                    None => std::env::current_dir()?.join(name),
                };
                match fs::symlink_metadata(&target) {
                    Ok(meta) if meta.file_type().is_symlink() => {
                        bail!("refusing symlink extraction target {}", target.display());
                    }
                    Ok(meta) if meta.is_dir() => {
                        let mut entries = fs::read_dir(&target)?;
                        if entries.next().is_some() {
                            bail!("{} already exists and is not empty", target.display());
                        }
                    }
                    Ok(_) => {
                        bail!("{} already exists and is not a directory", target.display());
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(err).with_context(|| format!("inspect {}", target.display()));
                    }
                }
                let mut budget = ExtractionBudget::new(
                    self.config.max_extract_entries,
                    self.config.max_extract_bytes,
                );
                send_progress(
                    progress.as_ref(),
                    "directory",
                    "extracting directory",
                    Some(0),
                    Some(summary.entries as u64),
                );
                let mut stack = Vec::new();
                self.fetch_dir_recursive(
                    root,
                    &target,
                    &mut stack,
                    0,
                    &mut budget,
                    TransferControl {
                        cancel: &cancel,
                        progress: progress.as_ref(),
                    },
                )
                .await?;
                Ok(GetResult {
                    object: ObjectSummary::Directory(summary.clone()),
                    path: target,
                    bytes: summary.total_size,
                })
            }
        }
    }

    // ─── Announcements and peers ────────────────────────────────────────────

    async fn handle_announce(self: &Arc<Self>, event: AnnounceEvent) {
        let desc = event.destination.lock().await.desc;
        if desc.name.as_name_hash_slice() != destination_name().as_name_hash_slice() {
            return;
        }
        if desc.address_hash == self.destination_hash() {
            return;
        }
        let announce = match NodeAnnounce::decode(event.app_data.as_slice()) {
            Ok(announce) => announce,
            Err(err) => {
                debug!("ignoring malformed meshvault announce: {err:#}");
                return;
            }
        };
        if announce.version != PROTOCOL_VERSION {
            debug!("ignoring peer with protocol version {}", announce.version);
            return;
        }

        let (is_new, connected) = {
            let mut peers = self.peers.lock().await;
            if !peers.contains_key(&desc.address_hash) && peers.len() >= self.config.max_known_peers
            {
                let victim = peers
                    .values()
                    .filter(|peer| peer.link.is_none())
                    .min_by_key(|peer| peer.last_seen)
                    .map(|peer| peer.address);
                match victim {
                    Some(address) => {
                        peers.remove(&address);
                        debug!(
                            "peer cap reached; evicted stale peer {}",
                            address.to_hex_string()
                        );
                    }
                    None => {
                        debug!(
                            "peer cap reached and all known peers are connected; ignoring announce from {}",
                            desc.address_hash.to_hex_string()
                        );
                        return;
                    }
                }
            }
            let peer = peers.entry(desc.address_hash).or_insert_with(|| {
                PeerState::new(
                    desc.address_hash,
                    self.config.peer_service_bytes_per_sec,
                    self.config.peer_service_burst_bytes,
                )
            });
            let is_new = peer.desc.is_none();
            if peer.inventory_digest != Some(announce.inventory) || peer.objects != announce.objects
            {
                peer.inventory_synced = false;
            }
            peer.desc = Some(desc);
            peer.identity = Some(desc.identity);
            peer.identity_hash = Some(desc.identity.address_hash);
            peer.name = clean_name(announce.name.clone());
            peer.objects = announce.objects;
            peer.inventory_digest = Some(announce.inventory);
            peer.hops = event.hops;
            peer.snr = event.snr;
            peer.rssi = event.rssi;
            peer.last_seen = Instant::now();
            (is_new, peer.link.is_some())
        };

        if is_new {
            info!(
                "discovered peer {} ({} hops, {} objects)",
                desc.address_hash.to_hex_string(),
                event.hops,
                announce.objects
            );
        }

        if connected {
            self.sync_if_needed(desc.address_hash).await;
        } else {
            self.ensure_link(desc.address_hash).await;
        }
    }

    async fn ensure_link(self: &Arc<Self>, address: AddressHash) {
        let desc = {
            let peers = self.peers.lock().await;
            peers.get(&address).and_then(|peer| peer.desc)
        };
        let Some(desc) = desc else {
            return;
        };
        let outbound = self
            .sessions
            .lock()
            .await
            .values()
            .filter(|session| session.outbound)
            .count();
        {
            let mut connecting = self.connecting.lock().await;
            connecting.retain(|_, started| started.elapsed() < Duration::from_secs(120));
            if connecting
                .get(&address)
                .map(|started| started.elapsed() < Duration::from_secs(90))
                .unwrap_or(false)
            {
                return;
            }
            if outbound.saturating_add(connecting.len()) >= self.config.max_peers {
                return;
            }
            connecting.insert(address, Instant::now());
        }

        info!("connecting to peer {}", address.to_hex_string());
        let link = self.transport.link(desc).await;
        let link_id = *link.lock().await.id();
        self.link_peers.lock().await.insert(link_id, address);
        debug!("outbound link {} pending", link_id);
    }

    async fn sync_if_needed(self: &Arc<Self>, address: AddressHash) {
        let (link, synced) = {
            let peers = self.peers.lock().await;
            match peers.get(&address) {
                Some(peer) => (peer.link, peer.inventory_synced),
                None => return,
            }
        };
        let Some(link_id) = link else {
            return;
        };
        if !synced {
            self.spawn_inventory_sync(link_id).await;
        }
    }

    async fn trigger_inventory_syncs(self: &Arc<Self>) {
        let links: Vec<LinkId> = {
            let peers = self.peers.lock().await;
            peers
                .values()
                .filter(|peer| peer.link.is_some() && peer.verified && !peer.inventory_synced)
                .filter_map(|peer| peer.link)
                .collect()
        };
        for link in links {
            self.spawn_inventory_sync(link).await;
        }
    }

    async fn spawn_inventory_sync(self: &Arc<Self>, link_id: LinkId) {
        {
            let mut syncing = self.syncing.lock().await;
            if !syncing.insert(link_id) {
                debug!("inventory sync already running on link {link_id}");
                return;
            }
        }
        debug!("starting inventory sync on link {link_id}");
        let node = self.clone();
        tokio::spawn(async move {
            let result = node.sync_inventory(link_id).await;
            if let Err(err) = result {
                debug!("inventory sync with {link_id} failed: {err:#}");
            }
            node.syncing.lock().await.remove(&link_id);
        });
    }

    async fn sync_inventory(self: &Arc<Self>, link_id: LinkId) -> Result<()> {
        let session = {
            let sessions = self.sessions.lock().await;
            sessions.get(&link_id).cloned()
        };
        let Some(session) = session else {
            return Ok(());
        };
        if !session.is_verified() {
            return Ok(());
        }
        let peer_address = session
            .verified_peer()
            .await
            .context("peer identity is not bound to the link")?;
        let local_count = self.store.file_count() + self.store.dir_count();
        let local_digest = self.store.inventory_digest();
        let expected_digest = {
            let peers = self.peers.lock().await;
            peers
                .get(&peer_address)
                .and_then(|peer| peer.inventory_digest)
        };
        debug!(
            "inventory sync with {}: peer digest {}, local digest {}",
            peer_address.to_hex_string(),
            expected_digest
                .map(|d| d.short())
                .unwrap_or_else(|| "?".into()),
            local_digest.short()
        );
        if expected_digest == Some(local_digest) {
            // Identical digest means both sides have the same object set.  The
            // local store is authoritative, so keep the peer's inventory map
            // empty instead of cloning a potentially huge local inventory.
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&peer_address) {
                peer.inventory.clear();
                peer.inventory_synced = true;
                peer.inventory_digest = Some(local_digest);
                peer.objects = local_count as u32;
            }
            return Ok(());
        }

        let max_objects = self.config.max_inventory_objects;
        let max_pages = (max_objects as u32).div_ceil(INVENTORY_PAGE_SIZE).max(1);
        let mut objects = HashMap::new();
        let mut snapshot = None;
        let mut page = 0u32;
        loop {
            if page >= max_pages {
                bail!("peer inventory has too many pages");
            }
            debug!("requesting inventory page {page} over {link_id}");
            let timeout = session
                .transfer_timeout(INVENTORY_PAGE_SIZE as usize * 256)
                .await;
            let response = session
                .request(Control::GetInventory { page }, timeout)
                .await?;
            let Control::InventoryPage {
                page: got_page,
                pages,
                inventory,
                entries,
            } = response
            else {
                bail!("unexpected inventory response");
            };
            if got_page != page || pages == 0 || pages > max_pages {
                bail!("invalid or oversized inventory page response");
            }
            if entries.len() > INVENTORY_PAGE_SIZE as usize {
                bail!("inventory page has too many entries");
            }
            if let Some(snapshot) = snapshot {
                if inventory != snapshot {
                    bail!("inventory changed during sync");
                }
            } else {
                snapshot = Some(inventory);
            }
            if objects.len().saturating_add(entries.len()) > max_objects {
                bail!("peer inventory exceeds max_inventory_objects");
            }
            for object in entries {
                object.validate_inventory()?;
                objects.insert(object.root(), object);
            }
            page += 1;
            if page >= pages {
                break;
            }
        }

        let mut peers = self.peers.lock().await;
        let other_objects: usize = peers
            .values()
            .filter(|peer| peer.address != peer_address)
            .map(|peer| peer.inventory.len())
            .sum();
        if other_objects.saturating_add(objects.len()) > self.config.max_inventory_objects_total {
            bail!("global inventory object cap exceeded");
        }
        if let Some(peer) = peers.get_mut(&peer_address) {
            peer.inventory = objects;
            peer.inventory_synced = true;
            if let Some(snapshot) = snapshot {
                peer.inventory_digest = Some(snapshot);
            }
            peer.objects = peer.inventory.len() as u32;
        }
        debug!(
            "synced inventory from peer {}",
            peer_address.to_hex_string()
        );
        Ok(())
    }

    async fn on_peer_inventory_changed(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        objects: u32,
        inventory: ContentHash,
    ) {
        if !session.is_verified() {
            debug!(
                "ignoring inventory change on unverified link {}",
                session.link_id
            );
            return;
        }
        debug!(
            "peer inventory change on link {}: {} objects, digest {}",
            session.link_id,
            objects,
            inventory.short()
        );
        let Some(address) = session.verified_peer().await else {
            return;
        };
        {
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&address) {
                peer.objects = objects;
                peer.inventory_digest = Some(inventory);
                peer.inventory_synced = false;
            }
        }
        if inventory == self.store.inventory_digest() {
            let local_count = self.store.file_count() + self.store.dir_count();
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&address) {
                peer.inventory.clear();
                peer.inventory_synced = true;
                peer.objects = local_count as u32;
            }
            return;
        }
        self.spawn_inventory_sync(session.link_id).await;
    }

    // ─── Link lifecycle and handshake ──────────────────────────────────────

    async fn ensure_session(
        self: &Arc<Self>,
        link_id: LinkId,
        outbound: bool,
    ) -> Option<Arc<LinkSession>> {
        if let Some(session) = self.sessions.lock().await.get(&link_id).cloned() {
            return Some(session);
        }
        let link = if outbound {
            self.transport.find_out_link(&link_id).await
        } else {
            self.transport.find_in_link(&link_id).await
        }?;
        let (tx, rx) = mpsc::channel(SESSION_INCOMING_QUEUE);
        let session = Arc::new(LinkSession::new(
            link_id,
            link,
            self.transport.clone(),
            self.memory_budget.clone(),
            outbound,
            tx,
        ));
        {
            let mut sessions = self.sessions.lock().await;
            if let Some(existing) = sessions.get(&link_id) {
                return Some(existing.clone());
            }
            sessions.insert(link_id, session.clone());
        }
        let task = tokio::spawn(session_message_loop(self.clone(), session.clone(), rx));
        self.session_tasks.lock().await.insert(link_id, task);
        Some(session)
    }

    async fn on_link_activated(self: &Arc<Self>, link_id: LinkId, outbound: bool) {
        if self.sessions.lock().await.len() >= self.config.max_links {
            warn!("refusing link {link_id}: max_links reached");
            let _ = self.transport.link_close(link_id).await;
            return;
        }
        let Some(session) = self.ensure_session(link_id, outbound).await else {
            warn!("activated link {link_id} disappeared");
            return;
        };
        let link_mtu = {
            let link = session.link.lock().await;
            debug!(
                "link {} activated ({}): mtu={} mdu={}",
                link_id,
                if outbound { "out" } else { "in" },
                link.mtu(),
                link.mdu()
            );
            link.mtu()
        };
        if link_mtu > MAX_LINK_MTU {
            warn!("closing link {link_id}: signalled MTU {link_mtu} exceeds {MAX_LINK_MTU}");
            self.close_session(&session).await;
            return;
        }

        if outbound {
            let desc = {
                let link = session.link.lock().await;
                *link.destination()
            };
            let peer_address = desc.address_hash;
            self.link_peers.lock().await.insert(link_id, peer_address);
            let mut peers = self.peers.lock().await;
            if !ensure_peer_slot(&mut peers, peer_address, self.config.max_known_peers) {
                drop(peers);
                warn!("closing outbound link {link_id}: known peer cap reached");
                self.close_session(&session).await;
                return;
            }
            let peer = peers.entry(peer_address).or_insert_with(|| {
                PeerState::new(
                    peer_address,
                    self.config.peer_service_bytes_per_sec,
                    self.config.peer_service_burst_bytes,
                )
            });
            peer.desc = Some(desc);
            peer.identity = Some(desc.identity);
            peer.identity_hash = Some(desc.identity.address_hash);
            peer.last_seen = Instant::now();
            drop(peers);
            debug!("outbound link {link_id} active");
        } else {
            debug!("inbound link {link_id} active");
        }

        let hello = match self.hello().await {
            Ok(hello) => hello,
            Err(err) => {
                warn!("cannot build hello: {err:#}");
                return;
            }
        };
        let node = self.clone();
        let identity = self.identity.clone();
        let session_clone = session.clone();
        tokio::spawn(async move {
            if outbound && let Err(err) = node.transport.link_identify(link_id, &identity).await {
                debug!("link identify failed: {err:?}");
            }
            if let Err(err) = session_clone.send_unsolicited(hello).await {
                warn!("cannot send hello on {link_id}: {err:#}");
            }
        });

        if !outbound {
            let node = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(45)).await;
                if !session.is_verified() && !session.is_closed() {
                    warn!("closing unverified inbound link {link_id}");
                    let _ = node.transport.link_close(link_id).await;
                    session.mark_closed().await;
                }
            });
        }
    }

    async fn on_link_closed(self: &Arc<Self>, link_id: LinkId) {
        let session = self.sessions.lock().await.remove(&link_id);
        if let Some(task) = self.session_tasks.lock().await.remove(&link_id) {
            task.abort();
        }
        if let Some(session) = &session {
            session.mark_closed().await;
        }
        let peer_address = self.link_peers.lock().await.remove(&link_id);
        if let Some(address) = peer_address {
            self.connecting.lock().await.remove(&address);
        }
        let mut peers = self.peers.lock().await;
        for peer in peers.values_mut() {
            if peer.link == Some(link_id) {
                peer.link = None;
                peer.verified = false;
                peer.inventory_synced = false;
                peer.inventory.clear();
            }
        }
        debug!("link {link_id} closed");
    }

    async fn handle_hello(self: &Arc<Self>, session: &Arc<LinkSession>, hello: HelloPayload) {
        if session.is_verified() {
            debug!(
                "ignoring repeated Hello on already-verified link {}",
                session.link_id
            );
            return;
        }
        let HelloPayload {
            version,
            dest,
            identity,
            name,
            objects,
            inventory,
        } = hello;
        if let Some(existing) = session.hello().await {
            if existing.dest == dest && existing.identity == identity {
                debug!(
                    "ignoring duplicate Hello on unverified link {}",
                    session.link_id
                );
            } else {
                warn!(
                    "peer changed identity in a second Hello on link {}; closing",
                    session.link_id
                );
                self.close_session(session).await;
            }
            return;
        }
        if version != PROTOCOL_VERSION {
            warn!("peer speaks protocol version {version}; closing link");
            self.close_session(session).await;
            return;
        }
        if AddressHash::new_from_hex_string(&dest).is_err()
            || AddressHash::new_from_hex_string(&identity).is_err()
        {
            warn!("peer sent invalid hello identifiers");
            self.close_session(session).await;
            return;
        }
        let hello = PeerHello {
            dest,
            identity,
            name: name.clone(),
            objects,
            inventory,
        };
        session.set_hello(hello).await;
        // Peer state is created only after try_complete_handshake has
        // authenticated the claimed destination/identity.
        self.try_complete_handshake(session).await;
    }

    async fn try_complete_handshake(self: &Arc<Self>, session: &Arc<LinkSession>) {
        if session.is_verified() || session.is_closed() {
            return;
        }
        let _guard = self.handshake_lock.lock().await;
        if session.is_verified() {
            return;
        }
        let Some(hello) = session.hello().await else {
            return;
        };
        let (Ok(peer_dest), Ok(identity_hash)) = (
            AddressHash::new_from_hex_string(&hello.dest),
            AddressHash::new_from_hex_string(&hello.identity),
        ) else {
            self.close_session(session).await;
            return;
        };

        let (desc, identity) = if session.outbound {
            let desc = {
                let link = session.link.lock().await;
                *link.destination()
            };
            if desc.address_hash != peer_dest || desc.identity.address_hash != identity_hash {
                warn!("peer hello does not match the announced destination");
                self.close_session(session).await;
                return;
            }
            (desc, desc.identity)
        } else {
            let Some(identity) = session.remote_identity().await else {
                return;
            };
            if identity.address_hash != identity_hash {
                warn!("peer identified with a different identity than it announced");
                self.close_session(session).await;
                return;
            }
            let derived = SingleOutputDestination::new(identity, destination_name()).desc;
            if derived.address_hash != peer_dest {
                warn!("peer hello destination is not derived from its identity");
                self.close_session(session).await;
                return;
            }
            (derived, identity)
        };

        session.mark_verified();
        session.bind_verified_peer(peer_dest).await;
        self.connecting.lock().await.remove(&peer_dest);

        let existing = {
            let peers = self.peers.lock().await;
            peers.get(&peer_dest).and_then(|peer| peer.link)
        };
        // Both peers may initiate a link at the same time.  Keep the
        // lexicographically smaller link id on both ends and tear the other
        // down; this converges without either side needing to know who
        // "should" have connected.
        let keep_new = existing
            .filter(|existing| *existing != session.link_id)
            .map(|existing| session.link_id < existing)
            .unwrap_or(true);
        if !keep_new {
            info!(
                "deduplicating peer {}: keeping link {}",
                peer_dest.to_hex_string(),
                existing.unwrap()
            );
            self.close_session(session).await;
            return;
        }
        if let Some(existing) = existing.filter(|existing| *existing != session.link_id) {
            info!(
                "deduplicating peer {}: closing link {}",
                peer_dest.to_hex_string(),
                existing
            );
            self.close_link_id(existing).await;
        }

        {
            let mut peers = self.peers.lock().await;
            if !ensure_peer_slot(&mut peers, peer_dest, self.config.max_known_peers) {
                drop(peers);
                warn!(
                    "closing verified link {}: known peer cap reached",
                    session.link_id
                );
                self.close_session(session).await;
                return;
            }
            let peer = peers.entry(peer_dest).or_insert_with(|| {
                PeerState::new(
                    peer_dest,
                    self.config.peer_service_bytes_per_sec,
                    self.config.peer_service_burst_bytes,
                )
            });
            peer.desc = Some(desc);
            peer.identity = Some(identity);
            peer.identity_hash = Some(identity.address_hash);
            peer.link = Some(session.link_id);
            peer.verified = true;
            peer.name = clean_name(hello.name.clone());
            peer.objects = hello.objects;
            peer.inventory_digest = Some(hello.inventory);
            peer.last_seen = Instant::now();
        }
        self.link_peers
            .lock()
            .await
            .insert(session.link_id, peer_dest);
        info!(
            "peer {} verified on link {}",
            peer_dest.to_hex_string(),
            session.link_id
        );
        self.sync_if_needed(peer_dest).await;
    }

    async fn close_session(&self, session: &Arc<LinkSession>) {
        session.mark_closed().await;
        let _ = self.transport.link_close(session.link_id).await;
    }

    async fn close_link_id(&self, link_id: LinkId) {
        let session = {
            let sessions = self.sessions.lock().await;
            sessions.get(&link_id).cloned()
        };
        match session {
            Some(session) => self.close_session(&session).await,
            None => {
                let _ = self.transport.link_close(link_id).await;
            }
        }
    }

    // ─── Incoming service requests ─────────────────────────────────────────

    async fn handle_incoming(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        incoming: Incoming,
    ) -> Result<()> {
        match incoming {
            Incoming::Control {
                request,
                response,
                body,
            } => {
                if response {
                    debug!("unmatched control response on {}", session.link_id);
                    return Ok(());
                }
                match body {
                    Control::Hello {
                        version,
                        dest,
                        identity,
                        name,
                        objects,
                        inventory,
                    } => {
                        self.handle_hello(
                            session,
                            HelloPayload {
                                version,
                                dest,
                                identity,
                                name,
                                objects,
                                inventory,
                            },
                        )
                        .await;
                    }
                    Control::GetInventory { page } => {
                        if request == 0 {
                            return Ok(());
                        }
                        self.serve_inventory(session, request, page).await;
                    }
                    Control::GetManifest { root } => {
                        if request == 0 {
                            return Ok(());
                        }
                        self.serve_manifest(session, request, root).await;
                    }
                    Control::GetDirectory { root } => {
                        if request == 0 {
                            return Ok(());
                        }
                        self.serve_directory(session, request, root).await;
                    }
                    Control::GetChunk { root, start, count } => {
                        if request == 0 {
                            return Ok(());
                        }
                        self.serve_chunk(session, request, root, start, count).await;
                    }
                    Control::InventoryChanged { objects, inventory } => {
                        self.on_peer_inventory_changed(session, objects, inventory)
                            .await;
                    }
                    Control::Ping => {
                        if request != 0 {
                            let _ = session.respond(request, Control::Pong).await;
                        }
                    }
                    Control::Pong => {}
                    Control::Error { code, message } => {
                        debug!("peer error {code}: {message}");
                    }
                    other => debug!("unexpected control message: {other:?}"),
                }
            }
            Incoming::Chunk(_) => debug!("ignoring unsolicited chunk message"),
        }
        Ok(())
    }

    async fn require_verified(&self, session: &Arc<LinkSession>, request: u32) -> bool {
        if session.is_verified() {
            return true;
        }
        if request != 0 {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 403,
                        message: "link not verified".into(),
                    },
                )
                .await;
        }
        false
    }

    async fn peer_limiter(&self, session: &Arc<LinkSession>) -> Option<Arc<ServiceLimiter>> {
        let address = session.verified_peer().await?;
        let peers = self.peers.lock().await;
        peers.get(&address).map(|peer| peer.service.clone())
    }

    async fn respond_rate_limited(&self, session: &Arc<LinkSession>, request: u32) {
        debug!(
            "rate limiting peer request {} on link {}",
            request, session.link_id
        );
        let _ = session
            .respond(
                request,
                Control::Error {
                    code: 429,
                    message: "peer service rate limit exceeded".into(),
                },
            )
            .await;
    }

    async fn serve_inventory(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        request: u32,
        page: u32,
    ) {
        if !self.require_verified(session, request).await {
            return;
        }
        let Some(limiter) = self.peer_limiter(session).await else {
            self.respond_rate_limited(session, request).await;
            return;
        };
        if !limiter.try_consume(MIN_REQUEST_COST) {
            self.respond_rate_limited(session, request).await;
            return;
        }
        debug!("serving inventory page {page} to {}", session.link_id);
        let objects = self.store.inventory_snapshot();
        let pages = (objects.len() as u32).div_ceil(INVENTORY_PAGE_SIZE).max(1);
        if page >= pages {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 404,
                        message: "inventory page out of range".into(),
                    },
                )
                .await;
            return;
        }
        let start = page as usize * INVENTORY_PAGE_SIZE as usize;
        let end = (start + INVENTORY_PAGE_SIZE as usize).min(objects.len());
        let entries = objects[start..end].to_vec();
        let response = Control::InventoryPage {
            page,
            pages,
            inventory: self.store.inventory_digest(),
            entries,
        };
        if let Err(err) = session.respond(request, response).await {
            debug!("cannot send inventory page: {err:#}");
        }
    }

    async fn serve_manifest(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        request: u32,
        root: ContentHash,
    ) {
        if !self.require_verified(session, request).await {
            return;
        }
        let Some(summary) = self.store.file_summary(root) else {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 404,
                        message: "manifest unavailable".into(),
                    },
                )
                .await;
            return;
        };
        let Some(limiter) = self.peer_limiter(session).await else {
            self.respond_rate_limited(session, request).await;
            return;
        };
        let estimated = manifest_service_cost(&summary);
        if !limiter.try_consume(estimated) {
            self.respond_rate_limited(session, request).await;
            return;
        }

        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            let manifest = store.read_manifest(root)?;
            let hash = manifest.manifest_hash()?;
            let data = manifest.encode()?;
            Ok::<_, anyhow::Error>((hash, data))
        })
        .await;

        match result {
            Ok(Ok((manifest_hash, data))) => {
                if data.len() as u64 > estimated
                    && !limiter.try_consume(data.len() as u64 - estimated)
                {
                    self.respond_rate_limited(session, request).await;
                    return;
                }
                let _ = session
                    .respond(
                        request,
                        Control::Manifest {
                            root,
                            manifest_hash,
                            data,
                        },
                    )
                    .await;
            }
            Ok(Err(err)) => {
                debug!("manifest unavailable for {}: {err:#}", root.short());
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 404,
                            message: "manifest unavailable".into(),
                        },
                    )
                    .await;
            }
            Err(err) => debug!("manifest task failed: {err}"),
        }
    }

    async fn serve_directory(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        request: u32,
        root: ContentHash,
    ) {
        if !self.require_verified(session, request).await {
            return;
        }
        let Some(summary) = self.store.dir_summary(root) else {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 404,
                        message: "directory unavailable".into(),
                    },
                )
                .await;
            return;
        };
        let Some(limiter) = self.peer_limiter(session).await else {
            self.respond_rate_limited(session, request).await;
            return;
        };
        let estimated = directory_service_cost(&summary);
        if !limiter.try_consume(estimated) {
            self.respond_rate_limited(session, request).await;
            return;
        }

        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            let manifest = store.read_dir_manifest(root)?;
            manifest.encode()
        })
        .await;
        match result {
            Ok(Ok(data)) => {
                if data.len() as u64 > estimated
                    && !limiter.try_consume(data.len() as u64 - estimated)
                {
                    self.respond_rate_limited(session, request).await;
                    return;
                }
                let _ = session
                    .respond(request, Control::Directory { root, data })
                    .await;
            }
            Ok(Err(err)) => {
                debug!("directory unavailable for {}: {err:#}", root.short());
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 404,
                            message: "directory unavailable".into(),
                        },
                    )
                    .await;
            }
            Err(err) => debug!("directory task failed: {err}"),
        }
    }

    async fn serve_chunk(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        request: u32,
        root: ContentHash,
        start: u32,
        count: u32,
    ) {
        if !self.require_verified(session, request).await {
            return;
        }
        if count == 0 || count > MAX_PIECES_PER_REQUEST {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 400,
                        message: "invalid chunk size".into(),
                    },
                )
                .await;
            return;
        }
        let Some(summary) = self.store.file_summary(root) else {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 404,
                        message: "file unavailable".into(),
                    },
                )
                .await;
            return;
        };
        let budget = match session.budget().await {
            Ok(budget) => budget,
            Err(err) => {
                debug!("cannot compute link budget: {err:#}");
                return;
            }
        };
        let max_bytes = budget.max_message_bytes.saturating_sub(CHUNK_HEADER_LEN);
        let total = summary.pieces;
        if start >= total {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 400,
                        message: "chunk start out of range".into(),
                    },
                )
                .await;
            return;
        }
        let actual = count.min(total - start);
        let piece_size = summary.piece_size as u64;
        let start_byte = start as u64 * piece_size;
        let end_byte = if start + actual == total {
            summary.size
        } else {
            (start + actual) as u64 * piece_size
        };
        let length = end_byte.saturating_sub(start_byte);
        if length as usize > max_bytes {
            let _ = session
                .respond(
                    request,
                    Control::Error {
                        code: 400,
                        message: "requested chunk exceeds link message budget".into(),
                    },
                )
                .await;
            return;
        }

        let Some(limiter) = self.peer_limiter(session).await else {
            self.respond_rate_limited(session, request).await;
            return;
        };
        if !limiter.try_consume(length.saturating_add(CHUNK_HEADER_LEN as u64)) {
            self.respond_rate_limited(session, request).await;
            return;
        }

        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            let manifest = store.read_manifest(root)?;
            let data = store.read_chunk(&manifest, start, actual)?;
            Ok::<_, anyhow::Error>(data)
        })
        .await;

        match result {
            Ok(Ok(data)) => {
                let chunk = ChunkMessage {
                    request,
                    root,
                    start,
                    count: actual,
                    data,
                };
                if let Err(err) = session.send_chunk(chunk).await {
                    debug!("cannot send chunk: {err:#}");
                }
            }
            Ok(Err(err)) => {
                debug!("chunk unavailable for {}: {err:#}", root.short());
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 404,
                            message: "chunk unavailable".into(),
                        },
                    )
                    .await;
            }
            Err(err) => debug!("chunk task failed: {err}"),
        }
    }

    // ─── Fetching ───────────────────────────────────────────────────────────

    async fn resolve_object(
        self: &Arc<Self>,
        root: ContentHash,
        wait: Duration,
        cancel: &CancelToken,
    ) -> Result<ObjectSummary> {
        let deadline = Instant::now() + wait;
        loop {
            if cancel.is_cancelled() {
                bail!("operation cancelled");
            }
            if let Some(object) = self.store.object_summary(root) {
                return Ok(object);
            }
            {
                let peers = self.peers.lock().await;
                let found = peers
                    .values()
                    .filter(|peer| peer.verified && peer.link.is_some())
                    .find_map(|peer| peer.object_summary(root).cloned());
                if let Some(object) = found {
                    return Ok(object);
                }
            }
            self.trigger_inventory_syncs().await;
            if Instant::now() >= deadline {
                bail!("object {} is not available on the mesh", root.short());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn fetch_candidates(&self, root: ContentHash, kind: ObjectKind) -> Vec<FetchCandidate> {
        let peers = self.peers.lock().await;
        let mut candidates: Vec<_> = peers
            .values()
            .filter(|peer| peer.verified)
            .filter_map(|peer| {
                let summary = peer.object_summary(root)?;
                if summary.kind() != kind {
                    return None;
                }
                Some(FetchCandidate {
                    peer: peer.address,
                    link: peer.link?,
                    hops: peer.hops,
                    snr: peer.snr,
                    manifest_hash: summary.manifest_hash(),
                })
            })
            .collect();
        candidates.sort_by(|a, b| {
            a.hops.cmp(&b.hops).then_with(|| {
                b.snr
                    .unwrap_or(f32::MIN)
                    .partial_cmp(&a.snr.unwrap_or(f32::MIN))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        candidates
    }

    async fn session_for_link(&self, link_id: LinkId) -> Option<Arc<LinkSession>> {
        let sessions = self.sessions.lock().await;
        sessions.get(&link_id).cloned()
    }

    /// Prefer the manifest layout advertised by the most peers.  This avoids
    /// letting one inconsistent or malicious peer choose a piece layout that
    /// the rest of the swarm cannot verify or serve in parallel.
    fn order_candidates_for_manifest(candidates: Vec<FetchCandidate>) -> Vec<FetchCandidate> {
        if candidates.len() < 2 {
            return candidates;
        }
        let mut counts: HashMap<ContentHash, usize> = HashMap::new();
        for candidate in &candidates {
            *counts.entry(candidate.manifest_hash).or_default() += 1;
        }
        let preferred = counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(hash, _)| hash);
        let mut ordered = candidates;
        if let Some(preferred) = preferred {
            ordered.sort_by_key(|candidate| candidate.manifest_hash != preferred);
        }
        ordered
    }

    async fn fetch_lock(&self, root: ContentHash) -> Arc<Mutex<()>> {
        self.fetch_locks
            .lock()
            .await
            .entry(root)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn fetch_manifest_from(
        &self,
        session: &Arc<LinkSession>,
        peer: AddressHash,
        root: ContentHash,
    ) -> Result<(Manifest, ContentHash)> {
        let summary = {
            let peers = self.peers.lock().await;
            peers
                .get(&peer)
                .and_then(|peer| peer.object_summary(root))
                .and_then(|object| object.file().cloned())
        };
        let timeout = session.transfer_timeout(64 * 1024).await;
        let response = session
            .request(Control::GetManifest { root }, timeout)
            .await?;
        let Control::Manifest {
            root: response_root,
            manifest_hash,
            data,
        } = response
        else {
            bail!("unexpected manifest response");
        };
        if response_root != root {
            bail!("peer returned the wrong manifest");
        }
        let manifest = Manifest::decode(&data)?;
        if manifest.root != root {
            bail!("manifest root does not match requested hash");
        }
        let actual_hash = manifest.manifest_hash()?;
        if actual_hash != manifest_hash {
            bail!("manifest hash mismatch");
        }
        if let Some(summary) = summary
            && summary.manifest_hash != manifest_hash
        {
            bail!("manifest does not match peer inventory");
        }
        Ok((manifest, manifest_hash))
    }

    async fn fetch_file(
        self: &Arc<Self>,
        root: ContentHash,
        output: Option<PathBuf>,
        mut budget: Option<&mut ExtractionBudget>,
        control: TransferControl<'_>,
    ) -> Result<FetchResult> {
        let cancel = control.cancel;
        let progress_tx = control.progress;
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        let lock = self.fetch_lock(root).await;
        let _guard = lock.lock().await;

        if self.store.has_file(root) {
            let size = self.store.file_summary(root).map(|f| f.size).unwrap_or(0);
            if let Some(budget) = budget.as_deref_mut() {
                budget.consume_bytes(size)?;
            }
            send_progress(progress_tx, "saving", "copying local file", Some(0), None);
            let store = self.store.clone();
            let out = output.clone();
            let path = tokio::task::spawn_blocking(move || store.export(root, out.as_deref()))
                .await
                .context("export task panicked")??;
            let object = self
                .store
                .object_summary(root)
                .context("file summary missing")?;
            return Ok(FetchResult {
                object,
                path,
                bytes: size,
                resumed: true,
                sources: Vec::new(),
            });
        }

        let discovery_deadline =
            Instant::now() + Duration::from_secs(self.config.fetch_wait_secs.max(5));
        let mut last_error: Option<anyhow::Error> = None;
        let mut cooldown: HashMap<AddressHash, Instant> = HashMap::new();
        let mut manifest: Option<Manifest> = None;
        let mut manifest_hash: Option<ContentHash> = None;
        let mut progress: Option<Arc<StdMutex<PieceProgress>>> = None;
        let mut shared: Option<Arc<SharedFetch>> = None;
        let mut partial: Option<Arc<std::fs::File>> = None;
        let mut initial_verified = 0usize;
        let mut sources: HashSet<AddressHash> = HashSet::new();
        let mut empty_rounds = 0u32;
        let mut announced_sources = false;
        let mut budget_charged = false;
        let mut last_progress_at = Instant::now();
        let mut last_verified_count = 0usize;
        let stall_timeout = Duration::from_secs(self.config.fetch_stall_timeout_secs.max(60));

        loop {
            if cancel.is_cancelled() {
                bail!("operation cancelled");
            }
            if manifest.is_some() {
                if let Some(progress) = &progress {
                    let done = progress.lock().unwrap().verified_count();
                    if done > last_verified_count {
                        last_verified_count = done;
                        last_progress_at = Instant::now();
                    }
                }
                if last_progress_at.elapsed() > stall_timeout {
                    bail!("fetch made no progress for {:?}", stall_timeout);
                }
            }
            let candidates = self.fetch_candidates(root, ObjectKind::File).await;
            if candidates.is_empty() {
                self.trigger_inventory_syncs().await;
            }

            if manifest.is_none() {
                for candidate in &Self::order_candidates_for_manifest(candidates.clone()) {
                    if cooldown
                        .get(&candidate.peer)
                        .is_some_and(|until| *until > Instant::now())
                    {
                        continue;
                    }
                    let Some(session) = self.session_for_link(candidate.link).await else {
                        continue;
                    };
                    match self
                        .fetch_manifest_from(&session, candidate.peer, root)
                        .await
                    {
                        Ok((loaded, hash)) => {
                            let store = self.store.clone();
                            let manifest_for_verify = loaded.clone();
                            let verified = tokio::task::spawn_blocking(move || {
                                store.verify_partial(&manifest_for_verify)
                            })
                            .await
                            .context("verify partial task panicked")??;
                            initial_verified = verified.iter().filter(|done| **done).count();
                            let piece_progress =
                                Arc::new(StdMutex::new(PieceProgress::new(verified)));
                            partial = Some(Arc::new(self.store.open_partial(root)?));
                            let label = loaded.name.clone().unwrap_or_else(|| root.short());
                            send_progress(
                                progress_tx,
                                "downloading",
                                label.clone(),
                                Some(initial_verified as u64),
                                Some(loaded.piece_count() as u64),
                            );
                            shared = Some(Arc::new(SharedFetch {
                                manifest: loaded.clone(),
                                progress: piece_progress.clone(),
                                progress_tx: progress_tx.cloned(),
                                label,
                            }));
                            progress = Some(piece_progress);
                            manifest = Some(loaded);
                            manifest_hash = Some(hash);
                            if !budget_charged {
                                if let Some(budget) = budget.as_deref_mut() {
                                    budget
                                        .consume_bytes(manifest.as_ref().map_or(0, |m| m.size))?;
                                }
                                budget_charged = true;
                            }
                            last_progress_at = Instant::now();
                            last_verified_count = initial_verified;
                            break;
                        }
                        Err(err) => {
                            warn!(
                                "peer {} cannot provide manifest for {}: {err:#}",
                                candidate.peer.to_hex_string(),
                                root.short()
                            );
                            if let Some(peer) = self.peers.lock().await.get_mut(&candidate.peer) {
                                peer.last_error = Some(format!("{err:#}"));
                            }
                            cooldown
                                .insert(candidate.peer, Instant::now() + Duration::from_secs(10));
                            last_error = Some(err);
                        }
                    }
                }
                if manifest.is_none() {
                    if Instant::now() >= discovery_deadline {
                        return Err(last_error.unwrap_or_else(|| {
                            anyhow!("no peer advertises file {}", root.short())
                        }));
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            }

            let shared = shared.as_ref().context("fetch state missing")?.clone();
            let partial = partial.as_ref().context("partial file missing")?.clone();
            let progress = progress.as_ref().context("progress missing")?.clone();
            let manifest_hash = manifest_hash.context("manifest hash missing")?;

            if progress.lock().unwrap().all_done() {
                break;
            }
            if !announced_sources {
                info!(
                    "fetching {} ({} pieces) from up to {} peer(s)",
                    root.short(),
                    shared.manifest.piece_count(),
                    self.config.fetch_parallelism
                );
                announced_sources = true;
            }

            let matching: Vec<FetchCandidate> = candidates
                .into_iter()
                .filter(|candidate| candidate.manifest_hash == manifest_hash)
                .collect();
            let now = Instant::now();
            let mut usable: Vec<FetchCandidate> = matching
                .iter()
                .filter(|candidate| {
                    !cooldown
                        .get(&candidate.peer)
                        .is_some_and(|until| *until > now)
                })
                .cloned()
                .collect();
            if usable.is_empty() {
                // All usable peers are cooling down; give them another
                // chance rather than stalling forever.
                usable = matching;
            }
            usable.truncate(self.config.fetch_parallelism.max(1));

            if usable.is_empty() {
                empty_rounds += 1;
                if empty_rounds >= 6 {
                    return Err(last_error
                        .unwrap_or_else(|| anyhow!("no peer can serve file {}", root.short())));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            let before = progress.lock().unwrap().verified_count();
            let mut workers = tokio::task::JoinSet::new();
            let mut spawned = 0usize;
            for candidate in usable {
                let Some(session) = self.session_for_link(candidate.link).await else {
                    continue;
                };
                let node = self.clone();
                let shared = shared.clone();
                let partial = partial.clone();
                let max_chunk_bytes = self.config.max_chunk_bytes;
                let cancel = cancel.clone();
                workers.spawn(async move {
                    let stats = node
                        .fetch_file_worker(
                            &session,
                            root,
                            &shared,
                            &partial,
                            max_chunk_bytes,
                            &cancel,
                        )
                        .await;
                    (candidate.peer, stats)
                });
                spawned += 1;
            }

            loop {
                if cancel.is_cancelled() {
                    workers.abort_all();
                    bail!("operation cancelled");
                }
                let joined =
                    match tokio::time::timeout(Duration::from_millis(500), workers.join_next())
                        .await
                    {
                        Ok(Some(joined)) => joined,
                        Ok(None) => break,
                        Err(_) => continue,
                    };
                match joined {
                    Ok((peer, Ok(stats))) => {
                        if stats.chunks > 0 {
                            sources.insert(peer);
                            debug!(
                                "peer {} contributed {} chunk(s), {} bytes",
                                peer.to_hex_string(),
                                stats.chunks,
                                stats.bytes
                            );
                        }
                        cooldown.remove(&peer);
                    }
                    Ok((peer, Err(err))) => {
                        warn!(
                            "peer {} stopped serving {}: {err:#}",
                            peer.to_hex_string(),
                            root.short()
                        );
                        if let Some(peer_state) = self.peers.lock().await.get_mut(&peer) {
                            peer_state.last_error = Some(format!("{err:#}"));
                        }
                        cooldown.insert(peer, Instant::now() + Duration::from_secs(10));
                        last_error = Some(err);
                    }
                    Err(err) => {
                        last_error = Some(anyhow!("fetch worker failed: {err}"));
                    }
                }
            }

            let after = progress.lock().unwrap().verified_count();
            if after > before {
                empty_rounds = 0;
            } else {
                empty_rounds += 1;
            }
            if progress.lock().unwrap().all_done() {
                break;
            }
            if empty_rounds >= 6 {
                return Err(
                    last_error.unwrap_or_else(|| anyhow!("download of {} stalled", root.short()))
                );
            }
            debug!(
                "fetch progress {}/{} pieces from {} worker(s)",
                after,
                progress.lock().unwrap().total(),
                spawned
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }

        let partial = partial.context("partial file missing")?;
        partial.sync_data().context("fsync partial download")?;
        drop(partial);

        let manifest = manifest.context("manifest missing")?;
        send_progress(
            progress_tx,
            "saving",
            manifest.name.clone().unwrap_or_else(|| root.short()),
            Some(manifest.piece_count() as u64),
            Some(manifest.piece_count() as u64),
        );
        let store = self.store.clone();
        let manifest_for_finalize = manifest.clone();
        tokio::task::spawn_blocking(move || store.finalize_partial(&manifest_for_finalize))
            .await
            .context("finalize task panicked")??;

        let store = self.store.clone();
        let out = output.clone();
        let path = tokio::task::spawn_blocking(move || store.export(root, out.as_deref()))
            .await
            .context("export task panicked")??;

        let object = self
            .store
            .object_summary(root)
            .context("fetched file summary missing")?;
        let bytes = manifest.size;

        if !self.config.cache_fetched {
            let store = self.store.clone();
            let _ = tokio::task::spawn_blocking(move || store.remove(root)).await;
        }

        let mut source_list: Vec<String> = sources
            .into_iter()
            .map(|address| address.to_hex_string())
            .collect();
        source_list.sort();

        Ok(FetchResult {
            object,
            path,
            bytes,
            resumed: initial_verified > 0,
            sources: source_list,
        })
    }

    async fn fetch_file_worker(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        root: ContentHash,
        shared: &Arc<SharedFetch>,
        file: &Arc<std::fs::File>,
        max_chunk_bytes: u64,
        cancel: &CancelToken,
    ) -> Result<WorkerStats> {
        let mut stats = WorkerStats::default();
        loop {
            if cancel.is_cancelled() {
                bail!("operation cancelled");
            }
            let all_done = shared.progress.lock().unwrap().all_done();
            if all_done {
                break;
            }
            let remaining = shared.progress.lock().unwrap().remaining() as u32;
            let (plan, _) = session
                .chunk_plan(shared.manifest.piece_size, remaining, max_chunk_bytes)
                .await?;
            let mut requested = plan.clamp(1, MAX_PIECES_PER_REQUEST);
            let mut attempts = 0u8;

            loop {
                let claim = shared.progress.lock().unwrap().claim(requested);
                let Some((start, count)) = claim else {
                    return Ok(stats);
                };
                let expected_bytes = shared.manifest.range_len(start, count)? as usize;
                let timeout = session.transfer_timeout(expected_bytes).await;
                let started = Instant::now();
                match session
                    .request_chunk(Control::GetChunk { root, start, count }, timeout)
                    .await
                {
                    Ok(chunk) => {
                        session
                            .record_chunk(chunk.data.len(), started.elapsed())
                            .await;
                        match verify_and_write_chunk(
                            &self.store,
                            file,
                            &shared.manifest,
                            root,
                            start,
                            count,
                            chunk,
                        ) {
                            Ok(bytes) => {
                                let (done, total) = {
                                    let mut progress = shared.progress.lock().unwrap();
                                    progress.complete(start, count);
                                    (progress.verified_count() as u64, progress.total() as u64)
                                };
                                send_progress(
                                    shared.progress_tx.as_ref(),
                                    "downloading",
                                    shared.label.clone(),
                                    Some(done),
                                    Some(total),
                                );
                                stats.chunks += 1;
                                stats.bytes += bytes as u64;
                                break;
                            }
                            Err(err) => {
                                shared.progress.lock().unwrap().release(start, count);
                                attempts += 1;
                                if count <= 1 || attempts >= 3 {
                                    return Err(err).context("chunk verification failed");
                                }
                                requested = count.div_ceil(2).max(1);
                                debug!(
                                    "retrying pieces {}..{} with {} piece(s): {err:#}",
                                    start,
                                    start + count,
                                    requested
                                );
                            }
                        }
                    }
                    Err(err) => {
                        shared.progress.lock().unwrap().release(start, count);
                        attempts += 1;
                        if count <= 1 || attempts >= 3 {
                            return Err(err).context("chunk request failed");
                        }
                        requested = count.div_ceil(2).max(1);
                        debug!(
                            "retrying pieces {}..{} with {} piece(s): {err:#}",
                            start,
                            start + count,
                            requested
                        );
                    }
                }
            }
        }
        Ok(stats)
    }

    async fn get_dir_manifest(
        self: &Arc<Self>,
        root: ContentHash,
        summary: Option<&DirSummary>,
        cancel: &CancelToken,
    ) -> Result<DirManifest> {
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        if let Ok(manifest) = self.store.read_dir_manifest(root) {
            return Ok(manifest);
        }
        let summary = match summary {
            Some(summary) => summary.clone(),
            None => match self
                .resolve_object(
                    root,
                    Duration::from_secs(self.config.fetch_wait_secs.max(5)),
                    cancel,
                )
                .await?
            {
                ObjectSummary::Directory(summary) => summary,
                ObjectSummary::File(_) => bail!("{} is a file, not a directory", root.short()),
            },
        };
        let candidates = self.fetch_candidates(root, ObjectKind::Directory).await;
        let mut last_error: Option<anyhow::Error> = None;
        for candidate in candidates {
            if cancel.is_cancelled() {
                bail!("operation cancelled");
            }
            let peer_address = candidate.peer;
            let Some(session) = self.session_for_link(candidate.link).await else {
                continue;
            };
            let timeout = session.transfer_timeout(64 * 1024).await;
            match session
                .request(Control::GetDirectory { root }, timeout)
                .await
            {
                Ok(Control::Directory {
                    root: response_root,
                    data,
                }) if response_root == root => {
                    let manifest = DirManifest::decode(&data)?;
                    if manifest.root()? != root {
                        bail!("directory manifest hash mismatch");
                    }
                    if self.config.cache_fetched {
                        let store = self.store.clone();
                        let manifest_for_store = manifest.clone();
                        let name = summary.name.clone();
                        tokio::task::spawn_blocking(move || {
                            store.store_dir_manifest(&manifest_for_store, name)
                        })
                        .await
                        .context("store directory task panicked")??;
                        self.notify_inventory_changed();
                    }
                    return Ok(manifest);
                }
                Ok(Control::Error { code, message }) => {
                    last_error = Some(anyhow!("peer error {code}: {message}"));
                }
                Ok(other) => {
                    last_error = Some(anyhow!("unexpected directory response: {other:?}"));
                }
                Err(err) => {
                    last_error = Some(err);
                }
            }
            if let Some(peer) = self.peers.lock().await.get_mut(&peer_address) {
                peer.last_error = last_error.as_ref().map(|err| format!("{err:#}"));
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no peer serves directory {}", root.short())))
    }

    async fn fetch_dir_recursive(
        self: &Arc<Self>,
        root: ContentHash,
        target: &Path,
        stack: &mut Vec<ContentHash>,
        depth: usize,
        budget: &mut ExtractionBudget,
        control: TransferControl<'_>,
    ) -> Result<()> {
        let cancel = control.cancel;
        let progress = control.progress;
        if cancel.is_cancelled() {
            bail!("operation cancelled");
        }
        if depth > MAX_DIRECTORY_DEPTH {
            bail!("directory nesting is too deep");
        }
        if stack.contains(&root) {
            bail!("directory cycle detected at {}", root.short());
        }
        stack.push(root);
        let manifest = self.get_dir_manifest(root, None, cancel).await?;
        fs::create_dir_all(target)
            .with_context(|| format!("create directory {}", target.display()))?;

        let total_entries = manifest.entries.len() as u64;
        for (index, entry) in manifest.entries.into_iter().enumerate() {
            if cancel.is_cancelled() {
                bail!("operation cancelled");
            }
            budget.consume_entry()?;
            send_progress(
                progress,
                "directory",
                entry.name.clone(),
                Some(index as u64 + 1),
                Some(total_entries),
            );
            let Some(name) = sanitize_name(&entry.name) else {
                warn!("skipping unsafe directory entry name {:?}", entry.name);
                continue;
            };
            let child = target.join(&name);
            if fs::symlink_metadata(&child).is_ok() {
                bail!(
                    "refusing existing/symlink extraction path {}",
                    child.display()
                );
            }
            match entry.kind {
                ObjectKind::File => {
                    self.fetch_file(entry.hash, Some(child), Some(budget), control)
                        .await?;
                }
                ObjectKind::Directory => {
                    Box::pin(self.fetch_dir_recursive(
                        entry.hash,
                        &child,
                        stack,
                        depth + 1,
                        budget,
                        control,
                    ))
                    .await?;
                }
            }
        }
        stack.pop();
        Ok(())
    }

    // ─── Status ────────────────────────────────────────────────────────────

    pub async fn status(&self) -> NodeStatus {
        let (peers_known, peers_connected) = {
            let peers = self.peers.lock().await;
            (
                peers.len(),
                peers.values().filter(|peer| peer.link.is_some()).count(),
            )
        };
        let (links, outbound_links) = {
            let sessions = self.sessions.lock().await;
            (
                sessions.len(),
                sessions.values().filter(|session| session.outbound).count(),
            )
        };
        NodeStatus {
            name: self.config.name.clone(),
            destination: self.destination_hash().to_hex_string(),
            identity: self.identity_hash().to_hex_string(),
            data_dir: self.paths.data_dir.display().to_string(),
            config_file: self.paths.config_file.display().to_string(),
            control_socket: self.paths.control_socket.display().to_string(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            files: self.store.file_count(),
            directories: self.store.dir_count(),
            bytes: self.store.total_bytes(),
            inventory: self.store.inventory_digest().to_hex(),
            peers_known,
            peers_connected,
            links,
            outbound_links,
            inbound_buffer_bytes: self.memory_budget.used(),
            inbound_buffer_limit: self.memory_budget.limit(),
            known_peer_limit: self.config.max_known_peers,
            inventory_object_limit: self.config.max_inventory_objects,
            peer_service_bytes_per_sec: self.config.peer_service_bytes_per_sec,
            peer_service_burst_bytes: self.config.peer_service_burst_bytes,
            transport_node: self.config.transport_node,
            connect: self.config.interfaces.connect.clone(),
            listen: self.config.interfaces.listen.clone(),
        }
    }

    pub async fn peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().await;
        let mut info: Vec<_> = peers.values().map(PeerState::info).collect();
        info.sort_by(|a, b| {
            b.connected
                .cmp(&a.connected)
                .then_with(|| a.hops.cmp(&b.hops))
        });
        info
    }

    /// Report known holders of an object: the local store and every linked
    /// peer whose synchronized inventory advertises the same root.
    pub async fn sources(&self, root: ContentHash) -> SourceInfo {
        let local = self.store.object_summary(root);
        let local_present = local.is_some();
        let local_digest = self.store.inventory_digest();
        let peers = self.peers.lock().await;
        let mut sources = Vec::new();

        if let Some(object) = &local {
            sources.push(SourceEntry {
                local: true,
                address: None,
                node_name: None,
                hops: None,
                snr: None,
                rssi: None,
                object: object.clone(),
            });
        }

        let mut unknown_peers = 0usize;
        for peer in peers.values() {
            if !peer.verified || peer.link.is_none() {
                continue;
            }

            // A peer whose digest equals ours has exactly our inventory.  The
            // sync path drops the redundant per-peer map in that case, so use
            // the local summary as the source of truth.
            let same_inventory = peer.inventory_digest == Some(local_digest);
            let object = if peer.inventory_synced {
                peer.object_summary(root).cloned()
            } else if same_inventory {
                local.clone()
            } else {
                None
            };

            match object {
                Some(object) => sources.push(SourceEntry {
                    local: false,
                    address: Some(peer.address.to_hex_string()),
                    node_name: peer.name.clone(),
                    hops: Some(peer.hops),
                    snr: peer.snr,
                    rssi: peer.rssi,
                    object,
                }),
                None if !peer.inventory_synced && !same_inventory => unknown_peers += 1,
                None => {}
            }
        }

        sources.sort_by(|a, b| {
            b.local
                .cmp(&a.local)
                .then_with(|| a.hops.unwrap_or(u8::MAX).cmp(&b.hops.unwrap_or(u8::MAX)))
                .then_with(|| {
                    b.snr
                        .unwrap_or(f32::MIN)
                        .partial_cmp(&a.snr.unwrap_or(f32::MIN))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| a.address.cmp(&b.address))
        });

        let remote_copies = sources.iter().filter(|source| !source.local).count();
        SourceInfo {
            root,
            copies: sources.len(),
            remote_copies,
            local: local_present,
            sources,
            unknown_peers,
        }
    }
}

// ─── Background tasks ───────────────────────────────────────────────────────

async fn announce_loop(node: Arc<Node>) {
    tokio::time::sleep(Duration::from_secs(2)).await;
    node.announce().await;
    let interval = Duration::from_secs(node.config.announce_interval_secs.max(60));
    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => node.announce().await,
            _ = node.announce_now.notified() => {
                // Coalesce bursts of repository changes.
                tokio::time::sleep(Duration::from_secs(5)).await;
                node.announce().await;
            }
        }
    }
}

async fn announce_listener(node: Arc<Node>) {
    let mut receiver = node.transport.recv_announces().await;
    loop {
        match receiver.recv().await {
            Ok(event) => node.handle_announce(event).await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                debug!("announce stream lagged by {skipped}");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn link_event_loop(node: Arc<Node>, outbound: bool) {
    let mut receiver = if outbound {
        node.transport.out_link_events()
    } else {
        node.transport.in_link_events()
    };
    loop {
        match receiver.recv().await {
            Ok(event) => match event.event {
                LinkEvent::Activated => {
                    node.on_link_activated(event.id, outbound).await;
                }
                LinkEvent::Data(payload) => {
                    if let Some(session) = node.ensure_session(event.id, outbound).await
                        && let Err(err) = session.handle_data(payload.as_slice()).await
                    {
                        debug!("bad frame on link {}: {err:#}", event.id);
                    }
                }
                LinkEvent::RemoteIdentified(identity) => {
                    let session = {
                        let sessions = node.sessions.lock().await;
                        sessions.get(&event.id).cloned()
                    };
                    if let Some(session) = session {
                        session.set_remote_identity(identity).await;
                        node.try_complete_handshake(&session).await;
                    }
                }
                LinkEvent::Closed => node.on_link_closed(event.id).await,
                _ => {}
            },
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                debug!("link event stream lagged by {skipped}");
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

async fn session_message_loop(
    node: Arc<Node>,
    session: Arc<LinkSession>,
    mut receiver: mpsc::Receiver<Incoming>,
) {
    while let Some(incoming) = receiver.recv().await {
        if let Err(err) = node.handle_incoming(&session, incoming).await {
            debug!("incoming message error: {err:#}");
        }
    }
}

async fn reconnect_loop(node: Arc<Node>) {
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;
        let candidates: Vec<AddressHash> = {
            let mut peers = node.peers.lock().await;
            let before = peers.len();
            peers
                .retain(|_, peer| peer.link.is_some() || peer.last_seen.elapsed() < PEER_RETENTION);
            if peers.len() != before {
                debug!("evicted {} stale peer record(s)", before - peers.len());
            }
            peers
                .values()
                .filter(|peer| peer.desc.is_some() && peer.link.is_none())
                .map(|peer| peer.address)
                .collect()
        };
        for address in candidates {
            node.ensure_link(address).await;
        }
        // Remove stale connection attempts and link-to-peer mappings for
        // pending links that never activated.
        node.connecting
            .lock()
            .await
            .retain(|_, started| started.elapsed() < Duration::from_secs(120));
        let active_links: HashSet<LinkId> = {
            let sessions = node.sessions.lock().await;
            sessions.keys().copied().collect()
        };
        node.link_peers
            .lock()
            .await
            .retain(|link_id, _| active_links.contains(link_id));
    }
}

async fn inventory_broadcast_loop(node: Arc<Node>) {
    loop {
        node.inventory_changed.notified().await;
        // Let a batch of imports settle before spending announce airtime.
        tokio::time::sleep(Duration::from_secs(1)).await;
        let control = Control::InventoryChanged {
            objects: (node.store.file_count() + node.store.dir_count()) as u32,
            inventory: node.store.inventory_digest(),
        };
        let sessions: Vec<_> = {
            let sessions = node.sessions.lock().await;
            sessions.values().cloned().collect()
        };
        for session in sessions {
            if !session.is_verified() {
                continue;
            }
            let session = session.clone();
            let control = control.clone();
            tokio::spawn(async move {
                if let Err(err) = session.send_unsolicited(control).await {
                    debug!("inventory notify failed: {err:#}");
                }
            });
        }
        node.announce_now.notify_one();
    }
}

fn manifest_service_cost(summary: &ManifestSummary) -> u64 {
    (summary.pieces as u64)
        .saturating_mul(72)
        .saturating_add(summary.name.as_ref().map_or(0, |name| name.len() as u64))
        .saturating_add(1024)
        .max(MIN_REQUEST_COST)
}

fn directory_service_cost(summary: &DirSummary) -> u64 {
    (summary.entries as u64)
        .saturating_mul(384)
        .saturating_add(summary.name.as_ref().map_or(0, |name| name.len() as u64))
        .saturating_add(1024)
        .max(MIN_REQUEST_COST)
}

fn verify_and_write_chunk(
    store: &Store,
    file: &std::fs::File,
    manifest: &Manifest,
    root: ContentHash,
    start: u32,
    count: u32,
    chunk: ChunkMessage,
) -> Result<usize> {
    if chunk.root != root || chunk.start != start || chunk.count != count {
        bail!("peer returned a chunk for the wrong range");
    }
    let expected_len = manifest.range_len(start, count)? as usize;
    if chunk.data.len() != expected_len {
        bail!(
            "peer returned {} chunk bytes, expected {expected_len}",
            chunk.data.len()
        );
    }

    // Verify the whole chunk before writing any of it, so a corrupt piece does
    // not leave the shared progress in a half-written state.
    let mut offset = 0usize;
    for index in start..start + count {
        let len = manifest.piece_len(index)? as usize;
        manifest.verify_piece(index, &chunk.data[offset..offset + len])?;
        offset += len;
    }
    let mut offset = 0usize;
    for index in start..start + count {
        let len = manifest.piece_len(index)? as usize;
        store.write_piece_at(file, manifest, index, &chunk.data[offset..offset + len])?;
        offset += len;
    }
    Ok(chunk.data.len())
}

// ─── Identity ───────────────────────────────────────────────────────────────

pub fn load_identity(data_dir: &Path) -> Result<PrivateIdentity> {
    fs::create_dir_all(data_dir)
        .with_context(|| format!("create data directory {}", data_dir.display()))?;
    let path = data_dir.join(IDENTITY_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            let text = text.trim();
            PrivateIdentity::new_from_hex_string(text)
                .with_context(|| format!("parse identity {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let identity = PrivateIdentity::new_from_rand(&mut rng);
            write_identity(&path, &identity)?;
            info!("created new identity at {}", path.display());
            Ok(identity)
        }
        Err(err) => Err(err).with_context(|| format!("read identity {}", path.display())),
    }
}

fn write_identity(path: &Path, identity: &PrivateIdentity) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("create identity {}", path.display()))?;
    use std::io::Write;
    file.write_all(identity.to_hex_string().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_budget_is_enforced() {
        let mut budget = ExtractionBudget::new(2, 10);
        budget.consume_entry().unwrap();
        budget.consume_entry().unwrap();
        assert!(budget.consume_entry().is_err());

        budget.consume_bytes(6).unwrap();
        assert!(budget.consume_bytes(5).is_err());
        budget.consume_bytes(4).unwrap();
        assert!(budget.consume_bytes(1).is_err());
    }

    #[test]
    fn cancel_token_is_observable() {
        let token = CancelToken::new();
        assert!(!token.is_cancelled());
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn daemon_lock_is_exclusive_and_released_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let first = DataDirLock::acquire(temp.path()).unwrap();
        assert!(DataDirLock::acquire(temp.path()).is_err());
        drop(first);
        let second = DataDirLock::acquire(temp.path()).unwrap();
        drop(second);
    }
}
