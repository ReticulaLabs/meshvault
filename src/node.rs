//! MeshVault node: Reticulum service, peer manager, inventory sync, transfer.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::hash::ContentHash;
use crate::manifest::{DirEntry, DirManifest, DirSummary, Manifest, ObjectKind, ObjectSummary};
use crate::session::{Incoming, LinkSession, PeerHello};
use crate::store::{MAX_PIECES_PER_REQUEST, Store, sanitize_name};
use crate::wire::{
    CHUNK_HEADER_LEN, ChunkMessage, Control, INVENTORY_PAGE_SIZE, NodeAnnounce, PROTOCOL_VERSION,
};

const IDENTITY_FILE: &str = "identity.hex";
const ANNOUNCE_PAYLOAD_LIMIT: usize = 280;
const MAX_DIRECTORY_DEPTH: usize = 64;
const MAX_INVENTORY_PAGES: u32 = 4096;

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
    last_error: Option<String>,
}

impl PeerState {
    fn new(address: AddressHash) -> Self {
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

struct FetchState {
    manifest_hash: ContentHash,
    verified: Vec<bool>,
}

pub struct Node {
    pub config: Config,
    pub paths: Paths,
    pub identity: PrivateIdentity,
    pub destination: Arc<Mutex<SingleInputDestination>>,
    pub transport: Transport,
    pub store: Arc<Store>,
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
        let identity = load_identity(&paths.data_dir)?;
        let store = Arc::new(Store::open(&paths.data_dir)?);

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

    pub async fn remove(&self, root: ContentHash) -> Result<bool> {
        let store = self.store.clone();
        let removed = tokio::task::spawn_blocking(move || store.remove(root))
            .await
            .context("remove task panicked")??;
        if removed {
            self.notify_inventory_changed();
        }
        Ok(removed)
    }

    /// List a local or remote directory.
    pub async fn list_directory(self: &Arc<Self>, root: ContentHash) -> Result<DirListing> {
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
            )
            .await?;
        let ObjectSummary::Directory(summary) = object else {
            bail!("{} is a file, not a directory", root.short());
        };
        let manifest = self.get_dir_manifest(root, Some(&summary)).await?;
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
    ) -> Result<GetResult> {
        let object = self
            .resolve_object(
                root,
                Duration::from_secs(self.config.fetch_wait_secs.max(5)),
            )
            .await?;
        match object {
            ObjectSummary::File(_) => {
                let result = self.fetch_file(root, output).await?;
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
                    Some(path) if path.exists() && path.is_dir() => path.join(name),
                    Some(path) => path,
                    None => std::env::current_dir()?.join(name),
                };
                if target.exists() {
                    if !target.is_dir() {
                        bail!("{} already exists and is not a directory", target.display());
                    }
                    let mut entries = fs::read_dir(&target)?;
                    if entries.next().is_some() {
                        bail!("{} already exists and is not empty", target.display());
                    }
                }
                let mut stack = Vec::new();
                self.fetch_dir_recursive(root, &target, &mut stack, 0)
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
            let peer = peers
                .entry(desc.address_hash)
                .or_insert_with(|| PeerState::new(desc.address_hash));
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
        {
            let mut connecting = self.connecting.lock().await;
            if connecting
                .get(&address)
                .map(|started| started.elapsed() < Duration::from_secs(90))
                .unwrap_or(false)
            {
                return;
            }
            connecting.insert(address, Instant::now());
        }

        let outbound = self
            .sessions
            .lock()
            .await
            .values()
            .filter(|session| session.outbound)
            .count();
        if outbound >= self.config.max_peers {
            self.connecting.lock().await.remove(&address);
            return;
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
        let hello = session.hello().await.context("peer hello missing")?;
        let peer_address = AddressHash::new_from_hex_string(&hello.dest)?;
        let local_inventory = self.store.inventory();
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
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&peer_address) {
                peer.inventory = local_inventory
                    .into_iter()
                    .map(|object| (object.root(), object))
                    .collect();
                peer.inventory_synced = true;
                peer.inventory_digest = Some(local_digest);
            }
            return Ok(());
        }

        let mut objects = HashMap::new();
        let mut snapshot = None;
        let mut page = 0u32;
        loop {
            if page >= MAX_INVENTORY_PAGES {
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
            if got_page != page || pages == 0 {
                bail!("invalid inventory page response");
            }
            if let Some(snapshot) = snapshot {
                if inventory != snapshot {
                    bail!("inventory changed during sync");
                }
            } else {
                snapshot = Some(inventory);
            }
            for object in entries {
                if objects.len() >= 1_000_000 {
                    bail!("peer inventory is too large");
                }
                objects.insert(object.root(), object);
            }
            page += 1;
            if page >= pages {
                break;
            }
        }

        let mut peers = self.peers.lock().await;
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
        debug!(
            "peer inventory change on link {}: {} objects, digest {}",
            session.link_id,
            objects,
            inventory.short()
        );
        let Some(hello) = session.hello().await else {
            return;
        };
        let Ok(address) = AddressHash::new_from_hex_string(&hello.dest) else {
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
            let local = self.store.inventory();
            let mut peers = self.peers.lock().await;
            if let Some(peer) = peers.get_mut(&address) {
                peer.inventory = local
                    .into_iter()
                    .map(|object| (object.root(), object))
                    .collect();
                peer.inventory_synced = true;
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
        let (tx, rx) = mpsc::channel(256);
        let session = Arc::new(LinkSession::new(
            link_id,
            link,
            self.transport.clone(),
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
        {
            let link = session.link.lock().await;
            debug!(
                "link {} activated ({}): mtu={} mdu={}",
                link_id,
                if outbound { "out" } else { "in" },
                link.mtu(),
                link.mdu()
            );
        }

        if outbound {
            let desc = {
                let link = session.link.lock().await;
                *link.destination()
            };
            let peer_address = desc.address_hash;
            self.link_peers.lock().await.insert(link_id, peer_address);
            let mut peers = self.peers.lock().await;
            let peer = peers
                .entry(peer_address)
                .or_insert_with(|| PeerState::new(peer_address));
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
            }
        }
        debug!("link {link_id} closed");
    }

    async fn handle_hello(self: &Arc<Self>, session: &Arc<LinkSession>, hello: HelloPayload) {
        let HelloPayload {
            version,
            dest,
            identity,
            name,
            objects,
            inventory,
        } = hello;
        if version != PROTOCOL_VERSION {
            warn!("peer speaks protocol version {version}; closing link");
            self.close_session(session).await;
            return;
        }
        let (Ok(peer_dest), Ok(identity_hash)) = (
            AddressHash::new_from_hex_string(&dest),
            AddressHash::new_from_hex_string(&identity),
        ) else {
            warn!("peer sent invalid hello identifiers");
            self.close_session(session).await;
            return;
        };
        let hello = PeerHello {
            dest,
            identity,
            name: name.clone(),
            objects,
            inventory,
        };
        session.set_hello(hello).await;
        {
            let mut peers = self.peers.lock().await;
            let peer = peers
                .entry(peer_dest)
                .or_insert_with(|| PeerState::new(peer_dest));
            peer.name = clean_name(name);
            peer.objects = objects;
            peer.inventory_digest = Some(inventory);
            peer.identity_hash = Some(identity_hash);
            peer.last_seen = Instant::now();
        }
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
            let peer = peers
                .entry(peer_dest)
                .or_insert_with(|| PeerState::new(peer_dest));
            peer.desc = Some(desc);
            peer.identity = Some(identity);
            peer.identity_hash = Some(identity.address_hash);
            peer.link = Some(session.link_id);
            peer.verified = true;
            peer.name = hello.name.clone();
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

    async fn serve_inventory(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        request: u32,
        page: u32,
    ) {
        if !self.require_verified(session, request).await {
            return;
        }
        debug!("serving inventory page {page} to {}", session.link_id);
        let objects = self.store.inventory();
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
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 404,
                            message: format!("manifest unavailable: {err:#}"),
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
        let store = self.store.clone();
        let result = tokio::task::spawn_blocking(move || {
            let manifest = store.read_dir_manifest(root)?;
            manifest.encode()
        })
        .await;
        match result {
            Ok(Ok(data)) => {
                let _ = session
                    .respond(request, Control::Directory { root, data })
                    .await;
            }
            Ok(Err(err)) => {
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 404,
                            message: format!("directory unavailable: {err:#}"),
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
        let store = self.store.clone();
        let budget = match session.budget().await {
            Ok(budget) => budget,
            Err(err) => {
                debug!("cannot compute link budget: {err:#}");
                return;
            }
        };
        let max_bytes = budget.max_message_bytes.saturating_sub(CHUNK_HEADER_LEN);
        let result = tokio::task::spawn_blocking(move || {
            let manifest = store.read_manifest(root)?;
            if start >= manifest.piece_count() {
                bail!("chunk start out of range");
            }
            let actual = count.min(manifest.piece_count() - start);
            let length = manifest.range_len(start, actual)?;
            if length as usize > max_bytes {
                bail!("requested chunk exceeds link message budget");
            }
            let data = store.read_chunk(&manifest, start, actual)?;
            Ok::<_, anyhow::Error>((actual, data))
        })
        .await;

        match result {
            Ok(Ok((actual, data))) => {
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
                let _ = session
                    .respond(
                        request,
                        Control::Error {
                            code: 400,
                            message: format!("{err:#}"),
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
    ) -> Result<ObjectSummary> {
        let deadline = Instant::now() + wait;
        loop {
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

    async fn fetch_candidates(
        &self,
        root: ContentHash,
        kind: ObjectKind,
    ) -> Vec<(AddressHash, LinkId, u8, Option<f32>)> {
        let peers = self.peers.lock().await;
        let mut candidates: Vec<_> = peers
            .values()
            .filter(|peer| peer.verified)
            .filter_map(|peer| {
                let summary = peer.object_summary(root)?;
                if summary.kind() != kind {
                    return None;
                }
                Some((peer.address, peer.link?, peer.hops, peer.snr))
            })
            .collect();
        candidates.sort_by(|a, b| {
            a.2.cmp(&b.2).then_with(|| {
                b.3.unwrap_or(f32::MIN)
                    .partial_cmp(&a.3.unwrap_or(f32::MIN))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        candidates
    }

    async fn fetch_lock(&self, root: ContentHash) -> Arc<Mutex<()>> {
        self.fetch_locks
            .lock()
            .await
            .entry(root)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn fetch_file(
        self: &Arc<Self>,
        root: ContentHash,
        output: Option<PathBuf>,
    ) -> Result<FetchResult> {
        let lock = self.fetch_lock(root).await;
        let _guard = lock.lock().await;

        if self.store.has_file(root) {
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
                bytes: self.store.file_summary(root).map(|f| f.size).unwrap_or(0),
                resumed: true,
            });
        }

        let deadline = Instant::now() + Duration::from_secs(self.config.fetch_wait_secs.max(5));
        let mut state: Option<FetchState> = None;
        let mut last_error: Option<anyhow::Error> = None;

        loop {
            let candidates = self.fetch_candidates(root, ObjectKind::File).await;
            if candidates.is_empty() {
                self.trigger_inventory_syncs().await;
            }
            for (peer_address, link_id, _, _) in candidates {
                let session = {
                    let sessions = self.sessions.lock().await;
                    sessions.get(&link_id).cloned()
                };
                let Some(session) = session else {
                    continue;
                };
                match self
                    .fetch_file_from_peer(&session, peer_address, root, output.clone(), &mut state)
                    .await
                {
                    Ok(result) => {
                        self.notify_inventory_changed();
                        return Ok(result);
                    }
                    Err(err) => {
                        warn!(
                            "peer {} failed to serve {}: {err:#}",
                            peer_address.to_hex_string(),
                            root.short()
                        );
                        if let Some(peer) = self.peers.lock().await.get_mut(&peer_address) {
                            peer.last_error = Some(format!("{err:#}"));
                        }
                        last_error = Some(err);
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(last_error
                    .unwrap_or_else(|| anyhow!("no peer advertises file {}", root.short())));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn fetch_file_from_peer(
        self: &Arc<Self>,
        session: &Arc<LinkSession>,
        peer_address: AddressHash,
        root: ContentHash,
        output: Option<PathBuf>,
        state: &mut Option<FetchState>,
    ) -> Result<FetchResult> {
        let summary = {
            let peers = self.peers.lock().await;
            peers
                .get(&peer_address)
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

        if let Some(existing) = state {
            if existing.manifest_hash != manifest_hash {
                bail!("peer served a different manifest for the same hash");
            }
        } else {
            let store = self.store.clone();
            let manifest_for_verify = manifest.clone();
            let verified =
                tokio::task::spawn_blocking(move || store.verify_partial(&manifest_for_verify))
                    .await
                    .context("verify partial task panicked")??;
            *state = Some(FetchState {
                manifest_hash,
                verified,
            });
        }

        let state = state.as_mut().unwrap();
        let mut file = self.store.open_partial(root)?;
        let mut bytes_since_sync = 0u64;
        let mut last_sync = Instant::now();
        let piece_count = manifest.piece_count();

        while let Some(first_missing) = state.verified.iter().position(|verified| !verified) {
            let first_missing = first_missing as u32;
            let mut run = 0u32;
            while first_missing + run < piece_count
                && !state.verified[(first_missing + run) as usize]
            {
                run += 1;
            }

            let mut cursor = first_missing;
            let run_end = first_missing + run;
            while cursor < run_end {
                let remaining = run_end - cursor;
                let (mut plan, _budget) = session
                    .chunk_plan(manifest.piece_size, remaining, self.config.max_chunk_bytes)
                    .await?;
                plan = plan.clamp(1, MAX_PIECES_PER_REQUEST);

                let mut attempts = 0;
                let chunk = loop {
                    let expected_bytes = manifest.range_len(cursor, plan)? as usize;
                    let timeout = session.transfer_timeout(expected_bytes).await;
                    let started = Instant::now();
                    match session
                        .request_chunk(
                            Control::GetChunk {
                                root,
                                start: cursor,
                                count: plan,
                            },
                            timeout,
                        )
                        .await
                    {
                        Ok(chunk) => {
                            session
                                .record_chunk(chunk.data.len(), started.elapsed())
                                .await;
                            break chunk;
                        }
                        Err(err) => {
                            attempts += 1;
                            if plan <= 1 || attempts >= 3 {
                                return Err(err).context("chunk request failed");
                            }
                            plan = plan.div_ceil(2).max(1);
                            debug!(
                                "retrying chunk {} at {} pieces after error: {err:#}",
                                cursor, plan
                            );
                        }
                    }
                };

                if chunk.root != root || chunk.start != cursor {
                    bail!("peer returned a chunk for the wrong range");
                }
                let actual = chunk.count;
                if actual == 0 || actual > plan {
                    bail!("peer returned an invalid chunk size");
                }
                let expected_len = manifest.range_len(cursor, actual)? as usize;
                if chunk.data.len() != expected_len {
                    bail!(
                        "peer returned {} chunk bytes, expected {expected_len}",
                        chunk.data.len()
                    );
                }
                let mut offset = 0usize;
                for index in cursor..cursor + actual {
                    let len = manifest.piece_len(index)? as usize;
                    let piece = &chunk.data[offset..offset + len];
                    manifest.verify_piece(index, piece)?;
                    self.store.write_piece(&mut file, &manifest, index, piece)?;
                    state.verified[index as usize] = true;
                    offset += len;
                }
                bytes_since_sync += chunk.data.len() as u64;
                if bytes_since_sync >= 8 * 1024 * 1024
                    || last_sync.elapsed() >= Duration::from_secs(5)
                {
                    file.sync_data().context("fsync partial download")?;
                    bytes_since_sync = 0;
                    last_sync = Instant::now();
                }
                cursor += actual;
            }
        }
        file.sync_data().context("fsync partial download")?;
        drop(file);

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

        Ok(FetchResult {
            object,
            path,
            bytes,
            resumed: false,
        })
    }

    async fn get_dir_manifest(
        self: &Arc<Self>,
        root: ContentHash,
        summary: Option<&DirSummary>,
    ) -> Result<DirManifest> {
        if let Ok(manifest) = self.store.read_dir_manifest(root) {
            return Ok(manifest);
        }
        let summary = match summary {
            Some(summary) => summary.clone(),
            None => match self
                .resolve_object(
                    root,
                    Duration::from_secs(self.config.fetch_wait_secs.max(5)),
                )
                .await?
            {
                ObjectSummary::Directory(summary) => summary,
                ObjectSummary::File(_) => bail!("{} is a file, not a directory", root.short()),
            },
        };
        let candidates = self.fetch_candidates(root, ObjectKind::Directory).await;
        let mut last_error: Option<anyhow::Error> = None;
        for (peer_address, link_id, _, _) in candidates {
            let session = {
                let sessions = self.sessions.lock().await;
                sessions.get(&link_id).cloned()
            };
            let Some(session) = session else {
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
    ) -> Result<()> {
        if depth > MAX_DIRECTORY_DEPTH {
            bail!("directory nesting is too deep");
        }
        if stack.contains(&root) {
            bail!("directory cycle detected at {}", root.short());
        }
        stack.push(root);
        let manifest = self.get_dir_manifest(root, None).await?;
        fs::create_dir_all(target)
            .with_context(|| format!("create directory {}", target.display()))?;

        for entry in manifest.entries {
            let Some(name) = sanitize_name(&entry.name) else {
                warn!("skipping unsafe directory entry name {:?}", entry.name);
                continue;
            };
            let child = target.join(&name);
            match entry.kind {
                ObjectKind::File => {
                    if child.exists() {
                        bail!("{} already exists", child.display());
                    }
                    self.fetch_file(entry.hash, Some(child)).await?;
                }
                ObjectKind::Directory => {
                    Box::pin(self.fetch_dir_recursive(entry.hash, &child, stack, depth + 1))
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
            let peers = node.peers.lock().await;
            peers
                .values()
                .filter(|peer| peer.desc.is_some() && peer.link.is_none())
                .map(|peer| peer.address)
                .collect()
        };
        for address in candidates {
            node.ensure_link(address).await;
        }
        // Remove stale connection attempts.
        node.connecting
            .lock()
            .await
            .retain(|_, started| started.elapsed() < Duration::from_secs(120));
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
