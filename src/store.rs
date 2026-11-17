//! Crash-safe, content-addressed on-disk repository.
//!
//! Layout under `data_dir`:
//!
//! ```text
//! blobs/<blake3-hex>              raw file bytes
//! manifests/<blake3-hex>.json     verified file piece lists
//! dirs/<blake3-hex>.json          content-addressed directory listings
//! dirs/<blake3-hex>.name          optional local display name
//! partial/<blake3-hex>.part       resumable file downloads
//! tmp/                            atomic-write staging (cleared on start)
//! ```
//!
//! A file's identity is BLAKE3 of its full contents.  A directory's identity
//! is BLAKE3 of the canonical encoding of its sorted entries; each entry names
//! a child file hash or child directory hash.  Directory manifests are tiny
//! and can be served without holding the child blobs.
//!
//! Writes always go to `tmp/`, are `fsync`ed, and are then renamed into place.
//! A crash therefore leaves either the old state or the new state, never a
//! half-written blob.  The in-memory index is rebuilt from manifests at
//! startup; there is no separate database that can become inconsistent.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use log::{info, warn};

use crate::hash::ContentHash;
use crate::manifest::{
    DirEntry, DirManifest, DirSummary, MAX_PIECE_SIZE, MIN_PIECE_SIZE, Manifest, ManifestSummary,
    ObjectKind, ObjectSummary,
};

/// Largest chunk (in pieces) accepted from a peer. Prevents a malicious
/// request from forcing a huge allocation.
pub const MAX_PIECES_PER_REQUEST: u32 = 256;

pub struct Store {
    root: PathBuf,
    blob_dir: PathBuf,
    manifest_dir: PathBuf,
    dir_dir: PathBuf,
    partial_dir: PathBuf,
    tmp_dir: PathBuf,
    files: RwLock<HashMap<ContentHash, ManifestSummary>>,
    dirs: RwLock<HashMap<ContentHash, DirSummary>>,
    inventory_cache: RwLock<Option<Arc<Vec<ObjectSummary>>>>,
    digest_cache: RwLock<Option<ContentHash>>,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self> {
        let root = data_dir.to_path_buf();
        let blob_dir = root.join("blobs");
        let manifest_dir = root.join("manifests");
        let dir_dir = root.join("dirs");
        let partial_dir = root.join("partial");
        let tmp_dir = root.join("tmp");

        for dir in [&blob_dir, &manifest_dir, &dir_dir, &partial_dir, &tmp_dir] {
            fs::create_dir_all(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }

        // Staging files are never valid after a restart.
        for entry in fs::read_dir(&tmp_dir).context("scan tmp directory")? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let _ = fs::remove_file(entry.path());
            }
        }

        let store = Self {
            root,
            blob_dir,
            manifest_dir,
            dir_dir,
            partial_dir,
            tmp_dir,
            files: RwLock::new(HashMap::new()),
            dirs: RwLock::new(HashMap::new()),
            inventory_cache: RwLock::new(None),
            digest_cache: RwLock::new(None),
        };
        store.rebuild_index()?;
        Ok(store)
    }

    fn rebuild_index(&self) -> Result<()> {
        let mut files = HashMap::new();
        let mut dirs = HashMap::new();

        for entry in fs::read_dir(&self.manifest_dir).context("scan manifest directory")? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(err) => {
                    warn!("cannot read manifest {}: {err}", path.display());
                    continue;
                }
            };
            let manifest = match Manifest::decode(&data) {
                Ok(manifest) => manifest,
                Err(err) => {
                    warn!("ignoring corrupt manifest {}: {err:#}", path.display());
                    continue;
                }
            };
            let expected_name = format!("{}.json", manifest.root.to_hex());
            if path.file_name().and_then(|n| n.to_str()) != Some(expected_name.as_str()) {
                warn!(
                    "ignoring manifest {} (file name does not match its root)",
                    path.display()
                );
                continue;
            }
            let blob = self.blob_path(manifest.root);
            match fs::metadata(&blob) {
                Ok(meta) if meta.len() == manifest.size => {}
                Ok(meta) => {
                    warn!(
                        "ignoring manifest {}: blob length {} != {}",
                        manifest.root.short(),
                        meta.len(),
                        manifest.size
                    );
                    continue;
                }
                Err(_) => {
                    warn!(
                        "ignoring manifest {}: blob is missing",
                        manifest.root.short()
                    );
                    continue;
                }
            }
            match manifest.summary() {
                Ok(summary) => {
                    files.insert(manifest.root, summary);
                }
                Err(err) => warn!("ignoring manifest {}: {err:#}", path.display()),
            }
        }

        for entry in fs::read_dir(&self.dir_dir).context("scan directory manifests")? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(err) => {
                    warn!("cannot read directory manifest {}: {err}", path.display());
                    continue;
                }
            };
            let manifest = match DirManifest::decode(&data) {
                Ok(manifest) => manifest,
                Err(err) => {
                    warn!(
                        "ignoring corrupt directory manifest {}: {err:#}",
                        path.display()
                    );
                    continue;
                }
            };
            let root = match manifest.root() {
                Ok(root) => root,
                Err(err) => {
                    warn!("cannot hash directory manifest {}: {err:#}", path.display());
                    continue;
                }
            };
            let expected_name = format!("{}.json", root.to_hex());
            if path.file_name().and_then(|n| n.to_str()) != Some(expected_name.as_str()) {
                warn!(
                    "ignoring directory manifest {} (file name does not match its hash)",
                    path.display()
                );
                continue;
            }
            let name = fs::read_to_string(self.dir_name_path(root))
                .ok()
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty());
            let created_at = metadata_timestamp(&path);
            match manifest.summary(name, created_at) {
                Ok(summary) => {
                    dirs.insert(root, summary);
                }
                Err(err) => warn!("ignoring directory manifest {}: {err:#}", path.display()),
            }
        }

        // Orphaned blobs are left untouched: deleting user data on startup is
        // worse than wasting space.  They can be re-imported to build a
        // manifest again.
        if let Ok(entries_dir) = fs::read_dir(&self.blob_dir) {
            for entry in entries_dir.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Ok(root) = ContentHash::from_hex(name) else {
                    continue;
                };
                if !files.contains_key(&root) {
                    warn!("orphaned blob {} (no manifest)", root.short());
                }
            }
        }

        *self.files.write().unwrap() = files;
        *self.dirs.write().unwrap() = dirs;
        self.invalidate_inventory_cache();
        info!(
            "repository: {} file(s), {} directory manifest(s) indexed",
            self.files.read().unwrap().len(),
            self.dirs.read().unwrap().len()
        );
        Ok(())
    }

    fn invalidate_inventory_cache(&self) {
        *self.inventory_cache.write().unwrap() = None;
        *self.digest_cache.write().unwrap() = None;
    }

    pub fn root_dir(&self) -> &Path {
        &self.root
    }

    fn blob_path(&self, root: ContentHash) -> PathBuf {
        self.blob_dir.join(root.to_hex())
    }

    fn manifest_path(&self, root: ContentHash) -> PathBuf {
        self.manifest_dir.join(format!("{}.json", root.to_hex()))
    }

    fn dir_manifest_path(&self, root: ContentHash) -> PathBuf {
        self.dir_dir.join(format!("{}.json", root.to_hex()))
    }

    fn dir_name_path(&self, root: ContentHash) -> PathBuf {
        self.dir_dir.join(format!("{}.name", root.to_hex()))
    }

    pub fn partial_path(&self, root: ContentHash) -> PathBuf {
        self.partial_dir.join(format!("{}.part", root.to_hex()))
    }

    fn new_temp(&self, prefix: &str) -> Result<tempfile::NamedTempFile> {
        tempfile::Builder::new()
            .prefix(prefix)
            .tempfile_in(&self.tmp_dir)
            .context("create temporary file")
    }

    pub fn has(&self, root: ContentHash) -> bool {
        self.has_file(root) || self.has_dir(root)
    }

    pub fn has_file(&self, root: ContentHash) -> bool {
        self.files.read().unwrap().contains_key(&root)
    }

    pub fn has_dir(&self, root: ContentHash) -> bool {
        self.dirs.read().unwrap().contains_key(&root)
    }

    pub fn file_summary(&self, root: ContentHash) -> Option<ManifestSummary> {
        self.files.read().unwrap().get(&root).cloned()
    }

    pub fn dir_summary(&self, root: ContentHash) -> Option<DirSummary> {
        self.dirs.read().unwrap().get(&root).cloned()
    }

    pub fn object_summary(&self, root: ContentHash) -> Option<ObjectSummary> {
        if let Some(file) = self.file_summary(root) {
            Some(ObjectSummary::File(file))
        } else {
            self.dir_summary(root).map(ObjectSummary::Directory)
        }
    }

    /// Cached, sorted inventory snapshot.  Page serving clones only the
    /// requested page instead of rebuilding the whole inventory per request.
    pub fn inventory_snapshot(&self) -> Arc<Vec<ObjectSummary>> {
        if let Some(snapshot) = self.inventory_cache.read().unwrap().as_ref().cloned() {
            return snapshot;
        }
        let mut cache = self.inventory_cache.write().unwrap();
        if let Some(snapshot) = cache.as_ref().cloned() {
            return snapshot;
        }
        let mut objects: Vec<ObjectSummary> = self
            .files
            .read()
            .unwrap()
            .values()
            .cloned()
            .map(ObjectSummary::File)
            .chain(
                self.dirs
                    .read()
                    .unwrap()
                    .values()
                    .cloned()
                    .map(ObjectSummary::Directory),
            )
            .collect();
        objects.sort_by_key(|object| object.root());
        let snapshot = Arc::new(objects);
        *cache = Some(snapshot.clone());
        snapshot
    }

    pub fn inventory(&self) -> Vec<ObjectSummary> {
        (*self.inventory_snapshot()).clone()
    }

    pub fn file_count(&self) -> usize {
        self.files.read().unwrap().len()
    }

    pub fn dir_count(&self) -> usize {
        self.dirs.read().unwrap().len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.files.read().unwrap().values().map(|f| f.size).sum()
    }

    /// Deterministic digest of the current inventory.  Peers exchange this
    /// tiny value instead of repeatedly broadcasting full file lists.
    pub fn inventory_digest(&self) -> ContentHash {
        if let Some(digest) = *self.digest_cache.read().unwrap() {
            return digest;
        }
        let objects = self.inventory_snapshot();
        let mut hasher = blake3::Hasher::new();
        for object in objects.iter() {
            hasher.update(object.root().as_bytes());
            hasher.update(object.manifest_hash().as_bytes());
        }
        let digest = ContentHash::from_hasher(hasher);
        *self.digest_cache.write().unwrap() = Some(digest);
        digest
    }

    /// Import a file into the repository.  Streams the input, hashing each
    /// piece and the whole file in one pass.
    pub fn import_file(
        &self,
        source: &Path,
        piece_size: u32,
        name: Option<String>,
    ) -> Result<Manifest> {
        if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&piece_size) {
            bail!("piece size must be between {MIN_PIECE_SIZE} and {MAX_PIECE_SIZE}");
        }
        let metadata =
            fs::metadata(source).with_context(|| format!("stat {}", source.display()))?;
        if !metadata.is_file() {
            bail!("{} is not a regular file", source.display());
        }

        let input = File::open(source).with_context(|| format!("open {}", source.display()))?;
        let mut reader = BufReader::with_capacity(1024 * 1024, input);
        let temp = self.new_temp("import-")?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, temp.as_file());

        let mut full_hasher = blake3::Hasher::new();
        let mut pieces = Vec::new();
        let mut buffer = vec![0u8; piece_size as usize];
        let mut total = 0u64;

        loop {
            let read = read_full(&mut reader, &mut buffer)?;
            if read == 0 {
                break;
            }
            let piece = &buffer[..read];
            full_hasher.update(piece);
            pieces.push(ContentHash::of(piece));
            writer.write_all(piece)?;
            total += read as u64;
            if read < buffer.len() {
                break;
            }
        }
        writer.flush()?;
        drop(writer);

        let root = ContentHash::from_hasher(full_hasher);
        let name = name.or_else(|| source.file_name().map(|n| n.to_string_lossy().into_owned()));
        let manifest = Manifest::new(root, total, piece_size, pieces, name, unix_now())?;

        temp.as_file().sync_all().context("fsync imported blob")?;
        let blob_path = self.blob_path(root);
        if blob_path.exists() {
            // Already present; discard the duplicate staging file.
        } else {
            temp.persist(&blob_path)
                .map_err(|e| e.error)
                .context("commit blob")?;
            sync_dir(&self.blob_dir)?;
        }

        // Keep an existing manifest so an existing friendly name is not
        // replaced by a later import of the same bytes.
        let manifest_path = self.manifest_path(root);
        let final_manifest = if manifest_path.exists() {
            match self.read_manifest(root) {
                Ok(existing) => existing,
                Err(_) => {
                    self.write_manifest(&manifest)?;
                    manifest.clone()
                }
            }
        } else {
            self.write_manifest(&manifest)?;
            manifest.clone()
        };

        self.files
            .write()
            .unwrap()
            .insert(root, final_manifest.summary()?);
        self.invalidate_inventory_cache();
        Ok(final_manifest)
    }

    /// Recursively import a directory tree.  Symlinks and special files are
    /// skipped (they cannot be represented safely in a portable manifest).
    pub fn import_dir(&self, source: &Path, piece_size: u32) -> Result<DirSummary> {
        let metadata =
            fs::metadata(source).with_context(|| format!("stat {}", source.display()))?;
        if !metadata.is_dir() {
            bail!("{} is not a directory", source.display());
        }
        let name = source.file_name().map(|n| n.to_string_lossy().into_owned());
        self.import_dir_inner(source, piece_size, name)
    }

    fn import_dir_inner(
        &self,
        source: &Path,
        piece_size: u32,
        display_name: Option<String>,
    ) -> Result<DirSummary> {
        let mut children = Vec::new();
        for entry in
            fs::read_dir(source).with_context(|| format!("read directory {}", source.display()))?
        {
            let entry = entry?;
            children.push(entry);
        }
        children.sort_by_key(|entry| entry.file_name());

        let mut entries = Vec::new();
        for child in children {
            let file_type = child.file_type()?;
            let name = child.file_name().to_string_lossy().into_owned();
            if file_type.is_symlink() {
                warn!("skipping symlink {}", child.path().display());
                continue;
            }
            if file_type.is_dir() {
                let summary =
                    self.import_dir_inner(&child.path(), piece_size, Some(name.clone()))?;
                entries.push(DirEntry {
                    name,
                    hash: summary.root,
                    kind: ObjectKind::Directory,
                    size: summary.total_size,
                });
            } else if file_type.is_file() {
                let manifest = self.import_file(&child.path(), piece_size, Some(name.clone()))?;
                entries.push(DirEntry {
                    name,
                    hash: manifest.root,
                    kind: ObjectKind::File,
                    size: manifest.size,
                });
            } else {
                warn!("skipping special file {}", child.path().display());
            }
        }

        let manifest = DirManifest::new(entries)?;
        self.write_dir_manifest(&manifest, display_name.as_deref())
    }

    /// Change the local display name of a directory without changing its
    /// content hash.
    pub fn set_dir_name(&self, root: ContentHash, name: Option<String>) -> Result<()> {
        let name = name.filter(|name| !name.is_empty());
        match &name {
            Some(name) => {
                fs::write(self.dir_name_path(root), name)
                    .with_context(|| format!("write directory name for {}", root.short()))?;
            }
            None => {
                let _ = fs::remove_file(self.dir_name_path(root));
            }
        }
        if let Some(summary) = self.dirs.write().unwrap().get_mut(&root) {
            summary.name = name;
        }
        self.invalidate_inventory_cache();
        Ok(())
    }

    fn write_dir_manifest(
        &self,
        manifest: &DirManifest,
        display_name: Option<&str>,
    ) -> Result<DirSummary> {
        let root = manifest.root()?;
        let data = manifest.encode()?;
        let temp = self.new_temp("dir-")?;
        {
            let mut writer = BufWriter::new(temp.as_file());
            writer.write_all(&data)?;
            writer.flush()?;
        }
        temp.as_file()
            .sync_all()
            .context("fsync directory manifest")?;
        temp.persist(self.dir_manifest_path(root))
            .map_err(|e| e.error)
            .context("commit directory manifest")?;
        sync_dir(&self.dir_dir)?;

        if let Some(name) = display_name.filter(|name| !name.is_empty()) {
            fs::write(self.dir_name_path(root), name)
                .with_context(|| format!("write directory name for {}", root.short()))?;
        }

        let summary = manifest.summary(
            display_name
                .filter(|name| !name.is_empty())
                .map(str::to_owned),
            unix_now(),
        )?;
        self.dirs.write().unwrap().insert(root, summary.clone());
        self.invalidate_inventory_cache();
        Ok(summary)
    }

    fn write_manifest(&self, manifest: &Manifest) -> Result<()> {
        let data = manifest.encode()?;
        let temp = self.new_temp("manifest-")?;
        {
            let mut writer = BufWriter::new(temp.as_file());
            writer.write_all(&data)?;
            writer.flush()?;
        }
        temp.as_file().sync_all().context("fsync manifest")?;
        temp.persist(self.manifest_path(manifest.root))
            .map_err(|e| e.error)
            .context("commit manifest")?;
        sync_dir(&self.manifest_dir)
    }

    pub fn read_manifest(&self, root: ContentHash) -> Result<Manifest> {
        let path = self.manifest_path(root);
        let data = fs::read(&path).with_context(|| format!("read manifest {}", path.display()))?;
        let manifest = Manifest::decode(&data)?;
        if manifest.root != root {
            bail!("manifest root does not match requested hash");
        }
        Ok(manifest)
    }

    pub fn read_dir_manifest(&self, root: ContentHash) -> Result<DirManifest> {
        let path = self.dir_manifest_path(root);
        let data = fs::read(&path)
            .with_context(|| format!("read directory manifest {}", path.display()))?;
        let manifest = DirManifest::decode(&data)?;
        let actual = manifest.root()?;
        if actual != root {
            bail!("directory manifest hash does not match requested hash");
        }
        Ok(manifest)
    }

    /// Store a directory manifest fetched from the network.
    pub fn store_dir_manifest(
        &self,
        manifest: &DirManifest,
        display_name: Option<String>,
    ) -> Result<DirSummary> {
        self.write_dir_manifest(manifest, display_name.as_deref())
    }

    /// Read a contiguous range of pieces from a blob.
    pub fn read_chunk(&self, manifest: &Manifest, start: u32, count: u32) -> Result<Vec<u8>> {
        if count == 0 {
            bail!("empty chunk request");
        }
        if start >= manifest.piece_count() {
            bail!("chunk start {} out of range", start);
        }
        if count > MAX_PIECES_PER_REQUEST {
            bail!("chunk requests more than {MAX_PIECES_PER_REQUEST} pieces");
        }
        let end = (start + count).min(manifest.piece_count());
        let start_byte = manifest.piece_offset(start);
        let end_byte = if end == manifest.piece_count() {
            manifest.size
        } else {
            manifest.piece_offset(end)
        };
        let len = (end_byte - start_byte) as usize;

        let mut file = File::open(self.blob_path(manifest.root))
            .with_context(|| format!("open blob {}", manifest.root.short()))?;
        file.seek(SeekFrom::Start(start_byte))?;
        let mut data = vec![0u8; len];
        file.read_exact(&mut data)?;
        Ok(data)
    }

    /// Open (or create) the partial download file for `root`.
    pub fn open_partial(&self, root: ContentHash) -> Result<File> {
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.partial_path(root))
            .context("open partial download")
    }

    /// Verify which pieces already exist in a partial download.
    pub fn verify_partial(&self, manifest: &Manifest) -> Result<Vec<bool>> {
        let count = manifest.piece_count() as usize;
        let mut verified = vec![false; count];
        let path = self.partial_path(manifest.root);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(verified),
            Err(err) => return Err(err).context("open partial download"),
        };
        let length = file.metadata()?.len();
        let mut buffer = vec![0u8; manifest.piece_size as usize];
        for index in 0..manifest.piece_count() {
            let offset = manifest.piece_offset(index);
            let len = manifest.piece_len(index)? as usize;
            if offset + len as u64 > length {
                break;
            }
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buffer[..len])?;
            if ContentHash::of(&buffer[..len]) == manifest.pieces[index as usize] {
                verified[index as usize] = true;
            }
        }
        Ok(verified)
    }

    /// Verify and write one piece at its file offset.
    ///
    /// Uses positional writes so several fetch workers can share one file
    /// handle for disjoint piece ranges without seeking or locking.
    pub fn write_piece_at(
        &self,
        file: &File,
        manifest: &Manifest,
        index: u32,
        data: &[u8],
    ) -> Result<()> {
        use std::os::unix::fs::FileExt;

        manifest.verify_piece(index, data)?;
        file.write_all_at(data, manifest.piece_offset(index))
            .with_context(|| format!("write piece {index}"))?;
        Ok(())
    }

    /// Verify a complete partial download and atomically promote it to a blob.
    pub fn finalize_partial(&self, manifest: &Manifest) -> Result<()> {
        let partial_path = self.partial_path(manifest.root);
        let mut file = File::open(&partial_path).context("open partial download")?;
        if file.metadata()?.len() != manifest.size {
            bail!("partial download has wrong length");
        }
        let mut hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 1024 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let root = ContentHash::from_hasher(hasher);
        if root != manifest.root {
            let _ = fs::remove_file(&partial_path);
            bail!("downloaded file failed BLAKE3 verification");
        }
        file.sync_all().context("fsync partial download")?;
        drop(file);

        let blob_path = self.blob_path(manifest.root);
        if blob_path.exists() {
            let _ = fs::remove_file(&partial_path);
        } else {
            fs::rename(&partial_path, &blob_path).context("promote partial to blob")?;
            sync_dir(&self.blob_dir)?;
        }
        self.write_manifest(manifest)?;
        self.files
            .write()
            .unwrap()
            .insert(manifest.root, manifest.summary()?);
        self.invalidate_inventory_cache();
        Ok(())
    }

    /// Copy a stored file to a user-visible location.
    pub fn export(&self, root: ContentHash, output: Option<&Path>) -> Result<PathBuf> {
        let manifest = self.read_manifest(root)?;
        let blob = self.blob_path(root);
        if !blob.exists() {
            bail!("blob {} is missing", root.short());
        }

        let destination = match output {
            Some(path) => {
                if path.is_dir() {
                    path.join(safe_file_name(&manifest))
                } else {
                    path.to_path_buf()
                }
            }
            None => std::env::current_dir()?.join(safe_file_name(&manifest)),
        };
        if destination == blob {
            return Ok(destination);
        }
        if fs::symlink_metadata(&destination).is_ok() {
            bail!(
                "refusing to overwrite existing file or symlink {}",
                destination.display()
            );
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;

        let temp = tempfile::Builder::new()
            .prefix(".meshvault-")
            .tempfile_in(parent)
            .context("create export staging file")?;
        {
            let mut input = File::open(&blob)?;
            let mut output = BufWriter::new(temp.as_file());
            std::io::copy(&mut input, &mut output)?;
            output.flush()?;
        }
        temp.as_file().sync_all().context("fsync exported file")?;
        temp.persist(&destination)
            .map_err(|e| e.error)
            .context("commit exported file")?;
        Ok(destination)
    }

    /// Remove one object (file blob or directory listing).  Child objects of a
    /// directory are not removed automatically because they may be shared.
    pub fn remove(&self, root: ContentHash) -> Result<bool> {
        let known_file = self.files.write().unwrap().remove(&root).is_some();
        let known_dir = self.dirs.write().unwrap().remove(&root).is_some();
        let _ = fs::remove_file(self.manifest_path(root));
        let _ = fs::remove_file(self.blob_path(root));
        let _ = fs::remove_file(self.partial_path(root));
        let _ = fs::remove_file(self.dir_manifest_path(root));
        let _ = fs::remove_file(self.dir_name_path(root));
        if known_file || known_dir {
            self.invalidate_inventory_cache();
        }
        Ok(known_file || known_dir)
    }

    /// Recursively remove a directory/file tree.
    ///
    /// Children that are still referenced by another directory manifest are
    /// preserved.  The target tree's manifests are removed first, so objects
    /// stop being advertised even if the process dies partway through.
    pub fn remove_tree(&self, root: ContentHash) -> Result<usize> {
        let target = self.collect_reachable(root);
        let live = self.collect_live_objects(&target);

        let mut objects: Vec<_> = target.into_iter().collect();
        objects.sort_by(|a, b| {
            let a_dir = self.has_dir(*a);
            let b_dir = self.has_dir(*b);
            b_dir.cmp(&a_dir)
        });
        let mut removed = 0usize;
        for object in objects {
            if !live.contains(&object) && self.remove(object)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn collect_reachable(&self, root: ContentHash) -> HashSet<ContentHash> {
        let mut reachable = HashSet::new();
        let mut stack = vec![root];
        while let Some(hash) = stack.pop() {
            if !reachable.insert(hash) {
                continue;
            }
            if self.has_dir(hash)
                && let Ok(manifest) = self.read_dir_manifest(hash)
            {
                for entry in manifest.entries {
                    if reachable.insert(entry.hash) && entry.kind == ObjectKind::Directory {
                        stack.push(entry.hash);
                    }
                }
            }
        }
        reachable
    }

    /// Objects reachable from directory manifests outside the target tree.
    fn collect_live_objects(&self, target: &HashSet<ContentHash>) -> HashSet<ContentHash> {
        let mut live = HashSet::new();
        let mut stack: Vec<ContentHash> = self
            .dirs
            .read()
            .unwrap()
            .keys()
            .filter(|root| !target.contains(root))
            .copied()
            .collect();
        while let Some(hash) = stack.pop() {
            if !live.insert(hash) {
                continue;
            }
            if let Ok(manifest) = self.read_dir_manifest(hash) {
                for entry in manifest.entries {
                    if live.insert(entry.hash) && entry.kind == ObjectKind::Directory {
                        stack.push(entry.hash);
                    }
                }
            }
        }
        live
    }

    pub fn blob_path_for(&self, root: ContentHash) -> PathBuf {
        self.blob_path(root)
    }
}

fn read_full(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err).context("read input file"),
        }
    }
    Ok(filled)
}

fn safe_file_name(manifest: &Manifest) -> String {
    let candidate = manifest
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or("download");
    sanitize_name(candidate).unwrap_or_else(|| manifest.root.to_hex())
}

pub fn sanitize_name(candidate: &str) -> Option<String> {
    let name = Path::new(candidate)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(candidate);
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '\0') {
                '_'
            } else {
                c
            }
        })
        .take(128)
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        None
    } else {
        Some(cleaned)
    }
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn metadata_timestamp(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("fsync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp_file(dir: &Path, name: &str, size: usize) -> PathBuf {
        let path = dir.join(name);
        let mut data = vec![0u8; size];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index.wrapping_mul(31)) as u8;
        }
        fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn import_read_export_remove() {
        let temp = tempfile::tempdir().unwrap();
        let source = write_temp_file(temp.path(), "input.bin", 100_000);
        let store = Store::open(&temp.path().join("repo")).unwrap();

        let manifest = store
            .import_file(&source, 16 * 1024, Some("sample.bin".into()))
            .unwrap();
        assert_eq!(manifest.size, 100_000);
        assert_eq!(manifest.piece_count(), 7);
        assert!(store.has(manifest.root));

        let chunk = store.read_chunk(&manifest, 0, 3).unwrap();
        assert_eq!(chunk.len(), 3 * 16 * 1024);
        manifest.verify_piece(0, &chunk[..16 * 1024]).unwrap();

        let output = temp.path().join("out.bin");
        let exported = store.export(manifest.root, Some(&output)).unwrap();
        assert_eq!(fs::read(exported).unwrap(), fs::read(&source).unwrap());

        assert!(store.remove(manifest.root).unwrap());
        assert!(!store.has(manifest.root));
    }

    #[test]
    fn reopening_store_rebuilds_index() {
        let temp = tempfile::tempdir().unwrap();
        let source = write_temp_file(temp.path(), "input.bin", 4096);
        let repo = temp.path().join("repo");
        {
            let store = Store::open(&repo).unwrap();
            store.import_file(&source, 4096, None).unwrap();
        }
        let store = Store::open(&repo).unwrap();
        assert_eq!(store.file_count(), 1);
    }

    #[test]
    fn detects_bad_piece() {
        let temp = tempfile::tempdir().unwrap();
        let source = write_temp_file(temp.path(), "input.bin", 4096);
        let store = Store::open(&temp.path().join("repo")).unwrap();
        let manifest = store.import_file(&source, 4096, None).unwrap();
        let mut bad = vec![0u8; 4096];
        assert!(manifest.verify_piece(0, &bad).is_err());
        bad.copy_from_slice(&fs::read(&source).unwrap());
        manifest.verify_piece(0, &bad).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_symlink_destination() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let source = write_temp_file(temp.path(), "source.bin", 4096);
        let store = Store::open(&temp.path().join("repo")).unwrap();
        let manifest = store.import_file(&source, 4096, None).unwrap();

        let victim = temp.path().join("victim.txt");
        fs::write(&victim, b"do not overwrite").unwrap();
        let link = temp.path().join("output.bin");
        symlink(&victim, &link).unwrap();

        assert!(store.export(manifest.root, Some(&link)).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"do not overwrite");
    }

    #[test]
    fn recursive_remove_preserves_shared_children() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let store = Store::open(&repo).unwrap();

        let tree_a = temp.path().join("tree-a");
        let tree_b = temp.path().join("tree-b");
        fs::create_dir_all(&tree_a).unwrap();
        fs::create_dir_all(&tree_b).unwrap();
        let shared = write_temp_file(&tree_a, "shared.bin", 4096);
        fs::copy(&shared, tree_b.join("shared.bin")).unwrap();
        write_temp_file(&tree_b, "only-b.bin", 2048);

        let a = store.import_dir(&tree_a, 4096).unwrap();
        let b = store.import_dir(&tree_b, 4096).unwrap();
        let shared_hash = ContentHash::of(&fs::read(&shared).unwrap());
        assert!(store.has_file(shared_hash));

        let removed = store.remove_tree(a.root).unwrap();
        assert!(removed >= 1);
        assert!(!store.has_dir(a.root));
        assert!(store.has_dir(b.root));
        assert!(store.has_file(shared_hash));

        store.remove_tree(b.root).unwrap();
        assert!(!store.has_dir(b.root));
        assert!(!store.has_file(shared_hash));
    }

    #[test]
    fn inventory_cache_tracks_mutations() {
        let temp = tempfile::tempdir().unwrap();
        let source = write_temp_file(temp.path(), "cached.bin", 2048);
        let store = Store::open(&temp.path().join("repo")).unwrap();

        let empty = store.inventory_snapshot();
        let empty_digest = store.inventory_digest();
        assert!(empty.is_empty());

        let manifest = store.import_file(&source, 4096, None).unwrap();
        let populated = store.inventory_snapshot();
        assert_eq!(populated.len(), 1);
        assert_ne!(store.inventory_digest(), empty_digest);

        assert!(store.remove(manifest.root).unwrap());
        assert!(store.inventory_snapshot().is_empty());
    }

    #[test]
    fn imports_directory_tree() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("tree");
        fs::create_dir_all(input.join("nested")).unwrap();
        write_temp_file(&input, "a.txt", 10);
        write_temp_file(&input.join("nested"), "b.txt", 20);

        let repo = temp.path().join("repo");
        let store = Store::open(&repo).unwrap();
        let summary = store.import_dir(&input, 4096).unwrap();
        assert_eq!(summary.entries, 2);
        assert_eq!(summary.total_size, 30);
        assert!(store.has_dir(summary.root));

        let manifest = store.read_dir_manifest(summary.root).unwrap();
        assert_eq!(manifest.entries[0].name, "a.txt");
        assert_eq!(manifest.entries[1].kind, ObjectKind::Directory);

        // Reopen and make sure both file and directory indexes recover.
        drop(store);
        let store = Store::open(&repo).unwrap();
        assert_eq!(store.dir_count(), 2);
        assert_eq!(store.file_count(), 2);
        assert!(store.object_summary(summary.root).is_some());
    }
}
