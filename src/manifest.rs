//! File manifests: the verifiable description of a stored file.
//!
//! The repository is content addressed by the BLAKE3 hash of the complete
//! file (`root`).  Because a file is transferred in pieces, each piece has its
//! own BLAKE3 hash listed in the manifest.  A receiver can therefore verify
//! data as it lands, resume an interrupted download, and reject a malicious or
//! corrupt peer without waiting for the entire file.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

pub const MANIFEST_VERSION: u32 = 1;
pub const MIN_PIECE_SIZE: u32 = 1024;
pub const MAX_PIECE_SIZE: u32 = 16 * 1024 * 1024;
pub const DEFAULT_PIECE_SIZE: u32 = 16 * 1024;
/// Hard ceiling for a single manifest. Keeps control messages bounded.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

/// Description of one complete file in the repository.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    /// BLAKE3 of the entire file.
    pub root: ContentHash,
    pub size: u64,
    /// Every piece except possibly the last is exactly this long.
    pub piece_size: u32,
    /// BLAKE3 hashes of the file pieces, in order.
    pub pieces: Vec<ContentHash>,
    /// Original file name, if known.
    pub name: Option<String>,
    /// Unix creation timestamp.
    pub created_at: u64,
}

/// Small inventory entry exchanged between peers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestSummary {
    pub root: ContentHash,
    pub size: u64,
    pub piece_size: u32,
    pub pieces: u32,
    pub name: Option<String>,
    /// BLAKE3 of the canonical manifest encoding. Lets a peer prove the
    /// manifest it serves is the one its inventory advertised.
    pub manifest_hash: ContentHash,
    pub created_at: u64,
}

/// A directory manifest is a content-addressed listing of child objects.
///
/// Its BLAKE3 "directory hash" is computed over the canonical encoding of the
/// sorted entry list.  Names live in the *parent* entry, not in the manifest
/// itself, so the same directory content has the same hash regardless of what
/// it is called.  Entries can reference files or nested directories, forming a
/// DAG that can be listed and fetched one level at a time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirManifest {
    pub version: u32,
    pub entries: Vec<DirEntry>,
}

pub const DIR_MANIFEST_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub hash: ContentHash,
    pub kind: ObjectKind,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirSummary {
    pub root: ContentHash,
    pub entries: u32,
    pub total_size: u64,
    pub name: Option<String>,
    pub created_at: u64,
}

/// Inventory entry for either object type.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObjectSummary {
    File(ManifestSummary),
    Directory(DirSummary),
}

impl ObjectSummary {
    pub fn root(&self) -> ContentHash {
        match self {
            Self::File(file) => file.root,
            Self::Directory(dir) => dir.root,
        }
    }

    pub fn manifest_hash(&self) -> ContentHash {
        match self {
            Self::File(file) => file.manifest_hash,
            Self::Directory(dir) => dir.root,
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Self::File(file) => file.size,
            Self::Directory(dir) => dir.total_size,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::File(file) => file.name.as_deref(),
            Self::Directory(dir) => dir.name.as_deref(),
        }
    }

    pub fn kind(&self) -> ObjectKind {
        match self {
            Self::File(_) => ObjectKind::File,
            Self::Directory(_) => ObjectKind::Directory,
        }
    }

    pub fn display_name(&self) -> String {
        self.name()
            .filter(|n| !n.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| self.root().short())
    }

    pub fn file(&self) -> Option<&ManifestSummary> {
        match self {
            Self::File(file) => Some(file),
            Self::Directory(_) => None,
        }
    }

    /// Validate peer-advertised inventory metadata before retaining it.
    pub fn validate_inventory(&self) -> Result<()> {
        match self {
            Self::File(file) => {
                if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&file.piece_size) {
                    bail!("inventory file has an invalid piece size");
                }
                if file.size > 0 {
                    let expected = file.size.div_ceil(file.piece_size as u64);
                    if expected > u32::MAX as u64 || expected != file.pieces as u64 {
                        bail!("inventory file has an invalid piece count");
                    }
                } else if file.pieces != 0 {
                    bail!("empty inventory file has piece hashes");
                }
                if let Some(name) = &file.name {
                    validate_manifest_name(name)?;
                }
            }
            Self::Directory(dir) => {
                if let Some(name) = &dir.name {
                    validate_manifest_name(name)?;
                }
            }
        }
        Ok(())
    }
}

impl From<ManifestSummary> for ObjectSummary {
    fn from(value: ManifestSummary) -> Self {
        Self::File(value)
    }
}

impl From<DirSummary> for ObjectSummary {
    fn from(value: DirSummary) -> Self {
        Self::Directory(value)
    }
}

impl Manifest {
    pub fn new(
        root: ContentHash,
        size: u64,
        piece_size: u32,
        pieces: Vec<ContentHash>,
        name: Option<String>,
        created_at: u64,
    ) -> Result<Self> {
        let manifest = Self {
            version: MANIFEST_VERSION,
            root,
            size,
            piece_size,
            pieces,
            name,
            created_at,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Number of pieces. An empty file has zero pieces. Valid manifests are
    /// guaranteed to fit in `u32` by [`Self::validate`]; invalid in-memory
    /// values saturate rather than truncating.
    pub fn piece_count(&self) -> u32 {
        if self.size == 0 {
            0
        } else {
            u32::try_from(self.size.div_ceil(self.piece_size as u64)).unwrap_or(u32::MAX)
        }
    }

    /// Length of piece `index` in bytes.
    pub fn piece_len(&self, index: u32) -> Result<u32> {
        if index >= self.piece_count() {
            bail!("piece {index} out of range (count {})", self.piece_count());
        }
        let start = (index as u64)
            .checked_mul(self.piece_size as u64)
            .context("piece offset overflow")?;
        let end = start
            .checked_add(self.piece_size as u64)
            .context("piece end overflow")?
            .min(self.size);
        let len = end.saturating_sub(start);
        u32::try_from(len).context("piece length overflow")
    }

    /// Byte offset of a piece in the file.
    pub fn piece_offset(&self, index: u32) -> u64 {
        index as u64 * self.piece_size as u64
    }

    /// Byte length of a contiguous range of pieces.
    pub fn range_len(&self, start: u32, count: u32) -> Result<u64> {
        if count == 0 || start >= self.piece_count() {
            bail!("invalid piece range");
        }
        let end = start.saturating_add(count).min(self.piece_count());
        let start_byte = self.piece_offset(start);
        let end_byte = if end == self.piece_count() {
            self.size
        } else {
            self.piece_offset(end)
        };
        end_byte
            .checked_sub(start_byte)
            .context("invalid piece range ordering")
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("encode manifest")
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_MANIFEST_BYTES {
            bail!("manifest exceeds size limit");
        }
        let manifest: Self = serde_json::from_slice(data).context("decode manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn manifest_hash(&self) -> Result<ContentHash> {
        Ok(ContentHash::of(&self.encode()?))
    }

    pub fn summary(&self) -> Result<ManifestSummary> {
        Ok(ManifestSummary {
            root: self.root,
            size: self.size,
            piece_size: self.piece_size,
            pieces: self.piece_count(),
            name: self.name.clone(),
            manifest_hash: self.manifest_hash()?,
            created_at: self.created_at,
        })
    }

    pub fn verify_piece(&self, index: u32, data: &[u8]) -> Result<()> {
        let expected_len = self.piece_len(index)?;
        if data.len() != expected_len as usize {
            bail!(
                "piece {index} has length {}, expected {expected_len}",
                data.len()
            );
        }
        let expected = self
            .pieces
            .get(index as usize)
            .context("piece hash missing from manifest")?;
        let actual = ContentHash::of(data);
        if actual != *expected {
            bail!("piece {index} hash mismatch");
        }
        Ok(())
    }

    /// Validate structural invariants. This does not read the blob.
    pub fn validate(&self) -> Result<()> {
        if self.version != MANIFEST_VERSION {
            bail!("unsupported manifest version {}", self.version);
        }
        if !(MIN_PIECE_SIZE..=MAX_PIECE_SIZE).contains(&self.piece_size) {
            bail!("invalid piece size {}", self.piece_size);
        }
        let expected_u64 = if self.size == 0 {
            0
        } else {
            self.size.div_ceil(self.piece_size as u64)
        };
        let expected = u32::try_from(expected_u64)
            .context("manifest has more pieces than the protocol supports")?;
        if self.pieces.len() != expected as usize {
            bail!(
                "manifest has {} piece hashes, expected {expected}",
                self.pieces.len()
            );
        }
        if expected > 0 {
            let last = expected - 1;
            let offset = (last as u64)
                .checked_mul(self.piece_size as u64)
                .context("final piece offset overflow")?;
            let expected_last = self
                .size
                .checked_sub(offset)
                .context("final piece offset exceeds file size")?;
            if expected_last == 0 || expected_last > self.piece_size as u64 {
                bail!("inconsistent final piece length");
            }
        }
        if let Some(name) = &self.name {
            validate_manifest_name(name)?;
        }
        Ok(())
    }
}

impl ManifestSummary {
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| self.root.short())
    }
}

impl DirSummary {
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| self.root.short())
    }
}

impl DirManifest {
    pub fn new(mut entries: Vec<DirEntry>) -> Result<Self> {
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        let manifest = Self {
            version: DIR_MANIFEST_VERSION,
            entries,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != DIR_MANIFEST_VERSION {
            bail!("unsupported directory manifest version {}", self.version);
        }
        if self.entries.len() > 1_000_000 {
            bail!("directory has too many entries");
        }
        self.total_size().context("directory size overflow")?;
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            validate_entry_name(&entry.name)?;
            if let Some(previous) = previous
                && previous >= entry.name.as_str()
            {
                bail!("directory entries are not uniquely sorted");
            }
            previous = Some(&entry.name);
            if entry.kind == ObjectKind::File && entry.size == 0 {
                // Empty files are valid; this branch intentionally does not
                // reject them. Kept explicit for future invariants.
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("encode directory manifest")
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_MANIFEST_BYTES {
            bail!("directory manifest exceeds size limit");
        }
        let manifest: Self = serde_json::from_slice(data).context("decode directory manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// The BLAKE3 directory hash.
    pub fn root(&self) -> Result<ContentHash> {
        Ok(ContentHash::of(&self.encode()?))
    }

    pub fn total_size(&self) -> Result<u64> {
        self.entries.iter().try_fold(0u64, |total, entry| {
            total
                .checked_add(entry.size)
                .context("directory size overflow")
        })
    }

    pub fn summary(&self, name: Option<String>, created_at: u64) -> Result<DirSummary> {
        let entries = u32::try_from(self.entries.len())
            .context("directory has more entries than the protocol supports")?;
        Ok(DirSummary {
            root: self.root()?,
            entries,
            total_size: self.total_size()?,
            name,
            created_at,
        })
    }

    pub fn get(&self, name: &str) -> Option<&DirEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

fn validate_manifest_name(name: &str) -> Result<()> {
    if name.len() > 255 {
        bail!("manifest file name is too long");
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        bail!("manifest file name contains a path separator");
    }
    if name.chars().any(char::is_control) {
        bail!("manifest file name contains control characters");
    }
    Ok(())
}

fn validate_entry_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("empty directory entry name");
    }
    if name == "." || name == ".." {
        bail!("invalid directory entry name {name:?}");
    }
    if name.contains('/') || name.contains('\\') || name.contains('\0') {
        bail!("directory entry name contains a path separator: {name:?}");
    }
    if name.len() > 255 {
        bail!("directory entry name is too long");
    }
    if name.chars().any(char::is_control) {
        bail!("directory entry name contains control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(size: u64, piece_size: u32) -> Manifest {
        let count = size.div_ceil(piece_size as u64) as u32;
        Manifest::new(
            ContentHash::of(b"test"),
            size,
            piece_size,
            vec![ContentHash::of(b"piece"); count as usize],
            Some("test.bin".into()),
            0,
        )
        .unwrap()
    }

    #[test]
    fn piece_lengths_cover_file() {
        let m = manifest(100_000, 16 * 1024);
        assert_eq!(m.piece_count(), 7);
        let sum: u64 = (0..m.piece_count())
            .map(|i| m.piece_len(i).unwrap() as u64)
            .sum();
        assert_eq!(sum, 100_000);
        assert_eq!(m.piece_len(6).unwrap(), 100_000 - 6 * 16 * 1024);
    }

    #[test]
    fn empty_file_has_no_pieces() {
        let mut m = manifest(0, 16 * 1024);
        m.pieces.clear();
        assert_eq!(m.piece_count(), 0);
        assert!(m.validate().is_ok());
    }

    #[test]
    fn manifest_round_trip() {
        let m = manifest(50_000, 4096);
        let bytes = m.encode().unwrap();
        let decoded = Manifest::decode(&bytes).unwrap();
        assert_eq!(m, decoded);
        assert_eq!(m.manifest_hash().unwrap(), decoded.manifest_hash().unwrap());
    }

    #[test]
    fn directory_hash_is_deterministic_and_sorted() {
        let a = DirEntry {
            name: "a.txt".into(),
            hash: ContentHash::of(b"a"),
            kind: ObjectKind::File,
            size: 1,
        };
        let b = DirManifest::new(vec![
            DirEntry {
                name: "z.txt".into(),
                hash: ContentHash::of(b"z"),
                kind: ObjectKind::File,
                size: 1,
            },
            a.clone(),
        ])
        .unwrap();
        let c = DirManifest::new(vec![a]).unwrap();
        assert_eq!(b.entries[0].name, "a.txt");
        assert_ne!(b.root().unwrap(), c.root().unwrap());
        let decoded = DirManifest::decode(&b.encode().unwrap()).unwrap();
        assert_eq!(b, decoded);
        assert_eq!(b.root().unwrap(), decoded.root().unwrap());
    }

    #[test]
    fn rejects_too_many_pieces() {
        let too_large = (u32::MAX as u64).saturating_mul(4096).saturating_add(1);
        let manifest = Manifest::new(
            ContentHash::of(b"huge"),
            too_large,
            4096,
            Vec::new(),
            None,
            0,
        );
        assert!(manifest.is_err());
    }

    #[test]
    fn rejects_bad_manifest_names() {
        assert!(
            Manifest::new(
                ContentHash::of(b"name"),
                0,
                4096,
                Vec::new(),
                Some("../escape".into()),
                0,
            )
            .is_err()
        );
        assert!(
            Manifest::new(
                ContentHash::of(b"name"),
                0,
                4096,
                Vec::new(),
                Some("bad\nname".into()),
                0,
            )
            .is_err()
        );
        assert!(
            Manifest::new(
                ContentHash::of(b"name"),
                0,
                4096,
                Vec::new(),
                Some("x".repeat(256)),
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn range_len_saturates_instead_of_overflowing() {
        let manifest = manifest(100_000, 16 * 1024);
        let len = manifest.range_len(1, u32::MAX).unwrap();
        assert_eq!(len, manifest.size - 16 * 1024);
    }

    #[test]
    fn directory_rejects_size_overflow() {
        let entries = vec![
            DirEntry {
                name: "a".into(),
                hash: ContentHash::of(b"a"),
                kind: ObjectKind::File,
                size: u64::MAX,
            },
            DirEntry {
                name: "b".into(),
                hash: ContentHash::of(b"b"),
                kind: ObjectKind::File,
                size: 1,
            },
        ];
        assert!(DirManifest::new(entries).is_err());
    }

    #[test]
    fn inventory_summaries_are_bounded() {
        let bad_name = ObjectSummary::File(ManifestSummary {
            root: ContentHash::of(b"f"),
            size: 0,
            piece_size: 4096,
            pieces: 0,
            name: Some("x".repeat(256)),
            manifest_hash: ContentHash::of(b"m"),
            created_at: 0,
        });
        assert!(bad_name.validate_inventory().is_err());

        let bad_pieces = ObjectSummary::File(ManifestSummary {
            root: ContentHash::of(b"f"),
            size: 10_000,
            piece_size: 4096,
            pieces: 1,
            name: None,
            manifest_hash: ContentHash::of(b"m"),
            created_at: 0,
        });
        assert!(bad_pieces.validate_inventory().is_err());
    }

    #[test]
    fn directory_rejects_bad_names() {
        let entry = DirEntry {
            name: "../escape".into(),
            hash: ContentHash::of(b"x"),
            kind: ObjectKind::File,
            size: 1,
        };
        assert!(DirManifest::new(vec![entry]).is_err());
    }
}
