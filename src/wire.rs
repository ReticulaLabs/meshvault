//! Compact wire protocol carried inside Reticulum link data packets.
//!
//! Every application message is split into frames that fit the negotiated
//! link MDU.  Frames carry a small fixed header (18 bytes).  Reliability is
//! provided by message-level bitmap ACKs, *not* by Reticulum's per-packet
//! proofs: one ACK per message (plus occasional partial ACKs on lossy links)
//! is far cheaper than a signature/proof for every small frame.
//!
//! ```text
//! frame: MAGIC | version | kind | flags | msg_id | seq | total | len | payload
//!        4       1         1      2       4        2     2       2
//! ```
//!
//! `total` is the number of frames in the message.  An ACK frame reuses the
//! same header with `kind = ACK` and a bitmap payload where bit `i` means
//! "frame `i` received".  The bitmap must fit in one link packet; this bounds
//! the maximum message size per link automatically.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;
use crate::manifest::ObjectSummary;

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAGIC: [u8; 4] = *b"MVL1";
pub const HEADER_LEN: usize = 18;

pub const KIND_CONTROL: u8 = 1;
pub const KIND_CHUNK: u8 = 2;
pub const KIND_ACK: u8 = 3;

/// Last frame of a sender burst.  The receiver ACKs immediately on seeing
/// this flag, which avoids timer-driven ACK traffic on slow links.
pub const FLAG_BURST_END: u16 = 0x0001;

/// Upper bound regardless of link MTU.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

/// Control messages are small; reject anything absurd before decoding.
pub const MAX_CONTROL_BYTES: usize = 1024 * 1024;

pub const INVENTORY_PAGE_SIZE: u32 = 64;

#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    pub kind: u8,
    pub flags: u16,
    pub msg_id: u32,
    pub seq: u16,
    pub total: u16,
    pub payload: &'a [u8],
}

impl<'a> Frame<'a> {
    pub fn decode(data: &'a [u8]) -> Result<Self> {
        if data.len() < HEADER_LEN {
            bail!("frame shorter than header");
        }
        if data[..4] != MAGIC {
            bail!("bad frame magic");
        }
        if data[4] != PROTOCOL_VERSION {
            bail!("unsupported wire version {}", data[4]);
        }
        let kind = data[5];
        let flags = u16::from_be_bytes(data[6..8].try_into().unwrap());
        let msg_id = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let seq = u16::from_be_bytes(data[12..14].try_into().unwrap());
        let total = u16::from_be_bytes(data[14..16].try_into().unwrap());
        let len = u16::from_be_bytes(data[16..18].try_into().unwrap()) as usize;
        if data.len() != HEADER_LEN + len {
            bail!("frame length field does not match payload");
        }
        Ok(Self {
            kind,
            flags,
            msg_id,
            seq,
            total,
            payload: &data[HEADER_LEN..],
        })
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&MAGIC);
        out.push(PROTOCOL_VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.msg_id.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.total.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(self.payload);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        self.encode_into(&mut out);
        out
    }
}

/// Split a message body into complete encoded frames.
pub fn split_message(
    kind: u8,
    msg_id: u32,
    body: &[u8],
    max_frame_payload: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_frame_payload == 0 {
        bail!("link MDU too small for wire header");
    }
    if body.len() > MAX_MESSAGE_BYTES {
        bail!("message exceeds maximum size");
    }
    let frame_count = body.len().div_ceil(max_frame_payload).max(1);
    if frame_count > u16::MAX as usize {
        bail!("message needs too many frames");
    }
    let total = frame_count as u16;
    let mut frames = Vec::with_capacity(frame_count);
    for index in 0..frame_count {
        let start = index * max_frame_payload;
        let end = (start + max_frame_payload).min(body.len());
        let payload = if start < body.len() {
            &body[start..end]
        } else {
            &[]
        };
        frames.push(
            Frame {
                kind,
                flags: 0,
                msg_id,
                seq: index as u16,
                total,
                payload,
            }
            .encode(),
        );
    }
    Ok(frames)
}

/// Maximum number of frames a peer can ACK in one packet.  ACK frames use the
/// same header, so the bitmap must fit in `mdu - HEADER_LEN` bytes.
pub fn max_frames_per_message(mdu: usize) -> usize {
    mdu.saturating_sub(HEADER_LEN) * 8
}

/// Maximum chunk message body that can be ACKed over a link with this MDU.
pub fn max_message_bytes_for_mdu(mdu: usize) -> usize {
    let frame_payload = mdu.saturating_sub(HEADER_LEN);
    if frame_payload == 0 {
        return 0;
    }
    MAX_MESSAGE_BYTES.min(max_frames_per_message(mdu) * frame_payload)
}

pub fn ack_bitmap_len(total: u16) -> usize {
    (total as usize).div_ceil(8)
}

pub fn bitmap_set(bitmap: &mut [u8], bit: u16) {
    let index = bit as usize;
    if let Some(byte) = bitmap.get_mut(index / 8) {
        *byte |= 1 << (index % 8);
    }
}

pub fn bitmap_get(bitmap: &[u8], bit: u16) -> bool {
    let index = bit as usize;
    bitmap
        .get(index / 8)
        .map(|byte| byte & (1 << (index % 8)) != 0)
        .unwrap_or(false)
}

// ─── Control messages ───────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlEnvelope {
    /// Request correlation id.  0 for unsolicited messages.
    pub request: u32,
    /// True when this envelope answers `request`.  Requests from the two
    /// directions use independent id spaces, so this flag is required to
    /// avoid mistaking a peer's request for a response to our own.
    pub response: bool,
    pub body: Control,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Control {
    /// Sent once per link after activation.
    Hello {
        version: u8,
        /// Destination hash (16 bytes hex) of the sender.
        dest: String,
        /// Identity hash (16 bytes hex) of the sender.
        identity: String,
        name: Option<String>,
        objects: u32,
        inventory: ContentHash,
    },
    /// Cheap notification that the sender's inventory changed.
    InventoryChanged {
        objects: u32,
        inventory: ContentHash,
    },
    GetInventory {
        page: u32,
    },
    InventoryPage {
        page: u32,
        pages: u32,
        inventory: ContentHash,
        entries: Vec<ObjectSummary>,
    },
    GetManifest {
        root: ContentHash,
    },
    Manifest {
        root: ContentHash,
        manifest_hash: ContentHash,
        data: Vec<u8>,
    },
    GetDirectory {
        root: ContentHash,
    },
    Directory {
        root: ContentHash,
        data: Vec<u8>,
    },
    GetChunk {
        root: ContentHash,
        start: u32,
        count: u32,
    },
    Error {
        code: u16,
        message: String,
    },
    Ping,
    Pong,
}

impl Control {
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).context("encode control message")
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_CONTROL_BYTES {
            bail!("control message too large");
        }
        rmp_serde::from_slice(data).context("decode control message")
    }
}

impl ControlEnvelope {
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).context("encode control envelope")
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_CONTROL_BYTES {
            bail!("control envelope too large");
        }
        rmp_serde::from_slice(data).context("decode control envelope")
    }
}

// ─── Chunk messages ─────────────────────────────────────────────────────────

pub const CHUNK_HEADER_LEN: usize = 4 + 32 + 4 + 4;

#[derive(Debug, Clone)]
pub struct ChunkMessage {
    pub request: u32,
    pub root: ContentHash,
    pub start: u32,
    pub count: u32,
    pub data: Vec<u8>,
}

impl ChunkMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + self.data.len());
        out.extend_from_slice(&self.request.to_be_bytes());
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < CHUNK_HEADER_LEN {
            bail!("chunk message too short");
        }
        let request = u32::from_be_bytes(data[0..4].try_into().unwrap());
        let root = ContentHash::from_slice(&data[4..36])?;
        let start = u32::from_be_bytes(data[36..40].try_into().unwrap());
        let count = u32::from_be_bytes(data[40..44].try_into().unwrap());
        Ok(Self {
            request,
            root,
            start,
            count,
            data: data[CHUNK_HEADER_LEN..].to_vec(),
        })
    }
}

// ─── Announce app-data ─────────────────────────────────────────────────────

/// Compact value carried in Reticulum announce app-data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeAnnounce {
    pub version: u8,
    pub dest: String,
    pub identity: String,
    pub name: Option<String>,
    pub objects: u32,
    pub inventory: ContentHash,
}

impl NodeAnnounce {
    pub fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(self).context("encode announce payload")
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        rmp_serde::from_slice(data).context("decode announce payload")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let frame = Frame {
            kind: KIND_CONTROL,
            flags: FLAG_BURST_END,
            msg_id: 7,
            seq: 2,
            total: 5,
            payload: b"hello",
        };
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded.kind, KIND_CONTROL);
        assert_eq!(decoded.flags, FLAG_BURST_END);
        assert_eq!(decoded.msg_id, 7);
        assert_eq!(decoded.seq, 2);
        assert_eq!(decoded.total, 5);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn split_and_reassemble_order() {
        let body = vec![0xAB; 1000];
        let frames = split_message(KIND_CHUNK, 1, &body, 100).unwrap();
        assert_eq!(frames.len(), 10);
        let mut rebuilt = Vec::new();
        for (index, frame) in frames.iter().enumerate() {
            let frame = Frame::decode(frame).unwrap();
            assert_eq!(frame.seq as usize, index);
            assert_eq!(frame.total, 10);
            rebuilt.extend_from_slice(frame.payload);
        }
        assert_eq!(rebuilt, body);
    }

    #[test]
    fn empty_message_has_one_frame() {
        let frames = split_message(KIND_CONTROL, 3, &[], 100).unwrap();
        assert_eq!(frames.len(), 1);
        let frame = Frame::decode(&frames[0]).unwrap();
        assert_eq!(frame.payload.len(), 0);
    }

    #[test]
    fn bitmap_math() {
        let mut map = [0u8; 2];
        bitmap_set(&mut map, 0);
        bitmap_set(&mut map, 9);
        assert!(bitmap_get(&map, 0));
        assert!(!bitmap_get(&map, 1));
        assert!(bitmap_get(&map, 9));
        assert_eq!(ack_bitmap_len(10), 2);
    }

    #[test]
    fn ack_fits_in_one_frame() {
        for mdu in [64usize, 431, 1984] {
            let frame_payload = mdu - HEADER_LEN;
            let max_frames = max_frames_per_message(mdu);
            assert!(ack_bitmap_len(max_frames as u16) <= frame_payload);
            assert!(max_message_bytes_for_mdu(mdu) > 0);
        }
    }
}
