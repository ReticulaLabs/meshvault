//! Reliable, bandwidth-aware message transport over one Reticulum link.
//!
//! The session splits application messages into link-MDU-sized frames and
//! tracks a bitmap of received frames.  The receiver periodically returns a
//! compact ACK bitmap; the sender retransmits only frames still missing.  This
//! gives selective repeat without Reticulum's expensive per-packet proofs and
//! without forcing application messages to fit in a single packet.
//!
//! Transfer sizing is adaptive.  The first chunk is deliberately one piece;
//! after that, measured throughput determines how many pieces are requested.
//! Slow LoRa links stay at one piece, while a fast LAN link grows to the
//! configured maximum within a few chunks.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use log::{debug, warn};
use reticulum_sdk::destination::link::{Link, LinkId};
use reticulum_sdk::identity::Identity;
use reticulum_sdk::transport::Transport;
use tokio::sync::{Mutex, Notify, OnceCell, RwLock, mpsc, oneshot};

use crate::hash::ContentHash;
use crate::wire::{
    ChunkMessage, Control, ControlEnvelope, FLAG_BURST_END, Frame, KIND_ACK, KIND_CHUNK,
    KIND_CONTROL, MAX_MESSAGE_BYTES, ack_bitmap_len, bitmap_get, bitmap_set,
    max_frames_per_message, max_message_bytes_for_mdu, split_message,
};

const ACK_INTERVAL: Duration = Duration::from_millis(100);
/// Estimated non-payload overhead of an ACK on the wire (link header,
/// encryption token, and margin).  Partial ACKs are only sent after the
/// receiver has accumulated at least this many bytes plus the bitmap itself.
const ACK_SIZE_MARGIN: usize = 96;
const SEND_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_FRAME_ATTEMPTS: u8 = 12;
const MAX_REASSEMBLY_AGE: Duration = Duration::from_secs(120);

/// Conservative maximum link MTU.  The initiator controls the MTU signalled in
/// a Reticulum link request, so never let an inbound peer select an arbitrarily
/// large link/decrypt buffer or an unbounded frame count.
pub const MAX_LINK_MTU: usize = 4096;

/// Verified links normally have one message in flight, but allow a few
/// reassemblies for reordering/retransmission.
const MAX_REASSEMBLIES: usize = 4;
/// Before identity verification only a Hello is expected.  A second slot
/// absorbs a retransmitted Hello without allowing an attacker to accumulate
/// reassembly state.
const MAX_PRE_VERIFY_REASSEMBLIES: usize = 2;
/// Maximum encoded size of a pre-verification control message.
const MAX_PRE_VERIFY_MESSAGE_BYTES: usize = 16 * 1024;
/// Maximum frame count before verification, independent of link MTU.
const MAX_PRE_VERIFY_FRAMES: usize = 64;
/// Total in-progress receive bytes per link, across all reassemblies.
const MAX_INBOUND_BUFFER_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct PeerHello {
    pub dest: String,
    pub identity: String,
    pub name: Option<String>,
    pub objects: u32,
    pub inventory: ContentHash,
}

#[derive(Debug)]
pub enum Incoming {
    Control {
        request: u32,
        response: bool,
        body: Control,
    },
    Chunk(ChunkMessage),
}

#[derive(Clone, Copy, Debug)]
struct InitialParams {
    rate_bps: f64,
    window: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LinkBudget {
    pub mdu: usize,
    pub rtt: Duration,
    pub rate_bps: f64,
    pub window: usize,
    pub max_message_bytes: usize,
}

struct SendState {
    frames: Vec<Vec<u8>>,
    acked: Vec<bool>,
    sent_at: Vec<Option<Instant>>,
    attempts: Vec<u8>,
    acked_count: usize,
}

struct Reassembly {
    kind: u8,
    total: u16,
    frames: Vec<Option<Vec<u8>>>,
    received: usize,
    bytes: usize,
    /// Payload bytes received since the last ACK, including duplicate frames.
    /// Duplicates count so a lost ACK can be recovered by retransmission, but
    /// the peer must still send at least as many bytes as the ACK costs.
    bytes_since_ack: usize,
    bitmap: Vec<u8>,
    last_ack: Instant,
    last_progress: Instant,
}

#[derive(Default)]
struct TransferStats {
    /// Exponentially weighted effective throughput in bits/second.  Zero
    /// means "no measurement yet".
    rate_bps: f64,
}

impl TransferStats {
    fn record(&mut self, bytes: usize, elapsed: Duration) {
        if bytes == 0 || elapsed.as_secs_f64() <= 0.0 {
            return;
        }
        let sample = (bytes as f64 * 8.0) / elapsed.as_secs_f64();
        if !sample.is_finite() || sample <= 0.0 {
            return;
        }
        self.rate_bps = if self.rate_bps == 0.0 {
            sample
        } else {
            0.45 * sample + 0.55 * self.rate_bps
        };
    }
}

pub struct LinkSession {
    pub link_id: LinkId,
    pub link: Arc<Mutex<Link>>,
    pub outbound: bool,
    transport: Transport,
    next_msg_id: AtomicU32,
    send_lock: Mutex<()>,
    outgoing: Mutex<HashMap<u32, Arc<Mutex<SendState>>>>,
    incoming_msgs: Mutex<HashMap<u32, Reassembly>>,
    pending: Mutex<HashMap<u32, oneshot::Sender<Incoming>>>,
    incoming_tx: mpsc::Sender<Incoming>,
    ack_notify: Notify,
    stats: Mutex<TransferStats>,
    initial: OnceCell<InitialParams>,
    closed: AtomicBool,
    hello: RwLock<Option<PeerHello>>,
    /// Peer destination bound once during verification.  All peer/inventory
    /// attribution uses this value, never a later Hello.
    verified_peer: RwLock<Option<LinkId>>,
    remote_identity: RwLock<Option<Identity>>,
    verified: AtomicBool,
}

impl LinkSession {
    pub fn new(
        link_id: LinkId,
        link: Arc<Mutex<Link>>,
        transport: Transport,
        outbound: bool,
        incoming_tx: mpsc::Sender<Incoming>,
    ) -> Self {
        Self {
            link_id,
            link,
            outbound,
            transport,
            next_msg_id: AtomicU32::new(1),
            send_lock: Mutex::new(()),
            outgoing: Mutex::new(HashMap::new()),
            incoming_msgs: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            incoming_tx,
            ack_notify: Notify::new(),
            stats: Mutex::new(TransferStats::default()),
            initial: OnceCell::new(),
            closed: AtomicBool::new(false),
            hello: RwLock::new(None),
            verified_peer: RwLock::new(None),
            remote_identity: RwLock::new(None),
            verified: AtomicBool::new(false),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    pub fn is_verified(&self) -> bool {
        self.verified.load(Ordering::Relaxed)
    }

    pub fn mark_verified(&self) {
        self.verified.store(true, Ordering::Relaxed);
    }

    /// Bind the authenticated peer destination to this session.  The binding is
    /// immutable for the lifetime of the link.
    pub async fn bind_verified_peer(&self, peer: LinkId) {
        let mut binding = self.verified_peer.write().await;
        if binding.is_none() {
            *binding = Some(peer);
        }
    }

    pub async fn verified_peer(&self) -> Option<LinkId> {
        *self.verified_peer.read().await
    }

    pub async fn set_hello(&self, hello: PeerHello) {
        *self.hello.write().await = Some(hello);
    }

    pub async fn hello(&self) -> Option<PeerHello> {
        self.hello.read().await.clone()
    }

    pub async fn set_remote_identity(&self, identity: Identity) {
        *self.remote_identity.write().await = Some(identity);
    }

    pub async fn remote_identity(&self) -> Option<Identity> {
        *self.remote_identity.read().await
    }

    /// Mark the session dead and wake blocked senders/requesters.
    pub async fn mark_closed(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.pending.lock().await.clear();
        self.ack_notify.notify_waiters();
    }

    /// Effective transfer parameters for this link.
    pub async fn budget(&self) -> Result<LinkBudget> {
        let (mdu, rtt, mtu) = {
            let link = self.link.lock().await;
            (link.mdu(), *link.rtt(), link.mtu())
        };
        if mtu > MAX_LINK_MTU {
            bail!("link MTU {mtu} exceeds the {MAX_LINK_MTU}-byte safety limit");
        }
        if mdu <= crate::wire::HEADER_LEN + 1 {
            bail!("link MDU too small");
        }
        let rtt = rtt.max(Duration::from_millis(1));
        let measured = self.stats.lock().await.rate_bps;
        let initial = self.initial_params().await;
        let rate_bps = if measured > 0.0 {
            measured
        } else {
            initial.rate_bps
        };
        let window = if measured > 0.0 {
            let bdp = (rate_bps / 8.0) * rtt.as_secs_f64();
            ((bdp / mdu as f64).ceil() as usize).clamp(4, 128)
        } else {
            initial.window
        };
        Ok(LinkBudget {
            mdu,
            rtt,
            rate_bps,
            window,
            max_message_bytes: max_message_bytes_for_mdu(mdu),
        })
    }

    /// Estimate the initial rate/window once.  Reticulum exposes a bitrate for
    /// radio interfaces; TCP usually does not, so treat TCP/backbone as a fast
    /// reliable link rather than collapsing to one frame per RTT.
    async fn initial_params(&self) -> InitialParams {
        if let Some(params) = self.initial.get() {
            return *params;
        }
        let (mdu, rtt, iface) = {
            let link = self.link.lock().await;
            (link.mdu(), *link.rtt(), link.attached_interface())
        };
        let rtt = rtt.max(Duration::from_millis(1));
        let (bitrate, iface_type) = {
            let manager = self.transport.iface_manager();
            let manager = manager.lock().await;
            let bitrate = iface.and_then(|iface| manager.interface_bitrate(&iface));
            let iface_type = iface
                .and_then(|iface| {
                    manager
                        .interface_info_list()
                        .into_iter()
                        .find(|info| info.address == iface)
                        .map(|info| info.interface_type)
                })
                .unwrap_or_default();
            (bitrate, iface_type)
        };
        let lower = iface_type.to_ascii_lowercase();
        let rate_bps = bitrate
            .filter(|rate| rate.is_finite() && *rate > 0.0)
            .unwrap_or_else(|| {
                if lower.contains("tcp") || lower.contains("backbone") {
                    10_000_000.0
                } else {
                    (mdu as f64 * 8.0 / rtt.as_secs_f64()).clamp(100.0, 10_000_000.0)
                }
            });
        let bdp = (rate_bps / 8.0) * rtt.as_secs_f64();
        let window = ((bdp / mdu.max(1) as f64).ceil() as usize).clamp(4, 128);
        let params = InitialParams { rate_bps, window };
        debug!(
            "link initial budget: iface={} rate={}bps window={} rtt={:?}",
            iface_type, rate_bps, window, rtt
        );
        let _ = self.initial.set(params);
        *self.initial.get().unwrap()
    }

    /// Choose how many pieces to request next, capped by the link's message
    /// size and `max_chunk_bytes`.
    pub async fn chunk_plan(
        &self,
        piece_size: u32,
        remaining_pieces: u32,
        max_chunk_bytes: u64,
    ) -> Result<(u32, LinkBudget)> {
        let budget = self.budget().await?;
        let piece_size = piece_size.max(1) as u64;
        let measured = self.stats.lock().await.rate_bps;

        let pieces_by_rate = if measured == 0.0 {
            1
        } else {
            let target_secs = (2.0 * budget.rtt.as_secs_f64()).max(0.5);
            let target_bytes = (measured / 8.0) * target_secs;
            (target_bytes / piece_size as f64).ceil().max(1.0) as u32
        };

        let by_message = (budget
            .max_message_bytes
            .saturating_sub(crate::wire::CHUNK_HEADER_LEN) as u64
            / piece_size)
            .max(1) as u32;
        let by_config = (max_chunk_bytes / piece_size).max(1) as u32;
        let plan = pieces_by_rate
            .min(by_message)
            .min(by_config)
            .min(remaining_pieces.max(1));
        Ok((plan.max(1), budget))
    }

    pub async fn record_chunk(&self, bytes: usize, elapsed: Duration) {
        self.stats.lock().await.record(bytes, elapsed);
    }

    /// Generous timeout for a request of `bytes` payload bytes, scaled to the
    /// link's measured rate.  This keeps small control requests snappy on TCP
    /// while allowing large manifests/inventory pages to complete on LoRa.
    pub async fn transfer_timeout(&self, bytes: usize) -> Duration {
        let Ok(budget) = self.budget().await else {
            return Duration::from_secs(120);
        };
        let transmission = bytes as f64 * 8.0 / budget.rate_bps.max(1.0);
        Duration::from_secs_f64(
            (transmission * 4.0 + budget.rtt.as_secs_f64() * 4.0 + 60.0).min(3600.0),
        )
    }

    fn next_id(&self) -> u32 {
        loop {
            let id = self.next_msg_id.fetch_add(1, Ordering::Relaxed);
            if id != 0 {
                return id;
            }
        }
    }

    // ─── Incoming frames ────────────────────────────────────────────────────

    pub async fn handle_data(&self, data: &[u8]) -> Result<()> {
        if self.is_closed() {
            return Ok(());
        }
        let frame = Frame::decode(data)?;
        match frame.kind {
            KIND_ACK => {
                self.handle_ack(&frame).await;
                Ok(())
            }
            KIND_CONTROL | KIND_CHUNK => self.handle_message_frame(frame).await,
            other => {
                debug!("ignoring unknown frame kind {other}");
                Ok(())
            }
        }
    }

    async fn handle_ack(&self, frame: &Frame<'_>) {
        let state = self.outgoing.lock().await.get(&frame.msg_id).cloned();
        let Some(state) = state else {
            return;
        };
        let mut state = state.lock().await;
        let total = state.frames.len().min(frame.total as usize);
        for index in 0..total {
            if bitmap_get(frame.payload, index as u16) && !state.acked[index] {
                state.acked[index] = true;
                state.acked_count += 1;
            }
        }
        drop(state);
        self.ack_notify.notify_one();
    }

    async fn handle_message_frame(&self, frame: Frame<'_>) -> Result<()> {
        if frame.total == 0 {
            bail!("frame total is zero");
        }
        if frame.seq >= frame.total {
            bail!("frame sequence out of range");
        }
        let budget = self.budget().await?;
        let verified = self.is_verified();
        let frame_capacity = budget
            .mdu
            .checked_sub(crate::wire::HEADER_LEN)
            .filter(|capacity| *capacity > 0)
            .context("link MDU too small")?;
        if !inbound_message_allowed(
            verified,
            frame.kind,
            frame.total,
            frame_capacity,
            budget.mdu,
        ) {
            debug!(
                "dropping oversized/pre-verification frame on {} (kind={} total={} mdu={})",
                self.link_id, frame.kind, frame.total, budget.mdu
            );
            return Ok(());
        }

        let mut ack = None;
        let complete = {
            let mut messages = self.incoming_msgs.lock().await;
            let max_reassemblies = if verified {
                MAX_REASSEMBLIES
            } else {
                MAX_PRE_VERIFY_REASSEMBLIES
            };
            prune_reassemblies(&mut messages, max_reassemblies);

            if let Some(entry) = messages.get(&frame.msg_id)
                && (entry.total != frame.total || entry.kind != frame.kind)
            {
                // Never let a peer mutate a message's shape mid-reassembly.
                messages.remove(&frame.msg_id);
                bail!("inconsistent message metadata");
            }

            let buffered: usize = messages.values().map(|entry| entry.bytes).sum();
            let duplicate = messages
                .get(&frame.msg_id)
                .map(|entry| entry.frames[frame.seq as usize].is_some())
                .unwrap_or(false);
            if !duplicate && buffered.saturating_add(frame.payload.len()) > MAX_INBOUND_BUFFER_BYTES
            {
                debug!(
                    "dropping frame on {}: inbound reassembly buffer limit reached",
                    self.link_id
                );
                return Ok(());
            }

            let entry = messages.entry(frame.msg_id).or_insert_with(|| Reassembly {
                kind: frame.kind,
                total: frame.total,
                frames: vec![None; frame.total as usize],
                received: 0,
                bytes: 0,
                bytes_since_ack: 0,
                bitmap: vec![0u8; ack_bitmap_len(frame.total)],
                last_ack: Instant::now(),
                last_progress: Instant::now(),
            });
            let index = frame.seq as usize;
            let duplicate = entry.frames[index].is_some();
            if !duplicate {
                entry.frames[index] = Some(frame.payload.to_vec());
                entry.received += 1;
                entry.bytes = entry.bytes.saturating_add(frame.payload.len());
                entry.last_progress = Instant::now();
                bitmap_set(&mut entry.bitmap, frame.seq);
            }
            // Count duplicate payload too: it lets a lost ACK be recovered by
            // retransmission, but never gives more ACK bytes than data bytes.
            entry.bytes_since_ack = entry.bytes_since_ack.saturating_add(frame.payload.len());
            let complete = entry.received == entry.total as usize;

            if ack_is_due(AckContext {
                verified,
                complete,
                burst_end: frame.flags & FLAG_BURST_END != 0,
                duplicate,
                received: entry.received,
                bytes_since_ack: entry.bytes_since_ack,
                since_last_ack: entry.last_ack.elapsed(),
                total: entry.total,
            }) {
                entry.last_ack = Instant::now();
                entry.bytes_since_ack = 0;
                ack = Some((entry.total, entry.bitmap.clone()));
            }
            complete
        };

        if let Some((total, bitmap)) = ack {
            self.send_ack(frame.msg_id, total, &bitmap).await;
        }

        if complete {
            let finished = self.incoming_msgs.lock().await.remove(&frame.msg_id);
            let Some(finished) = finished else {
                return Ok(());
            };
            if finished.received != finished.total as usize {
                return Ok(());
            }
            // Final all-ones ACK so the sender can release its state even if
            // the last partial ACK was lost.
            let mut final_bitmap = vec![0u8; ack_bitmap_len(finished.total)];
            for bit in 0..finished.total {
                bitmap_set(&mut final_bitmap, bit);
            }
            self.send_ack(frame.msg_id, finished.total, &final_bitmap)
                .await;

            let mut body = Vec::new();
            for part in finished.frames {
                let Some(part) = part else {
                    return Ok(());
                };
                body.extend_from_slice(&part);
            }
            self.deliver_message(finished.kind, frame.msg_id, body)
                .await;
        }
        Ok(())
    }

    async fn deliver_message(&self, kind: u8, _msg_id: u32, body: Vec<u8>) {
        let incoming = match kind {
            KIND_CONTROL => match ControlEnvelope::decode(&body) {
                Ok(envelope) => Incoming::Control {
                    request: envelope.request,
                    response: envelope.response,
                    body: envelope.body,
                },
                Err(err) => {
                    warn!("invalid control message: {err:#}");
                    return;
                }
            },
            KIND_CHUNK => match ChunkMessage::decode(&body) {
                Ok(chunk) => Incoming::Chunk(chunk),
                Err(err) => {
                    warn!("invalid chunk message: {err:#}");
                    return;
                }
            },
            _ => return,
        };

        if !self.is_verified() && !pre_verification_message_allowed(&incoming) {
            debug!(
                "dropping non-Hello message received before link verification on {}",
                self.link_id
            );
            return;
        }

        let correlation = match &incoming {
            Incoming::Control {
                request, response, ..
            } => response.then_some(*request),
            Incoming::Chunk(chunk) => Some(chunk.request),
        };
        if let Some(request) = correlation.filter(|request| *request != 0) {
            let sender = self.pending.lock().await.remove(&request);
            if let Some(sender) = sender {
                let _ = sender.send(incoming);
                return;
            }
        }
        if let Err(err) = self.incoming_tx.try_send(incoming) {
            warn!("dropping inbound message: {err}");
        }
    }

    async fn send_ack(&self, msg_id: u32, total: u16, bitmap: &[u8]) {
        let mdu = {
            let link = self.link.lock().await;
            link.mdu()
        };
        let frame = Frame {
            kind: KIND_ACK,
            flags: 0,
            msg_id,
            seq: 0,
            total,
            payload: bitmap,
        };
        let encoded = frame.encode();
        if encoded.len() > mdu {
            warn!("ACK bitmap does not fit link MDU; dropping");
            return;
        }
        let packet = {
            let link = self.link.lock().await;
            match link.data_packet(&encoded) {
                Ok(packet) => packet,
                Err(err) => {
                    debug!("cannot build ACK packet: {err:?}");
                    return;
                }
            }
        };
        self.transport.send_packet(packet).await;
    }

    // ─── Outgoing messages ─────────────────────────────────────────────────

    /// Send one complete message and wait until all of its frames are ACKed.
    pub async fn send_message(&self, kind: u8, body: Vec<u8>) -> Result<()> {
        let guard = self.send_lock.lock().await;
        let result = self.send_message_inner(kind, body).await;
        drop(guard);
        result
    }

    async fn send_message_inner(&self, kind: u8, body: Vec<u8>) -> Result<()> {
        if self.is_closed() {
            bail!("link is closed");
        }
        if body.len() > MAX_MESSAGE_BYTES {
            bail!("message too large");
        }
        let budget = self.budget().await?;
        let frame_payload = budget
            .mdu
            .checked_sub(crate::wire::HEADER_LEN)
            .filter(|len| *len > 0)
            .context("link MDU too small")?;
        let msg_id = self.next_id();
        let frames = split_message(kind, msg_id, &body, frame_payload)?;
        let total = frames.len();
        if total > max_frames_per_message(budget.mdu) {
            bail!("message requires too many frames for this link");
        }

        let frame_time = Duration::from_secs_f64(
            (budget.mdu as f64 * 8.0 / budget.rate_bps.max(1.0)).max(0.0001),
        );
        let burst_time = frame_time.as_secs_f64() * budget.window as f64 * 1.5;
        let retransmit_timeout =
            Duration::from_secs_f64(budget.rtt.as_secs_f64() * 3.0 + burst_time + 0.5)
                .clamp(Duration::from_millis(400), Duration::from_secs(300));
        let estimated = (body.len() as f64 * 8.0 / budget.rate_bps.max(1.0)).max(1.0);
        let deadline = Instant::now()
            + Duration::from_secs_f64(estimated * 4.0 + 60.0)
                .min(Duration::from_secs(24 * 60 * 60));

        let state = Arc::new(Mutex::new(SendState {
            frames,
            acked: vec![false; total],
            sent_at: vec![None; total],
            attempts: vec![0; total],
            acked_count: 0,
        }));
        self.outgoing.lock().await.insert(msg_id, state.clone());

        let outcome = self
            .drive_send(
                msg_id,
                state.clone(),
                budget.window,
                retransmit_timeout,
                deadline,
            )
            .await;
        self.outgoing.lock().await.remove(&msg_id);

        outcome?;
        Ok(())
    }

    async fn drive_send(
        &self,
        msg_id: u32,
        state: Arc<Mutex<SendState>>,
        window: usize,
        retransmit_timeout: Duration,
        deadline: Instant,
    ) -> Result<usize> {
        let mut transferred = 0usize;
        loop {
            if self.is_closed() {
                bail!("link closed during transfer");
            }
            if Instant::now() > deadline {
                bail!("message transfer timed out");
            }

            let mut to_send: Vec<(u16, Vec<u8>)> = Vec::new();
            let all_done = {
                let mut state = state.lock().await;
                if state.acked_count == state.frames.len() {
                    true
                } else {
                    let now = Instant::now();
                    let mut inflight = state
                        .acked
                        .iter()
                        .enumerate()
                        .filter(|(index, acked)| {
                            !**acked
                                && state.sent_at[*index]
                                    .map(|at| now.duration_since(at) < retransmit_timeout)
                                    .unwrap_or(false)
                        })
                        .count();
                    for index in 0..state.frames.len() {
                        if state.acked[index] {
                            continue;
                        }
                        let due = state.sent_at[index]
                            .map(|at| now.duration_since(at) >= retransmit_timeout)
                            .unwrap_or(true);
                        if !due {
                            continue;
                        }
                        // Unsent frames respect the congestion window.
                        // Retransmissions are always allowed so a single lost
                        // frame cannot stall the whole message.
                        if state.sent_at[index].is_none() && inflight >= window {
                            continue;
                        }
                        if state.attempts[index] >= MAX_FRAME_ATTEMPTS {
                            bail!("frame {index} exceeded retry limit");
                        }
                        to_send.push((index as u16, state.frames[index].clone()));
                        state.sent_at[index] = Some(now);
                        state.attempts[index] += 1;
                        inflight += 1;
                    }
                    false
                }
            };
            if all_done {
                break;
            }

            let burst_end = to_send.last().map(|(seq, _)| *seq);
            for (seq, mut frame) in to_send {
                if Some(seq) == burst_end {
                    mark_burst_end(&mut frame);
                }
                let packet = {
                    let link = self.link.lock().await;
                    link.data_packet(&frame)
                        .with_context(|| format!("build frame {seq} packet"))?
                };
                transferred += frame.len();
                self.transport.send_packet(packet).await;
            }

            let _ = tokio::time::timeout(SEND_POLL_INTERVAL, self.ack_notify.notified()).await;
        }
        let state = state.lock().await;
        if state.acked_count != state.frames.len() {
            bail!("message ended without full acknowledgement");
        }
        let _ = msg_id;
        Ok(transferred)
    }

    // ─── Request / response helpers ────────────────────────────────────────

    pub async fn request(&self, body: Control, timeout: Duration) -> Result<Control> {
        match self.request_any(body, timeout).await? {
            Incoming::Control { body, .. } => Ok(body),
            Incoming::Chunk(_) => bail!("unexpected chunk response"),
        }
    }

    pub async fn request_chunk(&self, body: Control, timeout: Duration) -> Result<ChunkMessage> {
        match self.request_any(body, timeout).await? {
            Incoming::Chunk(chunk) => Ok(chunk),
            Incoming::Control {
                body: Control::Error { code, message },
                ..
            } => bail!("peer error {code}: {message}"),
            Incoming::Control { body, .. } => bail!("unexpected control response: {body:?}"),
        }
    }

    async fn request_any(&self, body: Control, timeout: Duration) -> Result<Incoming> {
        let request = self.next_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request, tx);
        let envelope = ControlEnvelope {
            request,
            response: false,
            body,
        };
        let encoded = envelope.encode()?;

        if let Err(err) = self.send_message(KIND_CONTROL, encoded).await {
            self.pending.lock().await.remove(&request);
            return Err(err);
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(incoming)) => Ok(incoming),
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&request);
                bail!("link closed while waiting for response")
            }
            Err(_) => {
                self.pending.lock().await.remove(&request);
                bail!("request timed out")
            }
        }
    }

    pub async fn respond(&self, request: u32, body: Control) -> Result<()> {
        let encoded = ControlEnvelope {
            request,
            response: true,
            body,
        }
        .encode()?;
        self.send_message(KIND_CONTROL, encoded).await
    }

    pub async fn send_unsolicited(&self, body: Control) -> Result<()> {
        let encoded = ControlEnvelope {
            request: 0,
            response: false,
            body,
        }
        .encode()?;
        self.send_message(KIND_CONTROL, encoded).await
    }

    pub async fn send_chunk(&self, chunk: ChunkMessage) -> Result<()> {
        self.send_message(KIND_CHUNK, chunk.encode()).await
    }
}

fn mark_burst_end(frame: &mut [u8]) {
    if frame.len() >= crate::wire::HEADER_LEN {
        let flags = u16::from_be_bytes([frame[6], frame[7]]) | FLAG_BURST_END;
        frame[6..8].copy_from_slice(&flags.to_be_bytes());
    }
}

#[derive(Clone, Copy)]
struct AckContext {
    verified: bool,
    complete: bool,
    burst_end: bool,
    duplicate: bool,
    received: usize,
    bytes_since_ack: usize,
    since_last_ack: Duration,
    total: u16,
}

fn ack_wire_cost(total: u16) -> usize {
    crate::wire::HEADER_LEN + ack_bitmap_len(total) + ACK_SIZE_MARGIN
}

fn ack_is_due(ctx: AckContext) -> bool {
    if ctx.complete {
        // A completed message has necessarily delivered its full payload;
        // even a tiny complete message produces only a tiny ACK.
        return true;
    }
    if !ctx.verified || ctx.bytes_since_ack < ack_wire_cost(ctx.total) {
        return false;
    }
    ctx.burst_end
        || (ctx.duplicate && ctx.since_last_ack >= ACK_INTERVAL)
        || ctx.received.is_multiple_of(128)
}

fn pre_verification_message_allowed(incoming: &Incoming) -> bool {
    matches!(
        incoming,
        Incoming::Control {
            response: false,
            body: Control::Hello { .. },
            ..
        }
    )
}

fn inbound_message_allowed(
    verified: bool,
    kind: u8,
    total: u16,
    frame_capacity: usize,
    mdu: usize,
) -> bool {
    if total == 0 || frame_capacity == 0 {
        return false;
    }
    let Some(declared_max) = (total as usize).checked_mul(frame_capacity) else {
        return false;
    };
    if !verified {
        if kind != KIND_CONTROL || total as usize > MAX_PRE_VERIFY_FRAMES {
            return false;
        }
        return declared_max <= MAX_PRE_VERIFY_MESSAGE_BYTES;
    }
    declared_max <= max_message_bytes_for_mdu(mdu)
}

fn prune_reassemblies(messages: &mut HashMap<u32, Reassembly>, max_reassemblies: usize) {
    messages.retain(|_, entry| entry.last_progress.elapsed() < MAX_REASSEMBLY_AGE);
    while messages.len() >= max_reassemblies {
        let Some(oldest) = messages
            .iter()
            .min_by_key(|(_, entry)| entry.last_progress)
            .map(|(id, _)| *id)
        else {
            break;
        };
        messages.remove(&oldest);
    }
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn pre_verification_accepts_only_small_control_messages() {
        let mdu = crate::wire::HEADER_LEN + 413;
        assert!(inbound_message_allowed(false, KIND_CONTROL, 1, 413, mdu));
        assert!(inbound_message_allowed(false, KIND_CONTROL, 39, 413, mdu));
        assert!(!inbound_message_allowed(false, KIND_CONTROL, 40, 413, mdu));
        assert!(!inbound_message_allowed(false, KIND_CONTROL, 65, 1, mdu));
        assert!(!inbound_message_allowed(false, KIND_CHUNK, 1, 413, mdu));
        assert!(!inbound_message_allowed(false, KIND_ACK, 1, 413, mdu));
    }

    #[test]
    fn verified_messages_are_capped_at_receive_side() {
        let mdu = crate::wire::HEADER_LEN + 413;
        assert!(inbound_message_allowed(true, KIND_CHUNK, 3304, 413, mdu));
        assert!(!inbound_message_allowed(true, KIND_CHUNK, 3305, 413, mdu));

        // A peer cannot use a huge signalled MTU to declare an enormous
        // message: the receiver cap is still MAX_MESSAGE_BYTES.
        assert!(!inbound_message_allowed(
            true,
            KIND_CHUNK,
            u16::MAX,
            2 * 1024 * 1024,
            2 * 1024 * 1024 + crate::wire::HEADER_LEN
        ));
    }

    #[test]
    fn only_hello_is_delivered_before_verification() {
        let hello = Incoming::Control {
            request: 0,
            response: false,
            body: Control::Hello {
                version: crate::wire::PROTOCOL_VERSION,
                dest: "00000000000000000000000000000000".into(),
                identity: "00000000000000000000000000000000".into(),
                name: None,
                objects: 0,
                inventory: ContentHash::of(b"inventory"),
            },
        };
        assert!(pre_verification_message_allowed(&hello));

        let request = Incoming::Control {
            request: 1,
            response: false,
            body: Control::GetChunk {
                root: ContentHash::of(b"file"),
                start: 0,
                count: 1,
            },
        };
        assert!(!pre_verification_message_allowed(&request));

        let response = Incoming::Control {
            request: 1,
            response: true,
            body: Control::Hello {
                version: crate::wire::PROTOCOL_VERSION,
                dest: "00000000000000000000000000000000".into(),
                identity: "00000000000000000000000000000000".into(),
                name: None,
                objects: 0,
                inventory: ContentHash::of(b"inventory"),
            },
        };
        assert!(!pre_verification_message_allowed(&response));
    }

    fn ack_ctx(total: u16, bytes_since_ack: usize, since_last_ack: Duration) -> AckContext {
        AckContext {
            verified: true,
            complete: false,
            burst_end: true,
            duplicate: false,
            received: 10,
            bytes_since_ack,
            since_last_ack,
            total,
        }
    }

    #[test]
    fn partial_acks_require_byte_credit() {
        let total = 3304u16;
        let cost = ack_wire_cost(total);

        assert!(ack_is_due(ack_ctx(total, cost, Duration::ZERO)));
        assert!(!ack_is_due(ack_ctx(total, cost - 1, Duration::ZERO)));
        assert!(!ack_is_due(AckContext {
            verified: false,
            ..ack_ctx(total, usize::MAX, Duration::ZERO)
        }));
        assert!(ack_is_due(AckContext {
            complete: true,
            ..ack_ctx(total, 0, Duration::ZERO)
        }));
    }

    #[test]
    fn duplicate_acks_are_rate_limited_and_byte_credited() {
        let total = 3304u16;
        let cost = ack_wire_cost(total);
        let duplicate = |since: Duration, bytes: usize| AckContext {
            burst_end: false,
            duplicate: true,
            bytes_since_ack: bytes,
            since_last_ack: since,
            ..ack_ctx(total, 0, Duration::ZERO)
        };
        assert!(ack_is_due(duplicate(ACK_INTERVAL, cost)));
        assert!(!ack_is_due(duplicate(
            ACK_INTERVAL - Duration::from_millis(1),
            cost
        )));
        assert!(!ack_is_due(duplicate(ACK_INTERVAL, cost - 1)));
    }

    #[test]
    fn ack_cost_scales_with_bitmap() {
        assert!(ack_wire_cost(1) < ack_wire_cost(64));
        assert!(ack_wire_cost(64) < ack_wire_cost(3304));
    }

    #[test]
    fn zero_length_metadata_is_rejected() {
        assert!(!inbound_message_allowed(true, KIND_CONTROL, 0, 413, 431));
        assert!(!inbound_message_allowed(false, KIND_CONTROL, 1, 0, 500));
    }
}
