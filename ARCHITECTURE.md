# MeshVault Architecture

This document explains the design decisions, wire protocol, storage model, and failure behavior. The short version: use Reticulum for identity, encryption, routing, and discovery; put a small content-addressed object layer on top; make bulk transfer reliable and adaptive without wasting mesh airtime.

## Goals and constraints

1. **Work over any Reticulum interface.** A Reticulum link may be a fast TCP backbone or a 366 bps LoRa channel. The same protocol must make progress on both without tuning.
2. **Minimize overhead on constrained links.** Avoid per-packet cryptographic proofs and avoid repeated full inventory broadcasts.
3. **Verify content independently of the transport.** Reticulum authenticates/encrypts the link, but content integrity is enforced with BLAKE3 at piece and file boundaries.
4. **Recover cleanly from crashes and interruptions.** No database that can become half-written; downloads resume.
5. **Be a good mesh citizen.** Bounded peers, bounded link count, bounded message sizes, bounded reassembly memory, paced transfers.
6. **Be simple to operate.** One daemon, one local socket, automatic announce/peer/reconnect/cache behavior.

Non-goals for this version: a global DHT, anonymity, access control, and tit-for-tat swarm accounting.

## Component overview

```text
┌──────────────┐   JSON/Unix socket   ┌──────────────────────────────────────┐
│ meshvault CLI│ ───────────────────► │ Node                                 │
└──────────────┘                      │  ├─ peer manager (announces/links)   │
                                      │  ├─ inventory index + digest         │
                                      │  ├─ fetch orchestration              │
                                      │  ├─ service request handlers         │
                                      │  └─ Store (blobs/manifests/partial)  │
                                      └──────────────┬───────────────────────┘
                                                     │ LinkSession per link
                                                     │  reliable frames, ACKs,
                                                     │  adaptive chunk/window
                                      ┌──────────────▼───────────────────────┐
                                      │ reticulum-sdk Transport              │
                                      │  destinations, links, paths,         │
                                      │  announcements, TCP interfaces       │
                                      └──────────────────────────────────────┘
```

- `Node` owns Reticulum state, peer state, and the repository.
- `LinkSession` is the reliable application-message layer for one Reticulum link.
- `Store` is a crash-safe content-addressed object store.
- The RPC layer only calls public `Node` operations; it has no protocol knowledge.

## Reticulum integration

### Destination and announces

Each instance creates one single-input destination:

```text
app name:  meshvault
aspect:    node
```

The destination address is derived by Reticulum from the node identity and this name. The identity is generated once and persisted in `identity.hex`.

The daemon announces periodically (default 900 s) with a compact MessagePack `NodeAnnounce` in Reticulum's announce app-data:

```rust
NodeAnnounce {
    version: 1,
    dest: "<destination hash hex>",
    identity: "<identity hash hex>",
    name: Option<String>,
    objects: u32,
    inventory: BLAKE3(inventory roots + manifest hashes),
}
```

The payload is kept under 280 bytes; the name is dropped if necessary. The inventory digest is the key optimization: an announce tells a peer *that* the inventory changed without carrying the inventory.

### Peer discovery and link establishment

1. A matching announce is verified by Reticulum and delivered to the node.
2. The destination name hash is compared using its 10-byte name-hash slice (the SDK reconstructs the name from only that prefix).
3. The peer is recorded with hop count and SNR/RSSI metadata.
4. If no link exists and the outbound-peer limit is not reached, the node opens a link.
5. On activation, both sides send a `Hello` control message.
6. The initiator calls Reticulum `link_identify` with its node identity.
7. The responder verifies that the initiator's identity derives the destination hash claimed in `Hello`.
8. The initiator verifies `Hello` against the destination identity it learned from the announce.
9. On success, the peer destination/identity is bound immutably to the session, peer state is created only then, and inventory sync begins.
10. A later `Hello` on the same link is ignored if identical and closes the link if it claims a different destination/identity. Inventory attribution always uses the bound destination, never mutable Hello state.

Both nodes may initiate simultaneously. Each side keeps the **lexicographically smaller link id** and closes the other. This converges without a coordinator. The kept link is the only one used for inventory and transfers.

The daemon acquires an exclusive lock on `daemon.lock` in the data directory before opening the identity or repository. A second daemon for the same repository fails to start, and an RPC bind failure is fatal. Links are bounded by `max_peers` (outbound and pending), `max_links` (total), and `max_known_peers` (retained peer records). Stale disconnected peers are evicted after one hour. Reticulum handles path discovery, multi-hop routing, encryption, and link keepalives.

## Content model

### Files

For a file:

```text
root        = BLAKE3(entire file)
piece_size  = configured fixed size (default 16 KiB)
pieces[i]   = BLAKE3(file[i*piece_size .. min(size, (i+1)*piece_size)])
```

The manifest is canonical JSON:

```json
{
  "version": 1,
  "root": "<64-hex>",
  "size": 20971520,
  "piece_size": 16384,
  "pieces": ["<64-hex>", "..."],
  "name": "report.pdf",
  "created_at": 1760000000
}
```

The *manifest hash* is BLAKE3 of exactly those bytes. Inventory advertises it so a peer cannot substitute a different manifest for the same file root.

### Directories

A directory manifest contains no name and no timestamps, only sorted entries:

```json
{
  "version": 1,
  "entries": [
    {"name":"a.txt","hash":"<file-or-dir hash>","kind":"file","size":1234},
    {"name":"photos","hash":"<dir hash>","kind":"directory","size":4567}
  ]
}
```

The **directory hash** is `BLAKE3(canonical JSON bytes)`. Entries are sorted by name; names cannot contain separators, control characters, `.` or `..`. Because a directory's own name lives in its parent entry, the same content has the same hash regardless of where it is mounted.

This forms a DAG:

```text
dir hash ──► dir manifest ──► child file hashes
                           └► child dir hashes ──► ...
```

Directory manifests are tiny and can be served by a peer that does not hold the child blobs. Retrieval is breadth-first by manifest, one object at a time. Names are not signed separately; they are part of the parent directory hash.

### Inventory

The local inventory is the set of all file and directory summaries:

```rust
enum ObjectSummary {
    File(ManifestSummary),
    Directory(DirSummary),
}
```

The inventory digest is:

```text
BLAKE3( for each object sorted by root:
          root bytes || manifest_hash bytes )
```

If two peers have the same digest, they have the same object set (with overwhelming probability), so no inventory pages need to be exchanged. This is the main reason idle peers consume almost no bandwidth.

## Wire protocol

All application data travels in Reticulum **link data packets** (`PacketContext::None`). Reticulum packet proofs are deliberately *not* enabled: on small frames, a per-packet signature/proof can add roughly 20% overhead. Reliability is handled once per application message instead.

### Frame format

```text
offset  size  field
0       4     magic "MVL1"
4       1     protocol version (1)
5       1     kind: CONTROL(1) | CHUNK(2) | ACK(3)
6       2     flags: bit 0 = BURST_END
8       4     message id
12      2     frame sequence
14      2     frame count
16      2     payload length
18      ...   payload
```

The header is 18 bytes. A frame is split so that `18 + payload <= link.mdu()`. The link MDU is negotiated by Reticulum; MeshVault uses the interoperable 500-byte MTU by default (MDU 431).

### Reliable messages

A logical message is split into frames. The receiver stores frames in a per-message reassembly table and returns a bitmap ACK:

- bit `i` set = frame `i` received
- ACK is itself a normal link data packet with `kind = ACK`, `total` copied from the message, and the bitmap as payload

Sender behavior:

- send up to `window` frames
- mark the last frame of each burst with `BURST_END`
- wait for an ACK
- mark acknowledged frames, retransmit missing frames after an adaptive timeout
- finish when all frames are acknowledged or the retry/deadline limit is reached

Receiver behavior:

- ACK completed messages unconditionally
- for partial messages, ACK only after receiving at least enough payload to cover the estimated ACK wire cost (bitmap + link header + encryption overhead); `BURST_END`, duplicate frames, and periodic progress can trigger that ACK, but never with fewer bytes received
- rate-limit duplicate ACKs; duplicate payload counts toward the byte credit so a lost ACK can be recovered by retransmission
- clamp message size so the ACK bitmap fits in one link packet
- enforce the same 4 MiB message cap on receive as on send
- cap total in-progress receive bytes per link at 4 MiB
- cap total in-progress receive bytes across all links with a shared 64 MiB budget (configurable), including frame-slot overhead
- expire stale reassemblies and bound the number of concurrent reassemblies
- **before identity verification, accept only bounded control messages** — normally the single-frame `Hello`. Chunk frames, non-Hello control messages, oversized messages, and more than two reassemblies are dropped. Peer state is created only after the handshake authenticates the destination/identity.
- cap the signalled link MTU at 4 KiB, since an inbound peer controls the MTU in its link request and could otherwise force oversized decrypt/reassembly buffers

Pre-verification frames are further limited to 64 frames and 16 KiB, and ACKs are sent only for completed pre-verification messages, not for attacker-controlled partial bursts.

The byte-credit rule is the anti-amplification invariant: partial ACK output is never larger than the data received since the previous ACK. A peer cannot send tiny frames with `BURST_END` and receive full-size bitmap ACKs in return.

### Peer service budgets

Each verified peer owns a byte token bucket (`peer_service_bytes_per_sec`, burst `peer_service_burst_bytes`). Inventory pages, file manifests, directory manifests, and chunks are charged an estimated response size with a 64 KiB minimum per request. Exhausted budgets return control error `429`, so a peer cannot turn repeated small requests into unbounded inventory scans or disk/network work.

Inventory responses use a cached, sorted snapshot plus a cached digest. Mutations invalidate both, so serving a page costs only the page slice rather than an O(n) clone and sort per request.

Manifest and directory charge estimates are derived from the stored summary (piece count/name length or entry count/name length), and chunk charges are derived from the requested byte range before the blob is read.

The ACK bitmap means retransmission is selective: only missing frames are resent. One ACK is typically a few bytes; for a 1 MiB chunk at 431-byte payloads, the sender sends ~2,500 frames and the final bitmap is only ~313 bytes.

### Adaptive flow control

The first chunk is deliberately **one piece** (16 KiB by default). This avoids guessing wrong on a slow link. After each completed chunk the receiver records effective throughput (bits/s) as an EWMA.

For the next chunk:

```text
target_seconds = max(0.5, 2 * RTT)
chunk_bytes    = measured_rate * target_seconds
pieces         = clamp(ceil(chunk_bytes / piece_size), 1, max)
```

The chunk is further capped by:

- `max_chunk_bytes` (default 1 MiB)
- the link's maximum message size (ACK bitmap must fit)
- the remaining pieces in the file
- `MAX_PIECES_PER_REQUEST` (256)

The send window is `clamp(BDP / mdu, 4, 128)`, where BDP is measured rate × RTT. For a TCP link with no advertised bitrate, the initial estimate assumes a fast reliable link; for a radio interface Reticulum usually provides a bitrate, which yields a small window automatically.

Consequences:

- On a fast link, the first 16 KiB chunk measures throughput and subsequent chunks jump toward the 1 MiB cap.
- On LoRa, the measured rate keeps the chunk at one piece and the window small.
- One chunk per link is in flight, which simplifies memory bounds and fairness; the adaptive chunk size keeps the pipe reasonably full.

### Multi-source piece scheduling

`PieceProgress` holds two bitmaps: `verified` and `claimed`. A worker claims the first contiguous run of pieces that is neither verified nor claimed, up to its link's chunk plan. Claims are released on failure and marked verified only after the entire chunk has been verified and written.

This gives:

- **No overlapping writes** — workers own disjoint byte ranges.
- **No duplicate work** — a piece is only requested from one peer at a time.
- **Resume compatibility** — pieces already present in the partial file are marked verified before workers start.
- **Failure isolation** — a slow or dishonest peer only loses its claimed range.
- **Bounded state** — two bits per piece plus the manifest, independent of the number of sources.

For a contiguous range, a worker verifies all pieces in memory before writing any of them. If one piece fails, the whole range is released and retried smaller; no half-verified range is recorded.

The manifest layout is chosen by majority preference among candidates. A file root is the same regardless of piece size, but piece hashes are not, so only peers advertising the same manifest hash participate in a given parallel fetch.

### Control messages

Control payloads are MessagePack. The envelope distinguishes requests from responses explicitly:

```rust
ControlEnvelope {
    request: u32,   // correlation id, 0 if unsolicited
    response: bool, // true only on replies
    body: Control,
}
```

The `response` flag is required because each direction has an independent request-id space; without it, a peer's request can accidentally satisfy an outstanding local request.

Operations:

| Operation | Purpose |
|---|---|
| `Hello` | version, destination/identity hashes, name, object count, inventory digest |
| `InventoryChanged` | unsolicited cheap digest update |
| `GetInventory { page }` / `InventoryPage` | paginated object summaries (64/page) |
| `GetManifest { root }` / `Manifest` | file piece manifest |
| `GetDirectory { root }` / `Directory` | directory manifest |
| `GetChunk { root, start, count }` | request a contiguous piece range |
| `Chunk` | chunk response; body = request id, root, start, count, data |
| `Error` | code + message |
| `Ping` / `Pong` | liveness through the same path |

Chunk bodies have a 44-byte header (request id, 32-byte root, start piece, piece count) followed by raw piece bytes. Chunk messages use the same reliable framing as control messages.

## Fetch flow

### File (multi-source)

1. Resolve the root locally or in a connected peer's inventory.
2. Request the file manifest once from the best candidate (fewest hops, then best SNR).
3. Verify the manifest hash against the inventory entry, then discard candidates whose advertised manifest hash differs.
4. Verify which pieces already exist in `partial/<root>.part`; this becomes the initial shared bitmap.
5. A caller cancellation token aborts the fetch when the local RPC connection closes, and `fetch_stall_timeout_secs` aborts a fetch that makes no verified progress.
6. Start up to `fetch_parallelism` workers, one per peer. Each worker:
   - asks its link for an adaptive chunk plan
   - atomically claims a disjoint contiguous range of missing pieces
   - requests that range and verifies every piece before writing any of them
   - writes pieces with positional `pwrite` calls into the shared partial file
   - marks the range verified and claims the next range
7. A failed range is released back to the pool and retried with half as many pieces (up to three attempts on that peer). If the peer still fails, it enters a short cooldown and other workers continue.
8. When every piece is verified, `fsync` the partial file, verify the full BLAKE3 root, atomically promote it to `blobs/`, write the manifest, cache/advertise if configured, and export to the output path.

Workers never overlap piece ranges, and verification-before-write prevents a corrupt chunk from leaving partial state in the shared progress bitmap. The partial file is opened once and shared; `write_at`/`pwrite` avoids seeks and cross-worker locking.

### Directory

1. Fetch the directory manifest and verify its BLAKE3 directory hash.
2. Create a per-get extraction budget (`max_extract_entries`, `max_extract_bytes`).
3. Consume one entry per listed child and the actual manifest size of every file before transfer.
4. Materialize entries in sorted order.
5. Files use the file fetch flow.
6. Child directories recurse, with a depth limit and a stack-based cycle check.
7. Unsafe entry names are rejected/skipped; symlink output paths and pre-existing/symlink child paths are refused; output never escapes the target directory.

## Storage design

Why not a database?

- The object set is content-addressed; the filesystem is already a key-value store keyed by hash.
- Manifests are small and immutable. Startup scans and validates them; there is no separate index that can disagree with the bytes.
- Atomic `tmp → fsync → rename` gives crash safety with no WAL or recovery logic.
- Range reads for piece/chunk serving are direct file reads at known offsets.

If a repository grows to millions of objects, an optional SQLite index could be added as a *cache*; the filesystem remains the source of truth.

Startup behavior:

- Corrupt manifests are ignored with a warning.
- Manifests whose blob is missing/wrong-sized are ignored.
- Orphaned blobs (no manifest) are left in place and reported; deleting user data automatically is worse than wasting space.
- Staging files under `tmp/` are always discarded.

## Local RPC design

- Unix domain socket, mode `0600`.
- Newline-delimited JSON so it can be driven by shell tools.
- One request/response per line; long operations hold their connection.
- The CLI auto-starts the daemon if the socket is not alive, waits for a ping, and then forwards the operation. This is why `meshvault get ...` works without a separate service-management step.
- The daemon only exposes local operations. There is no remote RPC.

## Design decisions and trade-offs

### App-level ACKs instead of Reticulum packet proofs

Reticulum can prove every link data packet, but on a 431-byte frame a proof is a large fraction of the payload. MeshVault proves **application messages** with a bitmap instead. The trade-off is that we implement retransmission and flow control, but we gain selective repeat and much lower overhead on constrained links.

### One chunk in flight per link, several links in parallel

Each link has one reliable chunk message in flight at a time, which keeps memory bounded and avoids streams starving each other. Aggregate throughput comes from fetching disjoint ranges from several peers concurrently. Chunk size is used to fill each individual link.

`fetch_parallelism` bounds the number of peers per file. Candidates are ordered by hop count then SNR; failures trigger a short cooldown so one bad peer does not repeatedly receive large requests.

### Fixed piece size, variable chunk size

Piece hashes must be stable across peers, so pieces are fixed at import time. Chunk size can vary freely because a chunk is just a contiguous range of pieces in one reliable message. This gives both verifiability and budget adaptation.

### Directory hash without names of itself

A directory's own name lives in its parent, matching the useful part of IPFS's model. The local display name is a sidecar and never changes the hash.

### Inventory digest gating

Full inventory exchange is O(objects). A 32-byte digest on announce/hello/change reduces steady-state traffic to near zero for unchanged peers. When the digest matches, peers assume identical inventories without transferring pages. Inventory pages are capped at 64 entries, per-peer inventories at `max_inventory_objects`, and all peer inventories together at `max_inventory_objects_total`. A peer that exceeds a cap is not fully synchronized, and disconnected peers' inventory maps are dropped.

### Conservative Reticulum MTU by default

Larger Reticulum link packets can improve TCP throughput, but are not reliable across every current interface/version combination. The default is the interoperable 500-byte MTU. `link_mtu_discovery = true` opts in on controlled all-modern meshes.

Independently of that option, inbound links are rejected if their signalled MTU exceeds 4 KiB. The initiator controls the MTU in a Reticulum link request, so trusting an unbounded value would let a peer force large SDK decrypt buffers and bypass footprint limits.

## Failure handling

| Failure | Behavior |
|---|---|
| Announce missed | Path/retry handled by Reticulum; periodic announces re-advertise. |
| Link drops mid-transfer | Session closes; that worker's claimed range is released, other workers continue, and later rounds retry it. |
| One source is slow/fails | Its claimed ranges return to the pool; remaining sources finish them. A failed peer cools down for 10 s. |
| Peer sends corrupt data | Piece hash fails; peer is recorded with a last error; retry/other peer. |
| Peer sends wrong manifest | Manifest hash/inventory mismatch rejects it. |
| Duplicate links | Smaller link id kept, other torn down. |
| Inventory changes during pagination | Sync aborts and retries on the next announce/notification. |
| Disk crash mid-import/fetch | Only `tmp/` staging is lost; existing objects remain valid. |
| Crash after blob write before manifest | Orphan blob reported at startup; can be re-imported. |
| RPC client disconnects during get/list | Cancellation token aborts the active operation; worker requests are aborted between joins. |
| Fetch makes no verified progress | Aborts after `fetch_stall_timeout_secs`. |
| Directory extraction exceeds entry/byte budget | Aborts before further file transfer or directory expansion. |
| Second daemon on same repository | Exits immediately because `daemon.lock` is held. |
| Concurrent CLI auto-start | Losing daemon exits; clients keep polling for the winner's RPC socket. |
| Malicious directory cycle | Recursion stack detects and aborts. |
| Oversized request | Bounded before allocation/read. |
| Malformed manifest | Rejected: checked piece-count/size arithmetic, bounded file names, and checked directory size totals. |

## Performance notes

Measured on loopback TCP through Reticulum with the default 500-byte MTU:

- 16 MiB file from two peers: ~0.43 s over loopback TCP (release build), with each source contributing roughly half the pieces.
- 20 MiB file: ~13.5 s including resume from a 1.7 MiB partial download (debug build, single peer) ≈ 1.5 MiB/s.
- Small file/listing/metadata operations complete in milliseconds on a healthy link.
- Idle two-node mesh exchanges periodic 60–900 s announces plus a tiny inventory digest; no full inventory transfer unless content changes.

Release builds and larger link MTUs (where supported) will improve TCP throughput further. On radio links, throughput is dominated by airtime; the protocol keeps chunking at one piece and avoids extra proof traffic.

## Future work

- Longer-term peer scoring/reputation and bandwidth accounting.
- DHT or gossip-based content discovery beyond connected-peer inventories.
- Pinning/GC policy and repository quotas.
- Streaming progress over RPC and cancelable fetches.
- Direct configuration for Reticulum LoRa/serial interfaces (currently via a Reticulum transport node).
- Resource (RNS Resource) interop for very large single objects.
