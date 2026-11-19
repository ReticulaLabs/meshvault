# MeshVault

MeshVault is a content-addressed file sharing service for [Reticulum](https://reticulum.network/) mesh networks. It is deliberately IPFS-like in use: hash a file or directory, share the hash, and anyone connected to the mesh can retrieve it.

Files and directory trees are identified by BLAKE3 hashes. File data is transferred in verified pieces with adaptive chunk sizes, so a 20 MiB file can move quickly across a LAN while a LoRa link automatically stays at a single small piece.

## Features

- **Runs as a local service.** One daemon connects to one or more Reticulum nodes and exposes a local JSON-RPC socket.
- **Automatic peering.** The daemon announces a `meshvault.node` destination, discovers other MeshVault peers, verifies their identity, and keeps a bounded set of links.
- **BLAKE3 content addressing.** File hashes cover the complete file; per-piece hashes allow incremental verification and resumption.
- **Content-addressed directories.** A directory hash covers a canonical, sorted listing of names → child file/directory hashes. Listings can be fetched without downloading the contents.
- **Recursive retrieval.** `get <directory-hash>` fetches the directory manifest and the whole tree.
- **Pinning.** `pin <hash>` fetches a file or whole tree into the local repository and keeps hosting it without exporting a copy.
- **Bandwidth-aware transfer.** App-level selective-repeat with compact bitmap ACKs, adaptive send windows, and chunks that grow from one piece to a configured maximum based on measured throughput.
- **Multi-source fetching.** A file is split into disjoint piece ranges and fetched from up to `fetch_parallelism` peers concurrently, with unified verification and resume.
- **Source visibility.** `sources <hash>` reports the known local and remote copies of an object, including peer address, hop count, and signal quality.
- **Minimal inventory traffic.** Peers exchange a 32-byte inventory digest; full inventories are only fetched when the digest changes.
- **Crash-safe storage.** Raw blobs plus atomically written manifests. No database corruption surface; the index is rebuilt at startup.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the protocol and design rationale.

## Build

```sh
cargo build --release
```

Requirements: Rust 1.85+ (edition 2024), Linux for the Unix-socket RPC service.

## Docker

The repository includes an Alpine-based multi-stage `Dockerfile`. The image runs as an unprivileged `meshvault` user, stores repository data in `/var/lib/meshvault`, and reads configuration from `/etc/meshvault/config.toml`.

```sh
docker build -t meshvault .

# Create a config on the host, then run the service.
docker run -d --name meshvault \
  --restart unless-stopped \
  -p 4243:4243 \
  -v meshvault-data:/var/lib/meshvault \
  -v "$PWD/config.toml:/etc/meshvault/config.toml:ro" \
  meshvault
```

A container-oriented config usually listens on all interfaces and connects to a Reticulum router on the host:

```toml
name = "docker-node"
fetch_parallelism = 4

[interfaces]
listen = ["0.0.0.0:4243"]
connect = ["host.docker.internal:4242"]
```

On Linux, add `--add-host=host.docker.internal:host-gateway` to reach a router on the host. If you do not mount a config, the container writes a default one and runs isolated until you provide interfaces. If you bind-mount a data directory instead of using a named volume, make it writable by the container's unprivileged `meshvault` user.

The CLI can be used inside the running container:

```sh
docker exec meshvault meshvault status
docker exec meshvault meshvault add /var/lib/meshvault/import/somefile
docker exec meshvault meshvault get <hash> -o /var/lib/meshvault/import/out
```

The RPC socket lives at `/var/lib/meshvault/control.sock`. The bundled build uses Reticulum's network-only features (TCP client/server); connect it to a Reticulum transport node that carries LoRa, serial, or other interfaces.

The CLI talks to the running daemon. After upgrading MeshVault, restart the daemon (and replace any installed binary such as `/usr/local/bin/meshvault`) before expecting new behavior from commands.

## Quick start

1. Create a configuration:

```sh
meshvault init
```

2. Edit `~/.config/meshvault/config.toml` to point at a Reticulum transport node:

```toml
name = "my-node"

[interfaces]
connect = ["127.0.0.1:4242"]
# Optional: accept inbound Reticulum connections from nearby nodes.
# listen = ["0.0.0.0:4243"]
```

3. Start the daemon (or let any CLI command start it automatically):

```sh
meshvault daemon
```

4. Add and share something:

```sh
$ meshvault add ./photos
directory 8a7c50c319772dad60d8ddbe8ccd1463a9519b9b4b2115d2b87cbf2bcc6044f1  2.4 GiB  photos  (1841 entries)

$ meshvault add ./report.pdf
file      3138c77b63d7acd08f065f6915603909602008bfc8cc03fe275f9a8eaaa21a3f  20.0 MiB  report.pdf
```

5. On another peer on the mesh:

```sh
$ meshvault ls 8a7c50c319772dad60d8ddbe8ccd1463a9519b9b4b2115d2b87cbf2bcc6044f1
directory 8a7c50c3... (1841, photos)
  file      6d1d...  4.2 MiB  summit.jpg
  directory 88a2...  2.1 GiB  raw
  ...

$ meshvault get 8a7c50c319772dad60d8ddbe8ccd1463a9519b9b4b2115d2b87cbf2bcc6044f1 -o ./received
resolving: resolving object
downloading: photos (120/1841)
directory: raw (1/1841)
saved ./received (2.4 GiB)

$ meshvault pin 8a7c50c319772dad60d8ddbe8ccd1463a9519b9b4b2115d2b87cbf2bcc6044f1
resolving: resolving object
directory: raw (1/1841)
pinned directory  8a7c50c3...  2.4 GiB  photos  (1841 entries)
```

`get` writes live progress to stderr while it resolves, downloads pieces, and extracts a directory tree. The final `saved ...` line still goes to stdout.

`pin` uses the same fetch path but stores the object tree only in the repository, with no output copy. Pinned data is retained even when `cache_fetched = false` and is announced to peers like locally added content. `remove` is the way to unpin it.

The daemon was automatically started by the CLI if it was not already running. It caches fetched content and advertises it to other peers by default.

## CLI

```text
meshvault daemon [--connect HOST:PORT]... [--listen HOST:PORT]...
                 [--announce-interval SECS] [--max-peers N]
                 [--name NAME] [--transport-node]

meshvault init                 Create default config and print paths
meshvault status               Daemon and repository status (JSON)
meshvault id                   Destination and identity hashes
meshvault add <path> [--name]  Import a file or directory tree
meshvault get <hash> [-o PATH] Fetch a file or directory tree
meshvault pin <hash>           Fetch a file or tree into the repository and keep hosting it
meshvault ls [hash] [--all]    List top-level objects, a directory, or all objects
meshvault sources <hash>       Show known local and remote copies of an object
meshvault remove <hash> [--recursive]  Remove an object or an unreferenced tree
meshvault peers                Known/connected peers
meshvault announce             Announce immediately
```

`sources <hash>` counts the local store plus each linked peer advertising that exact root. For a directory hash, that means copies of the directory manifest, not necessarily every child object.

`get` output rules:

- File: `-o` is a file path, or an existing directory (the original name is used).
- Directory: `-o` that already exists is treated as a parent directory (the tree is copied inside it); otherwise it is the target directory itself.

Hashes accept the 64-character BLAKE3 hex form.

## Running as a service

`meshvault daemon` handles `SIGTERM` and `Ctrl-C`. A minimal systemd unit:

```ini
[Unit]
Description=MeshVault Reticulum file sharing service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=meshvault
ExecStart=/usr/local/bin/meshvault daemon
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Use `meshvault init` once as that user (or set `data_dir`/`control_socket` explicitly in `/etc/meshvault/config.toml`). The daemon takes an exclusive `daemon.lock` in the data directory before touching the identity or repository, so a second daemon for the same repository exits immediately. RPC bind failures are fatal.

## Local RPC

The daemon listens on `<data_dir>/control.sock` with mode `0600`. The protocol is newline-delimited JSON. Requests are handled in order per connection.

```json
{"id":1,"method":"add","params":{"path":"/srv/data/report.pdf"}}
{"id":1,"result":{"object":{"kind":"file","root":"3138...","size":20971520,...},"path":"/srv/data/report.pdf"}}
```

Methods:

| Method | Params | Result |
|---|---|---|
| `ping` | `{}` | `"pong"` |
| `status` | `{}` | node/repository status object |
| `id` | `{}` | `{destination, identity, name}` |
| `add` | `{path, name?}` | `{object, path}` |
| `get` / `fetch` | `{hash, output?}` | `{object, path, bytes, resumed, sources}` |
| `pin` | `{hash}` | `{object, bytes}` |
| `ls` / `list` | `{}`, `{all}`, or `{hash}` | top-level object array, flat object array, or `{root, name, entries}` |
| `sources` | `{hash}` | `{root, copies, remote_copies, local, sources, unknown_peers}` |
| `remove` | `{hash, recursive?}` | boolean |
| `peers` | `{}` | peer array |
| `announce` | `{}` | boolean |

Long-running `get` and `pin` requests emit `{"id":N,"progress":{stage,message,current,total}}` lines before the final response. Clients may ignore them; the response is always the last line for that id.

Any local process with access to the socket can modify the repository, so the socket permissions matter. There is no network RPC listener.

## Configuration

```toml
name = "my-node"                 # optional friendly name announced to peers
# data_dir = "/var/lib/meshvault"
# control_socket = "/run/user/1000/meshvault.sock"

announce_interval_secs = 900     # minimum 60
max_peers = 8                    # outbound links
max_links = 64                   # total links
max_known_peers = 512            # retained peer records
piece_size = 16384               # hashing/verification piece size
max_chunk_bytes = 1048576        # cap for one adaptive transfer message
fetch_wait_secs = 20             # how long get waits for a peer/inventory
fetch_stall_timeout_secs = 3600  # abort after this long without progress
fetch_parallelism = 4            # parallel source peers per file (1 disables)
max_inventory_objects = 16384    # inventory entries accepted per peer
max_inventory_objects_total = 65536  # inventory entries across all peers
max_inbound_memory_bytes = 67108864  # 64 MiB global reassembly budget
max_extract_entries = 100000     # recursive get/pin entry budget
max_extract_bytes = 10737418240  # recursive get byte budget (10 GiB)
peer_service_bytes_per_sec = 4194304  # per-peer serving rate (4 MiB/s)
peer_service_burst_bytes = 8388608    # per-peer burst allowance (8 MiB)
cache_fetched = true             # keep and advertise content fetched by get
transport_node = false           # forward traffic for other Reticulum nodes
link_mtu_discovery = false       # keep interoperable 500-byte Reticulum MTU

[interfaces]
connect = ["127.0.0.1:4242"]
listen = []
# assumed_bitrate_bps = 1000000
```

Relative paths in the configuration are resolved against the configuration file's directory. Default paths follow the XDG directories (`~/.config/meshvault`, `~/.local/share/meshvault`).

### Interface notes

This build configures Reticulum **TCP client/server** interfaces. Point `connect` at a Reticulum transport/router that carries LoRa, packet radio, serial, or other interfaces; MeshVault then participates in that wider mesh without needing direct radio hardware.

`link_mtu_discovery` is off by default. Reticulum's interoperable packet MTU is 500 bytes; some SDK/interface combinations do not reliably carry larger link packets. Leave it off unless every peer is known to support a larger link MTU. Independently, MeshVault rejects inbound links whose signalled MTU exceeds 4 KiB, since the initiator controls that value.

## Storage

```text
<data_dir>/
  identity.hex                 Reticulum private identity (0600)
  daemon.lock                  exclusive single-instance lock (0600)
  blobs/<blake3>               raw file bytes
  manifests/<blake3>.json      piece hashes + file metadata
  dirs/<blake3>.json           directory listings
  dirs/<blake3>.name           optional local display name
  partial/<blake3>.part        resumable downloads
  tmp/                         atomic-write staging
  control.sock                 local RPC socket (0600)
  daemon.log                   daemon log when auto-started
```

All writes are staged in `tmp/`, `fsync`ed, and atomically renamed. A crash leaves either the old object or the new object, never a partial blob advertised as complete. Fetched files are verified piece-by-piece and then re-hashed in full against the root before being promoted.

`ls` with no hash lists **top-level repository roots** — objects not referenced by any directory manifest — so an imported directory appears once rather than as all of its children. Use `ls <directory-hash>` to list a directory's entries or `ls --all` to see the flat inventory.

`remove <hash>` removes one object only; removing a directory that way removes only its listing. `remove <hash> --recursive` removes the directory tree and its unreferenced children, while preserving any child still referenced by another directory manifest. There is currently no general garbage collector: content stays until it is explicitly removed, whether it was added locally, pinned, or cached by `get`.

## Security model

- All Reticulum links are encrypted. MeshVault additionally verifies that a peer's `Hello` identity derives the destination hash it announced, and that the link initiator identified itself on inbound links.
- Every file piece is BLAKE3-verified as it arrives; the completed file is verified against its root hash before being stored.
- Manifest bytes are checked against the hash advertised in the peer's inventory. Directory manifests are checked against their directory hash.
- Directory entry names are validated and path components are sanitized before filesystem use. Directory recursion has a depth limit and cycle detection.
- Message sizes, frame counts, inventory pages, piece requests, and reassembly state are all bounded.

MeshVault is a **public sharing service**. There is no read access control: any connected peer can list your inventory and fetch any object you advertise. Names and hashes are visible to peers. The local RPC socket is the only privileged interface; keep its permissions restrictive.

## Testing

```sh
cargo test --all-targets
```

The end-to-end development check runs daemons over Reticulum TCP, adds files/directories on one node, lists and retrieves them from another, and verifies byte-identical output. A 16 MiB file fetched from two peers concurrently completed in ~0.43 s over loopback TCP in a release build with the default 500-byte Reticulum MTU; each source contributed roughly half the pieces. A 20 MiB single-source debug transfer with resume completed in ~13.5 s.

## Limitations and future work

- Discovery is **peer-inventory based**, not a DHT. A file is visible if a connected peer advertises it. Reticulum handles multi-hop routing, but content discovery is bounded by the peer graph.
- Multi-source fetching is bounded by `fetch_parallelism`. Peers are selected by hop count then SNR, and a failing peer enters a short cooldown; there is no long-term reputation or bandwidth accounting.
- Parallel sources must advertise the same manifest hash, which means the same piece size/layout. A peer that imported the file with a different `piece_size` is excluded from that fetch.
- Peers with more than `max_inventory_objects` entries are not fully synchronized; raise that limit (and `max_inventory_objects_total`) for repositories with many files. Disconnected peers are evicted after one hour, and the retained peer table is capped by `max_known_peers`.
- Inbound reassembly is bounded per link (4 MiB) and globally by `max_inbound_memory_bytes`; frames that would exceed the global budget are dropped and retried by the sender.
- A fetch aborts after `fetch_stall_timeout_secs` without verified progress, and an RPC disconnect cancels its active operation.
- Recursive directory extraction is bounded by `max_extract_entries` and `max_extract_bytes`, refuses symlink destinations, and does not follow pre-existing symlinks in extracted paths.
- Each peer has a service token bucket (`peer_service_bytes_per_sec` / `peer_service_burst_bytes`) covering inventory pages, manifests, directories, and chunks. Requests are charged an estimated response cost with a 64 KiB minimum; an exhausted peer receives a `429` control error. Inventory pages are served from a cached snapshot rather than rebuilding the full inventory per page.
- No garbage collection. `pin` keeps fetched content until `remove`; `get` retains it in the repository only when `cache_fetched = true`.
- No partial-directory progress sidecar; individual files resume, but already-completed files in a directory are re-exported/fail if the target exists.
- Pieces are fetched in adaptive contiguous ranges, not individual pieces, which keeps protocol overhead low but can leave an under-filled tail when one source is much slower.
- The RPC is Unix-only. A disconnected CLI cancels its in-flight daemon operation.
- Directory names are not part of the directory hash (like IPFS links); the local display name is a sidecar.
- No encryption at rest.

## License

MIT.
