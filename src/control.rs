//! Local RPC service.
//!
//! The daemon listens on a Unix socket (mode 0600) and speaks newline
//! delimited JSON:
//!
//! ```text
//! -> {"id":1,"method":"add","params":{"path":"/tmp/file"}}
//! <- {"id":1,"result":{"object":{...},"path":"/tmp/file"}}
//! ```
//!
//! Requests on one connection are handled in order.  Long operations such as
//! `get` simply hold that connection until they finish.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::Paths;
use crate::hash::ContentHash;
use crate::node::Node;

#[derive(Deserialize)]
struct RpcRequest {
    id: u64,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Serialize)]
struct RpcResponse {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Bind the RPC socket, removing a stale socket but never stealing one from a
/// live daemon.  Returns the listener so the caller can treat bind/serve
/// failures as fatal.
pub async fn bind(socket: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create RPC socket directory {}", parent.display()))?;
    }
    if socket.exists() {
        // Remove a stale socket, but never steal one from a live daemon.
        if UnixStream::connect(socket).await.is_ok() {
            bail!(
                "another meshvault daemon is already listening on {}",
                socket.display()
            );
        }
        let _ = std::fs::remove_file(socket);
    }
    let listener = UnixListener::bind(socket)
        .with_context(|| format!("bind RPC socket {}", socket.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("secure RPC socket {}", socket.display()))?;
    }
    log::info!("RPC listening on {}", socket.display());
    Ok(listener)
}

/// Accept RPC connections until the listener fails.
pub async fn serve(node: Arc<Node>, listener: UnixListener) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await.context("accept RPC connection")?;
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(node, stream).await {
                log::debug!("RPC connection ended: {err:#}");
            }
        });
    }
}

async fn handle_connection(node: Arc<Node>, stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let request: RpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(err) => {
                let response = RpcResponse {
                    id: 0,
                    result: None,
                    error: Some(format!("invalid request: {err}")),
                };
                write_half
                    .write_all(serde_json::to_string(&response)?.as_bytes())
                    .await?;
                write_half.write_all(b"\n").await?;
                continue;
            }
        };
        let id = request.id;
        let response = match dispatch(&node, &request.method, request.params).await {
            Ok(result) => RpcResponse {
                id,
                result: Some(result),
                error: None,
            },
            Err(err) => RpcResponse {
                id,
                result: None,
                error: Some(format!("{err:#}")),
            },
        };
        let mut encoded = serde_json::to_vec(&response)?;
        encoded.push(b'\n');
        write_half.write_all(&encoded).await?;
        write_half.flush().await?;
    }
    Ok(())
}

async fn dispatch(node: &Arc<Node>, method: &str, params: Value) -> Result<Value> {
    match method {
        "ping" => Ok(json!("pong")),
        "status" => Ok(serde_json::to_value(node.status().await)?),
        "id" => Ok(json!({
            "destination": node.destination_hash().to_hex_string(),
            "identity": node.identity_hash().to_hex_string(),
            "name": node.config.name,
        })),
        "add" => {
            let path = param_string(&params, "path")?;
            let name = param_optional_string(&params, "name")?;
            let result = node.add_path(PathBuf::from(path), name).await?;
            Ok(serde_json::to_value(result)?)
        }
        "get" | "fetch" => {
            let hash = param_string(&params, "hash")?;
            let root = ContentHash::from_hex(&hash)?;
            let output = param_optional_string(&params, "output")?.map(PathBuf::from);
            let result = node.get(root, output).await?;
            Ok(serde_json::to_value(result)?)
        }
        "ls" | "list" => {
            let hash = param_optional_string(&params, "hash")?;
            match hash {
                Some(hash) => {
                    let root = ContentHash::from_hex(&hash)?;
                    let listing = node.list_directory(root).await?;
                    Ok(serde_json::to_value(listing)?)
                }
                None => Ok(serde_json::to_value(node.list_local())?),
            }
        }
        "remove" => {
            let hash = param_string(&params, "hash")?;
            let root = ContentHash::from_hex(&hash)?;
            let removed = node.remove(root).await?;
            Ok(json!(removed))
        }
        "peers" => Ok(serde_json::to_value(node.peers().await)?),
        "announce" => {
            node.request_announce();
            Ok(json!(true))
        }
        other => bail!("unknown method {other:?}"),
    }
}

fn param_string(params: &Value, name: &str) -> Result<String> {
    params
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("missing string parameter {name:?}"))
}

fn param_optional_string(params: &Value, name: &str) -> Result<Option<String>> {
    match params.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => bail!("parameter {name:?} must be a string"),
    }
}

// ─── Client ────────────────────────────────────────────────────────────────

pub struct RpcClient {
    stream: UnixStream,
    next_id: u64,
}

impl RpcClient {
    pub async fn connect(socket: &Path) -> Result<Self> {
        let stream = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(socket))
            .await
            .context("RPC connect timed out")?
            .with_context(|| format!("connect to {}", socket.display()))?;
        Ok(Self { stream, next_id: 1 })
    }

    pub async fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({"id": id, "method": method, "params": params});
        let mut encoded = serde_json::to_vec(&request)?;
        encoded.push(b'\n');
        self.stream.write_all(&encoded).await?;
        self.stream.flush().await?;

        let mut reader = BufReader::new(&mut self.stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.is_empty() {
            bail!("daemon closed the RPC connection");
        }
        let response: Value = serde_json::from_str(&line)?;
        let response_id = response.get("id").and_then(Value::as_u64).unwrap_or(0);
        if response_id != id {
            bail!("RPC response id mismatch");
        }
        if let Some(error) = response.get("error").and_then(Value::as_str) {
            bail!("{error}");
        }
        Ok(response.get("result").cloned().unwrap_or(Value::Null))
    }
}

pub async fn ping(socket: &Path) -> bool {
    match RpcClient::connect(socket).await {
        Ok(mut client) => client.call("ping", json!({})).await.is_ok(),
        Err(_) => false,
    }
}

/// Start the daemon if it is not already running, then return a client.
pub async fn client_for(paths: &Paths) -> Result<RpcClient> {
    let socket = &paths.control_socket;
    if ping(socket).await {
        return RpcClient::connect(socket).await;
    }

    std::fs::create_dir_all(&paths.data_dir)
        .with_context(|| format!("create {}", paths.data_dir.display()))?;
    let log_path = paths.data_dir.join("daemon.log");
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("open {}", log_path.display()))?;
    let log_clone = log.try_clone()?;
    let exe = std::env::current_exe().context("locate meshvault executable")?;
    let mut command = std::process::Command::new(exe);
    command
        .arg("daemon")
        .arg("--config")
        .arg(&paths.config_file)
        .arg("--data-dir")
        .arg(&paths.data_dir)
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(log_clone);
    let mut child = command.spawn().context("start meshvault daemon")?;

    // Wait for the socket to accept a ping.  The spawned daemon may lose the
    // data-directory lock to another daemon that is already starting; in that
    // case keep polling briefly so the winner's socket can come up.
    let mut child_status = None;
    let mut loops_after_exit = 0;
    for _ in 0..80 {
        if ping(socket).await {
            log::debug!("started daemon (pid {})", child.id());
            return RpcClient::connect(socket).await;
        }
        if child_status.is_none()
            && let Ok(Some(status)) = child.try_wait()
        {
            child_status = Some(status);
        }
        if child_status.is_some() {
            loops_after_exit += 1;
            // Keep waiting for the winner of a concurrent auto-start race.
            if loops_after_exit >= 80 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    if let Some(status) = child_status {
        bail!(
            "daemon exited during startup ({status}); another daemon may be starting, or see {}",
            log_path.display()
        );
    }
    bail!(
        "daemon did not start within 20s; see {}",
        log_path.display()
    )
}
