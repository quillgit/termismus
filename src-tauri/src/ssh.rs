use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use russh::client;
use russh::ChannelMsg;
use russh_keys::key::PublicKey;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};

use crate::models::{Host, PtyExit, PtyOut};

pub(crate) struct SshHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    key_error: Arc<std::sync::Mutex<Option<String>>>,
}

/// Algorithm family: all RSA signature variants count as one key type.
fn key_family(name: &str) -> &str {
    if name == "ssh-rsa" || name.starts_with("rsa-sha2-") {
        "rsa"
    } else {
        name
    }
}

fn host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_string()
    } else {
        format!("[{host}]:{port}")
    }
}

/// Does one comma-separated known_hosts host field match the pattern (plain or hashed)?
fn host_field_matches(pattern: &str, field: &str) -> bool {
    use hmac::{Hmac, Mac};
    for entry in field.split(',') {
        if let Some(rest) = entry.strip_prefix("|1|") {
            let mut parts = rest.split('|');
            let (Some(salt), Some(hash)) = (parts.next(), parts.next()) else {
                continue;
            };
            let (Ok(salt), Ok(hash)) = (STANDARD.decode(salt), STANDARD.decode(hash)) else {
                continue;
            };
            if let Ok(mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) {
                if mac.chain_update(pattern.as_bytes()).verify_slice(&hash).is_ok() {
                    return true;
                }
            }
        } else if entry == pattern {
            return true;
        }
    }
    false
}

/// Tolerant known_hosts reader: skips lines it cannot understand instead of failing.
fn tolerant_recorded_keys(host: &str, port: u16, path: &Path) -> Vec<(usize, PublicKey)> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let pattern = host_pattern(host, port);
    let mut out = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (hosts, _kt, b64) = match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(k), Some(b)) => (h, k, b),
            _ => continue,
        };
        if !host_field_matches(&pattern, hosts) {
            continue;
        }
        if let Ok(rec) = russh_keys::parse_public_key_base64(b64) {
            out.push((idx + 1, rec));
        }
    }
    out
}

/// Recorded keys for this host: russh-keys first, tolerant scan if the file has lines it cannot parse.
fn recorded_keys(host: &str, port: u16, path: &Path) -> Vec<(usize, PublicKey)> {
    match russh_keys::known_hosts::known_host_keys_path(host, port, path) {
        Ok(v) => v,
        Err(_) => tolerant_recorded_keys(host, port, path),
    }
}

enum HostKeyState {
    Match,
    Unknown,
    Changed(usize),
    OtherAlgo(usize, &'static str),
}

fn classify(recorded: &[(usize, PublicKey)], key: &PublicKey) -> HostKeyState {
    let fam = key_family(key.name());
    let mut changed: Option<usize> = None;
    for (line, rec) in recorded {
        if key_family(rec.name()) == fam {
            if rec == key {
                return HostKeyState::Match;
            }
            changed.get_or_insert(*line);
        }
    }
    if let Some(line) = changed {
        return HostKeyState::Changed(line);
    }
    match recorded.first() {
        Some((line, rec)) => HostKeyState::OtherAlgo(*line, rec.name()),
        None => HostKeyState::Unknown,
    }
}

impl SshHandler {
    fn changed_msg(&self, key: &PublicKey, line: usize) -> String {
        format!(
            "HOST KEY VERIFICATION FAILED for {}:{} - the server key has CHANGED (possible man-in-the-middle attack). Server offered {} SHA256:{}; {} line {} has a different key. If the change is legitimate, remove that line and reconnect.",
            self.host,
            self.port,
            key.name(),
            key.fingerprint(),
            self.known_hosts.display(),
            line
        )
    }

    fn other_algo_msg(&self, key: &PublicKey, line: usize, recorded: &str) -> String {
        format!(
            "HOST KEY VERIFICATION FAILED for {}:{} - server offered {} SHA256:{} but {} line {} records a {} key for this host (possible man-in-the-middle). Remove that line if the change is legitimate.",
            self.host,
            self.port,
            key.name(),
            key.fingerprint(),
            self.known_hosts.display(),
            line,
            recorded
        )
    }

    fn learn(&self, key: &PublicKey) {
        if let Err(e) =
            russh_keys::known_hosts::learn_known_hosts_path(&self.host, self.port, key, &self.known_hosts)
        {
            eprintln!("could not save host key to known_hosts: {e}");
        }
    }

    fn set_error(&self, msg: String) {
        if let Ok(mut g) = self.key_error.lock() {
            *g = Some(msg);
        }
    }
}

#[async_trait]
impl client::Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let recorded = recorded_keys(&self.host, self.port, &self.known_hosts);
        match classify(&recorded, key) {
            HostKeyState::Match => Ok(true),
            HostKeyState::Unknown => {
                self.learn(key);
                Ok(true)
            }
            HostKeyState::Changed(line) => {
                self.set_error(self.changed_msg(key, line));
                Ok(false)
            }
            HostKeyState::OtherAlgo(line, rec) => {
                self.set_error(self.other_algo_msg(key, line, rec));
                Ok(false)
            }
        }
    }
}

/// Host key algorithms ordered like OpenSSH: algorithms already recorded for this host first.
fn preferred_host_keys(host: &str, port: u16, path: &Path) -> Vec<russh_keys::key::Name> {
    use russh_keys::key;
    let mut list: Vec<key::Name> = Vec::new();
    for (_, rec) in recorded_keys(host, port, path) {
        let names: &[key::Name] = match key_family(rec.name()) {
            "rsa" => &[key::RSA_SHA2_256, key::RSA_SHA2_512],
            "ssh-ed25519" => &[key::ED25519],
            "ecdsa-sha2-nistp256" => &[key::ECDSA_SHA2_NISTP256],
            "ecdsa-sha2-nistp384" => &[key::ECDSA_SHA2_NISTP384],
            "ecdsa-sha2-nistp521" => &[key::ECDSA_SHA2_NISTP521],
            _ => &[],
        };
        for n in names {
            if !list.contains(n) {
                list.push(*n);
            }
        }
    }
    for n in russh::Preferred::DEFAULT.key.iter() {
        if !list.contains(n) {
            list.push(*n);
        }
    }
    list
}

pub struct SshSession {
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub resize_tx: mpsc::UnboundedSender<(u32, u32)>,
    pub alive: Arc<AtomicBool>,
}

pub type SshSessions = Arc<Mutex<HashMap<String, SshSession>>>;

pub fn new_sessions() -> SshSessions {
    Arc::new(Mutex::new(HashMap::new()))
}

fn home_dir_env() -> Option<String> {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
}

fn resolve_identity_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let expanded = if trimmed.starts_with("~/") || trimmed.starts_with("~\\") {
        match home_dir_env() {
            Some(home) => format!("{}{}", home, &trimmed[1..]),
            None => trimmed.to_string(),
        }
    } else {
        trimmed.to_string()
    };
    if Path::new(&expanded).exists() {
        Some(expanded)
    } else {
        None
    }
}

pub(crate) struct SshConn {
    pub handle: client::Handle<SshHandler>,
    pub _proxy: Option<tokio::process::Child>,
}

impl SshConn {
    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        drop(self._proxy);
    }
}

fn expand_proxy(cmd: &str, host: &str, port: u16, user: &str) -> String {
    let mut out = String::new();
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('h') => out.push_str(host),
            Some('p') => out.push_str(&port.to_string()),
            Some('r') => out.push_str(user),
            Some('%') => out.push('%'),
            Some(o) => {
                out.push('%');
                out.push(o);
            }
            None => out.push('%'),
        }
    }
    out
}

fn tail_2k(s: &mut String) {
    const MAX: usize = 2048;
    if s.len() > MAX {
        let mut cut = s.len() - MAX;
        while !s.is_char_boundary(cut) {
            cut += 1;
        }
        s.drain(..cut);
    }
}

pub(crate) async fn connect_and_auth(host: &Host) -> Result<SshConn, String> {
    // Overall bound for connect + key exchange + authentication.
    match tokio::time::timeout(Duration::from_secs(30), connect_and_auth_inner(host)).await {
        Ok(r) => r,
        Err(_) => Err("SSH connect/authentication timed out".into()),
    }
}

async fn connect_and_auth_inner(host: &Host) -> Result<SshConn, String> {
    let port: u16 = host.port.trim().parse().unwrap_or(22);
    let hostname = host.hostname.trim().to_string();
    if hostname.is_empty() {
        return Err("host has no address".into());
    }
    let user = {
        let u = host.user.trim();
        if !u.is_empty() {
            u.to_string()
        } else {
            std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "root".into())
        }
    };

    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        preferred: russh::Preferred {
            key: std::borrow::Cow::Owned(preferred_host_keys(
                &hostname,
                port,
                &crate::recovery::ssh_dir().join("known_hosts"),
            )),
            ..Default::default()
        },
        ..Default::default()
    });
    let key_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let handler = SshHandler {
        host: hostname.clone(),
        port,
        known_hosts: crate::recovery::ssh_dir().join("known_hosts"),
        key_error: key_error.clone(),
    };

    let proxy_cmd = host.proxy_command.trim().to_string();
    let proxy_err: Arc<std::sync::Mutex<String>> = Arc::new(std::sync::Mutex::new(String::new()));
    let mut proxy_child: Option<tokio::process::Child> = None;

    let connect_fut = async {
        if !proxy_cmd.is_empty() && !proxy_cmd.eq_ignore_ascii_case("none") {
            let cmdline = expand_proxy(&proxy_cmd, &hostname, port, &user);
            #[cfg(windows)]
            let mut c = {
                let mut c = tokio::process::Command::new("cmd");
                c.arg("/C").arg(&cmdline);
                c.creation_flags(0x0800_0000);
                c
            };
            #[cfg(not(windows))]
            let mut c = {
                let mut c = tokio::process::Command::new("sh");
                c.arg("-c").arg(&cmdline);
                c
            };
            c.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let mut child = c
                .spawn()
                .map_err(|e| format!("cannot start ProxyCommand: {e}"))?;
            let stdout = child.stdout.take().ok_or("proxy stdout unavailable")?;
            let stdin = child.stdin.take().ok_or("proxy stdin unavailable")?;
            if let Some(mut stderr) = child.stderr.take() {
                let buf = proxy_err.clone();
                tokio::spawn(async move {
                    let mut chunk = [0u8; 512];
                    loop {
                        match stderr.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if let Ok(mut g) = buf.lock() {
                                    g.push_str(&String::from_utf8_lossy(&chunk[..n]));
                                    tail_2k(&mut g);
                                }
                            }
                        }
                    }
                });
            }
            proxy_child = Some(child);
            let stream = tokio::io::join(stdout, stdin);
            client::connect_stream(config.clone(), stream, handler)
                .await
                .map_err(|e| format!("SSH connect failed: {e}"))
        } else {
            client::connect(config.clone(), (hostname.as_str(), port), handler)
                .await
                .map_err(|e| format!("SSH connect failed: {e}"))
        }
    };

    let result = tokio::time::timeout(Duration::from_secs(20), connect_fut).await;
    let mut handle = match result {
        Err(_) => return Err("SSH connect timed out".into()),
        Ok(Err(mut msg)) => {
            let k = key_error.lock().ok().and_then(|g| g.clone());
            if let Some(k) = k {
                return Err(k);
            }
            if let Ok(g) = proxy_err.lock() {
                let s = g.trim();
                if !s.is_empty() {
                    msg.push_str(&format!(" (proxy stderr: {s})"));
                }
            }
            return Err(msg);
        }
        Ok(Ok(h)) => h,
    };

    let mut authed = false;

    // (a) explicit identity file
    if let Some(key_path) = resolve_identity_path(&host.identity_file) {
        let pass = if host.password.is_empty() {
            None
        } else {
            Some(host.password.as_str())
        };
        let mut key = russh_keys::load_secret_key(&key_path, pass);
        if key.is_err() && pass.is_some() {
            key = russh_keys::load_secret_key(&key_path, None);
        }
        if let Ok(key) = key {
            authed = handle
                .authenticate_publickey(&user, Arc::new(key))
                .await
                .map_err(|e| format!("auth failed: {e}"))?;
        }
    }

    // (b) default keys
    if !authed {
        let dir = crate::recovery::ssh_dir();
        for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
            let p = dir.join(name);
            if !p.exists() {
                continue;
            }
            if let Ok(key) = russh_keys::load_secret_key(&p, None) {
                if handle
                    .authenticate_publickey(&user, Arc::new(key))
                    .await
                    .map_err(|e| format!("auth failed: {e}"))?
                {
                    authed = true;
                    break;
                }
            }
        }
    }

    // (c) password
    if !authed && !host.password.is_empty() {
        authed = handle
            .authenticate_password(&user, &host.password)
            .await
            .map_err(|e| format!("auth failed: {e}"))?;
    }

    if !authed {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        return Err("authentication failed - no valid key or password".into());
    }

    Ok(SshConn {
        handle,
        _proxy: proxy_child,
    })
}

#[tauri::command]
pub async fn ssh_open(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    host: Host,
    rows: u32,
    cols: u32,
) -> Result<(), String> {
    let conn = connect_and_auth(&host).await?;

    let setup = async {
        let channel = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("channel open failed: {e}"))?;
        channel
            .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
            .await
            .map_err(|e| format!("PTY request failed: {e}"))?;
        channel
            .request_shell(false)
            .await
            .map_err(|e| format!("shell request failed: {e}"))?;
        Ok::<_, String>(channel)
    };
    let mut channel = match setup.await {
        Ok(c) => c,
        Err(e) => {
            conn.close().await;
            return Err(e);
        }
    };

    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (resize_tx, mut resize_rx) = mpsc::unbounded_channel::<(u32, u32)>();
    let alive = Arc::new(AtomicBool::new(true));
    let alive_task = alive.clone();

    {
        let mut sessions = state.ssh_sessions.lock().await;
        sessions.insert(
            session_id.clone(),
            SshSession {
                input_tx,
                resize_tx,
                alive: alive.clone(),
            },
        );
    }

    let sessions_ref = state.ssh_sessions.clone();
    let id = session_id.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = channel.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => {
                        let _ = app.emit("pty-output", PtyOut { id: id.clone(), data: STANDARD.encode(data.as_ref()) });
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = app.emit("pty-output", PtyOut { id: id.clone(), data: STANDARD.encode(data.as_ref()) });
                    }
                    Some(ChannelMsg::ExitStatus { .. }) | Some(ChannelMsg::Eof) => continue,
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                },
                d = input_rx.recv() => match d {
                    Some(bytes) => {
                        if channel.data(&bytes[..]).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        break;
                    }
                },
                r = resize_rx.recv() => match r {
                    Some((c, rw)) => {
                        let _ = channel.window_change(c, rw, 0, 0).await;
                    }
                    None => break,
                },
            }
        }
        alive_task.store(false, Ordering::Relaxed);
        conn.close().await;
        let _ = app.emit("pty-exit", PtyExit { id: id.clone() });
        let mut sessions = sessions_ref.lock().await;
        if let Some(s) = sessions.get(&id) {
            if Arc::ptr_eq(&s.alive, &alive_task) {
                sessions.remove(&id);
            }
        }
    });

    Ok(())
}

#[tauri::command]
pub async fn ssh_input(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let sessions = state.ssh_sessions.lock().await;
    if let Some(s) = sessions.get(&session_id) {
        s.input_tx
            .send(data.into_bytes())
            .map_err(|_| "session closed".to_string())?;
        Ok(())
    } else {
        Err("session not found".into())
    }
}

#[tauri::command]
pub async fn ssh_resize(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
    rows: u32,
    cols: u32,
) -> Result<(), String> {
    let sessions = state.ssh_sessions.lock().await;
    if let Some(s) = sessions.get(&session_id) {
        let _ = s.resize_tx.send((cols, rows));
    }
    Ok(())
}

#[tauri::command]
pub async fn ssh_close(
    state: tauri::State<'_, crate::AppState>,
    session_id: String,
) -> Result<(), String> {
    let mut sessions = state.ssh_sessions.lock().await;
    sessions.remove(&session_id);
    Ok(())
}
