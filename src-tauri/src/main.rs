// TERMISMUS - local encrypted SSH host manager with embedded PTY terminals
// Vault: %APPDATA%\MKTRVault\vault.bin = magic | salt(16) | nonce(12) | AES-256-GCM(json)
// Key = Argon2id(master). Terminals run ssh inside a ConPTY; password auth is auto-typed.
#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::Emitter;

const MAGIC: &[u8; 6] = b"MKTRV1";
const MAGIC_BACKUP: &[u8; 6] = b"TMBB01";

#[derive(Serialize, Deserialize, Clone, Default)]
struct Host {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    user: String,
    #[serde(default)]
    port: String,
    #[serde(default)]
    identity_file: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    proxy_command: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    notes: String,
}

// ---------------- PTY session state ----------------

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;
type Master = Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>;
type ChildH = Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>;

struct Session {
    writer: Writer,
    master: Master,
    child: ChildH,
}

#[derive(Default)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

#[derive(Clone, Serialize)]
struct PtyOut {
    id: String,
    data: String,
}
#[derive(Clone, Serialize)]
struct PtyExit {
    id: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct FileEntry {
    name: String,
    is_dir: bool,
    size: String,
}

#[derive(Serialize, Deserialize)]
struct BackupPayload {
    hosts: Vec<Host>,
    ssh_files: HashMap<String, String>,
}

// ---------------- Vault crypto ----------------

fn vault_dir() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".into());
    let p = PathBuf::from(base).join("MKTRVault");
    let _ = fs::create_dir_all(&p);
    p
}
fn vault_path() -> PathBuf {
    vault_dir().join("vault.bin")
}

fn derive_key(master: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(master.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

fn encrypt_and_save(master: &str, hosts: &[Host]) -> Result<(), String> {
    let plaintext = serde_json::to_vec(hosts).map_err(|e| e.to_string())?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(master, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(6 + 16 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    let tmp = vault_path().with_extension("tmp");
    fs::write(&tmp, &out).map_err(|e| e.to_string())?;
    fs::rename(&tmp, vault_path()).map_err(|e| e.to_string())?;
    Ok(())
}

fn decrypt(master: &str) -> Result<Vec<Host>, String> {
    let data = fs::read(vault_path()).map_err(|e| format!("cannot read vault: {e}"))?;
    if data.len() < 6 + 16 + 12 || &data[0..6] != MAGIC {
        return Err("vault file is corrupt or not an MKTR vault".into());
    }
    let salt = &data[6..22];
    let nonce = &data[22..34];
    let ct = &data[34..];
    let key = derive_key(master, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "wrong master password or corrupted vault".to_string())?;
    serde_json::from_slice(&pt).map_err(|e| e.to_string())
}

// ---------------- Vault commands ----------------

#[tauri::command]
fn vault_exists() -> bool {
    vault_path().exists()
}
#[tauri::command]
fn vault_location() -> String {
    vault_path().to_string_lossy().to_string()
}
#[tauri::command]
fn create_vault(master: String, seed: bool) -> Result<Vec<Host>, String> {
    if master.len() < 4 {
        return Err("master password must be at least 4 characters".into());
    }
    let hosts = if seed { scan_recovered() } else { Vec::new() };
    encrypt_and_save(&master, &hosts)?;
    Ok(hosts)
}
#[tauri::command]
fn unlock_vault(master: String) -> Result<Vec<Host>, String> {
    decrypt(&master)
}
#[tauri::command]
fn save_vault(master: String, hosts: Vec<Host>) -> Result<(), String> {
    decrypt(&master)?; // verify before overwrite
    encrypt_and_save(&master, &hosts)
}
#[tauri::command]
fn recovered_hosts() -> Vec<Host> {
    scan_recovered()
}

// ---------------- PTY commands ----------------

fn ssh_program() -> String {
    let p = r"C:\Windows\System32\OpenSSH\ssh.exe";
    if Path::new(p).exists() {
        p.to_string()
    } else {
        "ssh.exe".to_string()
    }
}

#[tauri::command]
fn pty_open(
    app: tauri::AppHandle,
    state: tauri::State<AppState>,
    session_id: String,
    host: Host,
    rows: u16,
    cols: u16,
) -> Result<(), String> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: rows.max(10),
            cols: cols.max(20),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let mut cmd = CommandBuilder::new(ssh_program());
    // inherit environment so ssh finds PATH, USERPROFILE/.ssh, etc.
    for (k, v) in std::env::vars() {
        cmd.env(k, v);
    }
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("USERPROFILE") {
        cmd.cwd(home);
    }
    cmd.arg("-tt");
    cmd.arg("-o");
    cmd.arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o");
    cmd.arg("ServerAliveInterval=30");
    if !host.port.trim().is_empty() {
        cmd.arg("-p");
        cmd.arg(host.port.trim());
    }
    if !host.identity_file.trim().is_empty() {
        cmd.arg("-i");
        cmd.arg(host.identity_file.trim());
    }
    if !host.proxy_command.trim().is_empty() {
        cmd.arg("-o");
        cmd.arg(format!("ProxyCommand={}", host.proxy_command.trim()));
    }
    let target = if host.user.trim().is_empty() {
        host.hostname.trim().to_string()
    } else {
        format!("{}@{}", host.user.trim(), host.hostname.trim())
    };
    if target.is_empty() {
        return Err("host has no address".into());
    }
    cmd.arg(target);

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer: Writer = Arc::new(Mutex::new(
        pair.master.take_writer().map_err(|e| e.to_string())?,
    ));
    let master: Master = Arc::new(Mutex::new(pair.master));
    let child: ChildH = Arc::new(Mutex::new(child));

    {
        let mut map = state.sessions.lock().unwrap();
        map.insert(
            session_id.clone(),
            Session {
                writer: writer.clone(),
                master,
                child,
            },
        );
    }

    // reader thread: stream output + auto-type password on prompt
    let sessions = state.sessions.clone();
    let password = host.password.clone();
    let id = session_id.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut sent_pw = false;
        let mut recent = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let b64 = STANDARD.encode(&buf[..n]);
                    let _ = app.emit(
                        "pty-output",
                        PtyOut {
                            id: id.clone(),
                            data: b64,
                        },
                    );
                    if !sent_pw && !password.is_empty() {
                        recent.push_str(&String::from_utf8_lossy(&buf[..n]));
                        let low = recent.to_lowercase();
                        if low.contains("password:") || low.contains("password for") {
                            if let Ok(mut w) = writer.lock() {
                                let _ = w.write_all(password.as_bytes());
                                let _ = w.write_all(b"\r");
                                let _ = w.flush();
                            }
                            sent_pw = true;
                            recent.clear();
                        }
                        if recent.len() > 400 {
                            recent.drain(0..recent.len() - 200);
                        }
                    }
                }
            }
        }
        let _ = app.emit("pty-exit", PtyExit { id: id.clone() });
        if let Ok(mut map) = sessions.lock() {
            map.remove(&id);
        }
    });

    Ok(())
}

#[tauri::command]
fn pty_input(state: tauri::State<AppState>, session_id: String, data: String) -> Result<(), String> {
    let map = state.sessions.lock().unwrap();
    if let Some(s) = map.get(&session_id) {
        let mut w = s.writer.lock().map_err(|_| "writer lock".to_string())?;
        w.write_all(data.as_bytes()).map_err(|e| e.to_string())?;
        w.flush().map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err("session not found".into())
    }
}

#[tauri::command]
fn pty_resize(
    state: tauri::State<AppState>,
    session_id: String,
    rows: u16,
    cols: u16,
) -> Result<(), String> {
    let map = state.sessions.lock().unwrap();
    if let Some(s) = map.get(&session_id) {
        let m = s.master.lock().map_err(|_| "master lock".to_string())?;
        m.resize(PtySize {
            rows: rows.max(2),
            cols: cols.max(2),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn pty_close(state: tauri::State<AppState>, session_id: String) -> Result<(), String> {
    let mut map = state.sessions.lock().unwrap();
    if let Some(s) = map.remove(&session_id) {
        if let Ok(mut c) = s.child.lock() {
            let _ = c.kill();
        }
    }
    Ok(())
}

// ---------------- SFTP / file transfer ----------------

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    if bytes < 1024 * 1024 * 1024 {
        return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0));
    }
    format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc.is_ascii_alphabetic() || nc == '~' {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ssh_target(host: &Host) -> String {
    let h = host.hostname.trim();
    if host.user.trim().is_empty() {
        h.to_string()
    } else {
        format!("{}@{}", host.user.trim(), h)
    }
}

fn run_ssh_command(host: &Host, remote_cmd: &str, timeout_secs: u64) -> Result<String, String> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 200,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let mut cmd = CommandBuilder::new(ssh_program());
    for (k, v) in std::env::vars() {
        cmd.env(k, v);
    }
    cmd.env("TERM", "dumb");
    if let Ok(home) = std::env::var("USERPROFILE") {
        cmd.cwd(home);
    }
    cmd.arg("-o");
    cmd.arg("StrictHostKeyChecking=accept-new");
    cmd.arg("-o");
    cmd.arg("ServerAliveInterval=15");
    if !host.port.trim().is_empty() {
        cmd.arg("-p");
        cmd.arg(host.port.trim());
    }
    if !host.identity_file.trim().is_empty() {
        cmd.arg("-i");
        cmd.arg(host.identity_file.trim());
    }
    if !host.proxy_command.trim().is_empty() {
        cmd.arg("-o");
        cmd.arg(format!("ProxyCommand={}", host.proxy_command.trim()));
    }
    let target = ssh_target(host);
    if target.is_empty() {
        return Err("host has no address".into());
    }
    cmd.arg(&target);
    cmd.arg(remote_cmd);

    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let password = host.password.clone();
    let no_pw = password.is_empty();

    let handle = thread::spawn(move || -> String {
        let mut buf = [0u8; 8192];
        let mut sent_pw = no_pw;
        let mut recent = String::new();
        let mut output = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    if !sent_pw {
                        recent.push_str(&chunk);
                        let low = recent.to_lowercase();
                        if low.contains("password:") || low.contains("password for") {
                            let _ = writer.write_all(password.as_bytes());
                            let _ = writer.write_all(b"\n");
                            let _ = writer.flush();
                            sent_pw = true;
                            recent.clear();
                            continue;
                        }
                        if recent.len() > 600 {
                            recent.drain(0..recent.len() - 300);
                        }
                    } else {
                        output.push_str(&chunk);
                    }
                }
            }
        }
        output
    });

    let start = Instant::now();
    let mut exited = false;
    while start.elapsed().as_secs() < timeout_secs {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    if !exited {
        let _ = child.kill();
    }
    drop(pair.master);

    let raw = handle
        .join()
        .map_err(|_| "reader thread panicked".to_string())?;
    Ok(strip_ansi(&raw))
}

fn parse_ls_output(raw: &str) -> Vec<FileEntry> {
    let mut entries = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("total ") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 9 {
            continue;
        }
        let perms = tokens[0];
        if perms.len() < 2 {
            continue;
        }
        let is_dir = perms.starts_with('d');
        let size_raw = tokens[4];
        let name = tokens[8..].join(" ");
        let display = if let Some(i) = name.find(" -> ") {
            name[..i].to_string()
        } else {
            name
        };
        if display == "." || display == ".." {
            continue;
        }
        let size = if is_dir {
            "-".into()
        } else {
            size_raw
                .parse::<u64>()
                .map(format_size)
                .unwrap_or_else(|_| size_raw.to_string())
        };
        entries.push(FileEntry {
            name: display,
            is_dir,
            size,
        });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    entries
}

fn scp_program() -> String {
    let p = r"C:\Windows\System32\OpenSSH\scp.exe";
    if Path::new(p).exists() {
        p.to_string()
    } else {
        "scp.exe".to_string()
    }
}

fn run_scp_command(
    host: &Host,
    local_path: &str,
    remote_path: &str,
    upload: bool,
) -> Result<(), String> {
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 200,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let mut cmd = CommandBuilder::new(scp_program());
    for (k, v) in std::env::vars() {
        cmd.env(k, v);
    }
    if let Ok(home) = std::env::var("USERPROFILE") {
        cmd.cwd(home);
    }
    cmd.arg("-r");
    cmd.arg("-o");
    cmd.arg("StrictHostKeyChecking=accept-new");
    if !host.port.trim().is_empty() {
        cmd.arg("-P");
        cmd.arg(host.port.trim());
    }
    if !host.identity_file.trim().is_empty() {
        cmd.arg("-i");
        cmd.arg(host.identity_file.trim());
    }
    if !host.proxy_command.trim().is_empty() {
        cmd.arg("-o");
        cmd.arg(format!("ProxyCommand={}", host.proxy_command.trim()));
    }

    let target = ssh_target(host);
    if upload {
        cmd.arg(local_path);
        cmd.arg(format!("{}:{}", target, remote_path));
    } else {
        cmd.arg(format!("{}:{}", target, remote_path));
        cmd.arg(local_path);
    }

    let mut child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;

    let password = host.password.clone();
    let no_pw = password.is_empty();

    let handle = thread::spawn(move || -> String {
        let mut buf = [0u8; 8192];
        let mut sent_pw = no_pw;
        let mut recent = String::new();
        let mut output = String::new();
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                    if !sent_pw {
                        recent.push_str(&chunk);
                        let low = recent.to_lowercase();
                        if low.contains("password:") || low.contains("password for") {
                            let _ = writer.write_all(password.as_bytes());
                            let _ = writer.write_all(b"\n");
                            let _ = writer.flush();
                            sent_pw = true;
                            recent.clear();
                            continue;
                        }
                    }
                    output.push_str(&chunk);
                }
            }
        }
        output
    });

    let start = Instant::now();
    let mut exited = false;
    while start.elapsed().as_secs() < 300 {
        if let Ok(Some(_)) = child.try_wait() {
            exited = true;
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    if !exited {
        let _ = child.kill();
        drop(pair.master);
        let _ = handle.join();
        return Err("transfer timed out (5 min)".into());
    }
    drop(pair.master);

    let output = handle
        .join()
        .map_err(|_| "reader panicked".to_string())?;
    let low = output.to_lowercase();
    if low.contains("permission denied") || low.contains("no such file") {
        return Err(strip_ansi(&output));
    }
    Ok(())
}

fn list_drives_fast() -> Vec<FileEntry> {
    let mask: u32 = unsafe {
        extern "system" {
            fn GetLogicalDrives() -> u32;
        }
        GetLogicalDrives()
    };
    let mut drives = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) != 0 {
            let letter = (b'A' + i as u8) as char;
            drives.push(FileEntry {
                name: format!("{}:\\", letter),
                is_dir: true,
                size: "-".into(),
            });
        }
    }
    drives
}

#[tauri::command]
fn sftp_list_local(path: String) -> Result<(String, Vec<FileEntry>), String> {
    if path == "drives" {
        return Ok(("drives".into(), list_drives_fast()));
    }
    let effective = if path.is_empty() {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".into())
    } else {
        path
    };
    let p = PathBuf::from(&effective);
    if !p.is_dir() {
        return Err(format!("not a directory: {}", p.display()));
    }
    let display = p
        .to_string_lossy()
        .to_string()
        .strip_prefix(r"\\?\")
        .unwrap_or(&p.to_string_lossy())
        .to_string();
    let mut entries = Vec::new();
    let rd = fs::read_dir(&p).map_err(|e| e.to_string())?;
    for entry in rd {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        entries.push(FileEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            is_dir: meta.is_dir(),
            size: if meta.is_dir() {
                "-".into()
            } else {
                format_size(meta.len())
            },
        });
        if entries.len() >= 500 {
            break;
        }
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok((display, entries))
}

#[tauri::command]
fn sftp_list_remote(host: Host, path: String) -> Result<(String, Vec<FileEntry>), String> {
    let remote_path = if path.is_empty() {
        "~".to_string()
    } else {
        path
    };
    let cmd = format!(
        "echo '___MKTR_PWD___' && cd {} && pwd && echo '___MKTR_LS___' && ls -la",
        shell_escape(&remote_path)
    );
    let raw = run_ssh_command(&host, &cmd, 30)?;

    let pwd_marker = "___MKTR_PWD___";
    let ls_marker = "___MKTR_LS___";

    let pwd_start = raw.find(pwd_marker).unwrap_or(0);
    let after_pwd = &raw[pwd_start + pwd_marker.len()..];
    let abs_path = after_pwd
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("/")
        .trim()
        .to_string();

    let ls_start = raw.find(ls_marker).unwrap_or(raw.len());
    let ls_data = if ls_start < raw.len() {
        &raw[ls_start + ls_marker.len()..]
    } else {
        ""
    };
    let entries = parse_ls_output(ls_data);
    Ok((abs_path, entries))
}

#[tauri::command]
fn sftp_upload(
    host: Host,
    local_path: String,
    remote_path: String,
) -> Result<String, String> {
    run_scp_command(&host, &local_path, &remote_path, true)?;
    Ok("upload complete".into())
}

#[tauri::command]
fn sftp_download(
    host: Host,
    remote_path: String,
    local_path: String,
) -> Result<String, String> {
    run_scp_command(&host, &local_path, &remote_path, false)?;
    Ok("download complete".into())
}

// ---------------- Backup / Restore ----------------

#[tauri::command]
fn backup_create(master: String, dest: String) -> Result<String, String> {
    let hosts = decrypt(&master)?;
    let ssh = ssh_dir();
    let mut ssh_files: HashMap<String, String> = HashMap::new();
    if ssh.is_dir() {
        if let Ok(rd) = fs::read_dir(&ssh) {
            for entry in rd {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                let meta = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if !meta.is_file() || meta.len() > 10_000_000 {
                    continue;
                }
                if let Ok(bytes) = fs::read(entry.path()) {
                    let name = entry.file_name().to_string_lossy().to_string();
                    ssh_files.insert(name, STANDARD.encode(&bytes));
                }
            }
        }
    }
    let payload = BackupPayload { hosts, ssh_files };
    let plaintext = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(&master, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "encryption failed".to_string())?;
    let dest_path = PathBuf::from(&dest);
    let mut out = Vec::with_capacity(6 + 16 + 12 + ct.len());
    out.extend_from_slice(MAGIC_BACKUP);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    fs::write(&dest_path, &out).map_err(|e| e.to_string())?;
    Ok(dest_path.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_save_file(default_name: String) -> Option<String> {
    rfd::FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("TERMISMUS Backup", &["tmb"])
        .save_file()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn pick_open_file() -> Option<String> {
    rfd::FileDialog::new()
        .add_filter("TERMISMUS Backup", &["tmb"])
        .pick_file()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
fn backup_restore(master: String, path: String) -> Result<Vec<Host>, String> {
    let data = fs::read(&path).map_err(|e| format!("cannot read backup: {e}"))?;
    if data.len() < 6 + 16 + 12 || &data[0..6] != MAGIC_BACKUP {
        return Err("bukan file backup TERMISMUS yang valid".into());
    }
    let salt = &data[6..22];
    let nonce = &data[22..34];
    let ct = &data[34..];
    let key = derive_key(&master, salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "password salah atau backup corrupt".to_string())?;
    let payload: BackupPayload = serde_json::from_slice(&pt).map_err(|e| e.to_string())?;
    let ssh = ssh_dir();
    let _ = fs::create_dir_all(&ssh);
    for (name, b64) in &payload.ssh_files {
        if let Ok(bytes) = STANDARD.decode(b64) {
            let _ = fs::write(ssh.join(name), &bytes);
        }
    }
    encrypt_and_save(&master, &payload.hosts)?;
    Ok(payload.hosts)
}

// ---------------- Recovery scanner ----------------

fn ssh_dir() -> PathBuf {
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".ssh")
}

fn scan_recovered() -> Vec<Host> {
    let mut hosts: Vec<Host> = Vec::new();
    let dir = ssh_dir();
    let mut cfg_files: Vec<PathBuf> = vec![dir.join("config"), dir.join("config.bak")];
    if let Ok(base) = std::env::var("LOCALAPPDATA") {
        cfg_files.push(
            PathBuf::from(base)
                .join("NVIDIA Corporation")
                .join("Sync")
                .join("config")
                .join("ssh_config"),
        );
    }
    for f in cfg_files {
        if let Ok(text) = fs::read_to_string(&f) {
            parse_ssh_config(&text, &mut hosts);
        }
    }
    if let Ok(text) = fs::read_to_string(dir.join("known_hosts")) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("|1|") {
                continue;
            }
            if let Some(tok) = line.split_whitespace().next() {
                for raw in tok.split(',') {
                    let (hn, port) = split_host_port(raw);
                    if hn.is_empty() || hn == "github.com" {
                        continue;
                    }
                    if !hosts.iter().any(|h| h.hostname.eq_ignore_ascii_case(&hn)) {
                        hosts.push(Host {
                            id: new_id(&hn),
                            label: hn.clone(),
                            hostname: hn,
                            port,
                            group: "known_hosts".into(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }
    hosts
}

fn split_host_port(raw: &str) -> (String, String) {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        if let Some(idx) = rest.find("]:") {
            return (rest[..idx].to_string(), rest[idx + 2..].to_string());
        }
        return (rest.trim_end_matches(']').to_string(), String::new());
    }
    (raw.to_string(), String::new())
}

fn parse_ssh_config(text: &str, hosts: &mut Vec<Host>) {
    let mut cur: Option<Host> = None;
    fn flush(cur: &mut Option<Host>, hosts: &mut Vec<Host>) {
        if let Some(h) = cur.take() {
            if h.hostname.is_empty() {
                return;
            }
            if let Some(ex) = hosts
                .iter_mut()
                .find(|e| e.hostname.eq_ignore_ascii_case(&h.hostname) && e.user == h.user)
            {
                if ex.identity_file.is_empty() {
                    ex.identity_file = h.identity_file.clone();
                }
                if ex.proxy_command.is_empty() {
                    ex.proxy_command = h.proxy_command.clone();
                }
                if ex.port.is_empty() {
                    ex.port = h.port.clone();
                }
            } else {
                hosts.push(h);
            }
        }
    }
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let key = it.next().unwrap_or("").to_lowercase();
        let val = it.next().unwrap_or("").trim().trim_matches('"').to_string();
        match key.as_str() {
            "host" => {
                flush(&mut cur, hosts);
                if val == "*" || val.is_empty() {
                    cur = None;
                } else {
                    let first = val.split_whitespace().next().unwrap_or("").to_string();
                    cur = Some(Host {
                        id: new_id(&first),
                        label: first.clone(),
                        hostname: first,
                        group: "ssh config".into(),
                        ..Default::default()
                    });
                }
            }
            "hostname" => {
                if let Some(h) = cur.as_mut() {
                    h.hostname = val;
                }
            }
            "user" => {
                if let Some(h) = cur.as_mut() {
                    h.user = val;
                }
            }
            "port" => {
                if let Some(h) = cur.as_mut() {
                    h.port = val;
                }
            }
            "identityfile" => {
                if let Some(h) = cur.as_mut() {
                    h.identity_file = val;
                }
            }
            "proxycommand" => {
                if let Some(h) = cur.as_mut() {
                    h.proxy_command = val;
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, hosts);
}

fn new_id(seed: &str) -> String {
    let mut n = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut n);
    format!("{}-{:02x}{:02x}{:02x}{:02x}", seed, n[0], n[1], n[2], n[3])
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            vault_location,
            create_vault,
            unlock_vault,
            save_vault,
            recovered_hosts,
            backup_create,
            backup_restore,
            pick_save_file,
            pick_open_file,
            pty_open,
            pty_input,
            pty_resize,
            pty_close,
            sftp_list_local,
            sftp_list_remote,
            sftp_upload,
            sftp_download
        ])
        .run(tauri::generate_context!())
        .expect("error while running TERMISMUS");
}
