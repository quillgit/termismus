use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Host {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub identity_file: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub proxy_command: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Clone, Serialize)]
pub struct PtyOut {
    pub id: String,
    pub data: String,
}

#[derive(Clone, Serialize)]
pub struct PtyExit {
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: String,
}

#[derive(Serialize, Deserialize)]
pub struct BackupPayload {
    pub hosts: Vec<Host>,
    pub ssh_files: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultVersion {
    pub version_id: String,
    pub version: i64,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub blob_size: i64,
    #[serde(default)]
    pub created_at: String,
}

#[derive(Serialize)]
pub struct CloudPullResult {
    pub message: String,
    pub hosts: Vec<Host>,
    pub backup_path: Option<String>,
}

pub fn new_id(seed: &str) -> String {
    let mut n = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut n);
    format!("{}-{:02x}{:02x}{:02x}{:02x}", seed, n[0], n[1], n[2], n[3])
}

pub fn format_size(bytes: u64) -> String {
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

#[allow(dead_code)]
pub fn strip_ansi(s: &str) -> String {
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
