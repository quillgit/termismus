use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::models::{BackupPayload, Host};
use crate::recovery::ssh_dir;
use crate::vault::{decrypt, derive_key, encrypt_and_save};

const MAGIC_BACKUP: &[u8; 6] = b"TMBB01";

#[tauri::command]
pub fn backup_create(master: String, dest: String) -> Result<String, String> {
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
pub fn pick_save_file(default_name: String) -> Option<String> {
    rfd::FileDialog::new()
        .set_file_name(&default_name)
        .add_filter("TERMISMUS Backup", &["tmb"])
        .save_file()
        .map(|p| p.to_string_lossy().to_string())
}

#[tauri::command]
pub fn pick_open_file() -> Option<String> {
    rfd::FileDialog::new()
        .add_filter("TERMISMUS Backup", &["tmb"])
        .pick_file()
        .map(|p| p.to_string_lossy().to_string())
}

fn valid_ssh_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains("..")
        && !name.contains(['/', '\\', ':', '\0'])
        && Path::new(name).components().count() == 1
}

#[tauri::command]
pub fn backup_restore(master: String, path: String) -> Result<Vec<Host>, String> {
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
    if payload.ssh_files.len() > 200 {
        return Err("backup berisi terlalu banyak file ssh".into());
    }
    let ssh = ssh_dir();
    let _ = fs::create_dir_all(&ssh);
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for (name, b64) in &payload.ssh_files {
        if !valid_ssh_name(name) {
            eprintln!("backup_restore: skipped invalid file name {:?}", name);
            continue;
        }
        let bytes = match STANDARD.decode(b64) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let target = ssh.join(name);
        if target.exists() {
            match fs::read(&target) {
                Ok(existing) if existing == bytes => continue,
                _ => {}
            }
            let mut bak = ssh.join(format!("{name}.bak-restore"));
            if bak.exists() {
                bak = ssh.join(format!("{name}.bak-restore-{secs}"));
            }
            if let Err(e) = fs::copy(&target, &bak) {
                eprintln!("backup_restore: cannot back up {name}, not overwriting: {e}");
                continue;
            }
            eprintln!("backup_restore: backed up existing {name} to {}", bak.display());
        }
        if let Err(e) = fs::write(&target, &bytes) {
            eprintln!("backup_restore: cannot write {name}: {e}");
        }
    }
    encrypt_and_save(&master, &payload.hosts)?;
    Ok(payload.hosts)
}
