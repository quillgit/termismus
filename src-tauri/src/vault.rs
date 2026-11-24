use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

use crate::models::Host;
use crate::recovery::scan_recovered;

pub const MIN_MASTER_LEN: usize = 8;
/// Header written to new vault files.
pub const MAGIC: &[u8; 6] = b"TRMSV1";
/// Header of vaults written before the TERMISMUS rebrand; still readable.
pub const LEGACY_MAGIC: &[u8; 6] = b"MKTRV1";

const DATA_DIR: &str = "TERMISMUS";
const LEGACY_DATA_DIR: &str = "MKTRVault";

pub fn vault_dir() -> PathBuf {
    let base = PathBuf::from(std::env::var("APPDATA").unwrap_or_else(|_| ".".into()));
    let p = base.join(DATA_DIR);
    if !p.exists() {
        migrate_legacy_dir(&base.join(LEGACY_DATA_DIR), &p);
    }
    let _ = fs::create_dir_all(&p);
    p
}

/// One-time copy of the pre-rebrand data folder. The old folder is left
/// untouched as a fallback; copy into a temp dir then rename so a partial
/// copy never looks like a finished migration.
fn migrate_legacy_dir(old: &std::path::Path, new: &std::path::Path) {
    if !old.join("vault.bin").is_file() {
        return;
    }
    let tmp = new.with_extension("migrating");
    let _ = fs::remove_dir_all(&tmp);
    if fs::create_dir_all(&tmp).is_err() {
        return;
    }
    let Ok(rd) = fs::read_dir(old) else { return };
    for entry in rd.flatten() {
        if entry.path().is_file() && fs::copy(entry.path(), tmp.join(entry.file_name())).is_err() {
            let _ = fs::remove_dir_all(&tmp);
            return;
        }
    }
    if fs::rename(&tmp, new).is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
}

fn has_vault_magic(data: &[u8]) -> bool {
    data.len() >= 6 + 16 + 12 && (&data[0..6] == MAGIC || &data[0..6] == LEGACY_MAGIC)
}

pub fn vault_path() -> PathBuf {
    vault_dir().join("vault.bin")
}

pub fn derive_key(master: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(master.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

pub fn encrypt_and_save(master: &str, hosts: &[Host]) -> Result<(), String> {
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

pub fn decrypt(master: &str) -> Result<Vec<Host>, String> {
    let data = fs::read(vault_path()).map_err(|e| format!("cannot read vault: {e}"))?;
    decrypt_bytes(master, &data)
}

pub fn decrypt_bytes(master: &str, data: &[u8]) -> Result<Vec<Host>, String> {
    if !has_vault_magic(data) {
        return Err("vault file is corrupt or not a TERMISMUS vault".into());
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

pub fn encrypt_raw(master: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = derive_key(master, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), data)
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(6 + 16 + 12 + ct.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

// ── Tauri commands ──

#[tauri::command]
pub fn vault_exists() -> bool {
    vault_path().exists()
}

#[tauri::command]
pub fn vault_location() -> String {
    vault_path().to_string_lossy().to_string()
}

#[tauri::command]
pub fn create_vault(master: String, seed: bool) -> Result<Vec<Host>, String> {
    if master.chars().count() < MIN_MASTER_LEN {
        return Err("master password must be at least 8 characters".into());
    }
    let hosts = if seed { scan_recovered() } else { Vec::new() };
    encrypt_and_save(&master, &hosts)?;
    Ok(hosts)
}

#[tauri::command]
pub fn unlock_vault(master: String) -> Result<Vec<Host>, String> {
    decrypt(&master)
}

#[tauri::command]
pub fn save_vault(master: String, hosts: Vec<Host>) -> Result<(), String> {
    decrypt(&master)?;
    encrypt_and_save(&master, &hosts)
}

#[tauri::command]
pub fn recovered_hosts() -> Vec<Host> {
    scan_recovered()
}
