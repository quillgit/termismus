use crate::models::{format_size, FileEntry, Host};
use crate::ssh::{connect_and_auth, SshConn};
use russh_sftp::client::SftpSession;
use std::fs;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

#[cfg(windows)]
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

#[cfg(not(windows))]
fn list_drives_fast() -> Vec<FileEntry> {
    vec![FileEntry {
        name: "/".into(),
        is_dir: true,
        size: "-".into(),
    }]
}

fn default_local_dir() -> String {
    std::env::var("USERPROFILE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("HOME").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "C:\\".into()
            } else {
                "/".into()
            }
        })
}

#[tauri::command]
pub fn sftp_list_local(path: String) -> Result<(String, Vec<FileEntry>), String> {
    if path == "drives" {
        return Ok(("drives".into(), list_drives_fast()));
    }
    let effective = if path.is_empty() {
        default_local_dir()
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

async fn open_sftp(host: &Host) -> Result<(SshConn, SftpSession), String> {
    let conn = connect_and_auth(host).await?;
    let res = async {
        let ch = conn
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("channel open failed: {e}"))?;
        ch.request_subsystem(true, "sftp")
            .await
            .map_err(|e| format!("SFTP subsystem unavailable: {e}"))?;
        let sftp = SftpSession::new(ch.into_stream())
            .await
            .map_err(|e| format!("SFTP subsystem unavailable: {e}"))?;
        sftp.set_timeout(30);
        Ok::<_, String>(sftp)
    }
    .await;
    match res {
        Ok(sftp) => Ok((conn, sftp)),
        Err(e) => {
            conn.close().await;
            Err(e)
        }
    }
}

async fn finish(conn: SshConn, sftp: SftpSession) {
    let _ = sftp.close().await;
    conn.close().await;
}

async fn resolve_remote(sftp: &SftpSession, path: &str) -> Result<String, String> {
    let p = path.trim();
    let target = if p.is_empty() || p == "~" {
        "."
    } else if let Some(rest) = p.strip_prefix("~/") {
        if rest.is_empty() {
            "."
        } else {
            rest
        }
    } else {
        p
    };
    sftp.canonicalize(target)
        .await
        .map_err(|e| format!("cannot resolve remote path '{p}': {e}"))
}

fn join_remote(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Resolve the destination file path of an upload: absolute paths are used as-is,
/// "~/x" and relative paths are resolved against the login directory via the parent.
async fn resolve_remote_file(sftp: &SftpSession, path: &str) -> Result<String, String> {
    let p = path.trim();
    if p.starts_with('/') {
        return Ok(p.to_string());
    }
    let rel = p.strip_prefix("~/").unwrap_or(p);
    if rel.is_empty() || rel == "~" || rel.ends_with('/') {
        return Err("invalid remote file path".into());
    }
    let (parent, name) = match rel.rfind('/') {
        Some(i) => (&rel[..i], &rel[i + 1..]),
        None => (".", rel),
    };
    let parent = if parent.is_empty() { "/" } else { parent };
    let abs = sftp
        .canonicalize(parent)
        .await
        .map_err(|e| format!("cannot resolve remote path '{p}': {e}"))?;
    Ok(join_remote(&abs, name))
}

#[tauri::command]
pub async fn sftp_list_remote(
    host: Host,
    path: String,
) -> Result<(String, Vec<FileEntry>), String> {
    let (conn, sftp) = open_sftp(&host).await?;
    let res = list_remote_inner(&sftp, &path).await;
    finish(conn, sftp).await;
    res
}

async fn list_remote_inner(
    sftp: &SftpSession,
    path: &str,
) -> Result<(String, Vec<FileEntry>), String> {
    let abs = resolve_remote(sftp, path).await?;
    let rd = sftp
        .read_dir(abs.clone())
        .await
        .map_err(|e| format!("cannot list '{abs}': {e}"))?;
    let mut entries = Vec::new();
    for entry in rd {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let meta = entry.metadata();
        let mut is_dir = entry.file_type().is_dir();
        if entry.file_type().is_symlink() {
            if let Ok(m) = sftp.metadata(join_remote(&abs, &name)).await {
                is_dir = m.file_type().is_dir();
            }
        }
        let size = if is_dir {
            "-".to_string()
        } else {
            format_size(meta.len())
        };
        entries.push(FileEntry { name, is_dir, size });
    }
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok((abs, entries))
}

#[tauri::command]
pub async fn sftp_upload(
    host: Host,
    local_path: String,
    remote_path: String,
) -> Result<String, String> {
    let meta = tokio::fs::metadata(&local_path)
        .await
        .map_err(|e| format!("cannot read local file: {e}"))?;
    if !meta.is_file() {
        return Err("only single files can be uploaded".into());
    }
    let (conn, sftp) = open_sftp(&host).await?;
    let res = upload_inner(&sftp, &local_path, &remote_path).await;
    finish(conn, sftp).await;
    res.map(|n| format!("upload complete ({})", format_size(n)))
}

async fn upload_inner(sftp: &SftpSession, local: &str, remote: &str) -> Result<u64, String> {
    let remote = resolve_remote_file(sftp, remote).await?;
    let mut src = tokio::fs::File::open(local)
        .await
        .map_err(|e| format!("cannot read local file: {e}"))?;
    let part = format!("{remote}.part");
    let mut dst = sftp
        .create(part.clone())
        .await
        .map_err(|e| format!("cannot create remote file '{part}': {e}"))?;
    let copy = async {
        let n = tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(|e| format!("upload failed: {e}"))?;
        dst.shutdown()
            .await
            .map_err(|e| format!("upload failed: {e}"))?;
        Ok::<u64, String>(n)
    }
    .await;
    drop(dst);
    let n = match copy {
        Ok(n) => n,
        Err(e) => {
            let _ = sftp.remove_file(part).await;
            return Err(e);
        }
    };
    // SFTP rename does not replace an existing file on most servers: remove first.
    let _ = sftp.remove_file(remote.clone()).await;
    if let Err(e) = sftp.rename(part.clone(), remote.clone()).await {
        let _ = sftp.remove_file(part).await;
        return Err(format!("cannot finalize remote file '{remote}': {e}"));
    }
    Ok(n)
}

#[tauri::command]
pub async fn sftp_download(
    host: Host,
    remote_path: String,
    local_path: String,
) -> Result<String, String> {
    let (conn, sftp) = open_sftp(&host).await?;
    let res = download_inner(&sftp, &remote_path, &local_path).await;
    finish(conn, sftp).await;
    res.map(|n| format!("download complete ({})", format_size(n)))
}

async fn download_inner(sftp: &SftpSession, remote: &str, local: &str) -> Result<u64, String> {
    let remote = resolve_remote_file(sftp, remote).await?;
    let mut rf = sftp
        .open(remote.clone())
        .await
        .map_err(|e| format!("cannot open remote file '{remote}': {e}"))?;
    let tmp = format!("{local}.part");
    let copy = async {
        let mut out = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| format!("cannot write local file: {e}"))?;
        let n = tokio::io::copy(&mut rf, &mut out)
            .await
            .map_err(|e| format!("download failed: {e}"))?;
        out.flush()
            .await
            .map_err(|e| format!("cannot write local file: {e}"))?;
        out.sync_all()
            .await
            .map_err(|e| format!("cannot write local file: {e}"))?;
        drop(out);
        fs::rename(&tmp, local).map_err(|e| format!("cannot write local file: {e}"))?;
        Ok::<u64, String>(n)
    }
    .await;
    if copy.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    copy
}
