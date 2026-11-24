use base64::{engine::general_purpose::STANDARD, Engine as _};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use tauri::Emitter;

use crate::models::{PtyExit, PtyOut};

type Writer = Arc<Mutex<Box<dyn Write + Send>>>;
type Master = Arc<Mutex<Box<dyn portable_pty::MasterPty + Send>>>;
type ChildH = Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>;

pub struct LocalSession {
    pub writer: Writer,
    pub master: Master,
    pub child: ChildH,
}

pub type LocalSessions = Arc<Mutex<HashMap<String, LocalSession>>>;

pub fn new_sessions() -> LocalSessions {
    Arc::new(Mutex::new(HashMap::new()))
}

fn default_shell() -> String {
    if let Ok(shell) = std::env::var("COMSPEC") {
        if std::path::Path::new(&shell).exists() {
            return shell;
        }
    }
    let pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe";
    if std::path::Path::new(pwsh).exists() {
        return pwsh.to_string();
    }
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    if std::path::Path::new(ps).exists() {
        return ps.to_string();
    }
    "cmd.exe".to_string()
}

#[derive(serde::Serialize, Clone)]
pub struct ShellProfile {
    pub id: String,
    pub name: String,
    pub path: String,
    pub args: Vec<String>,
}

fn push_if_exists(out: &mut Vec<ShellProfile>, id: &str, name: &str, path: &str, args: &[&str]) {
    if std::path::Path::new(path).exists() && !out.iter().any(|p| p.id == id) {
        out.push(ShellProfile {
            id: id.into(),
            name: name.into(),
            path: path.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
        });
    }
}

/// Detect shells available on this machine. The first entry is the default.
#[tauri::command]
pub fn pty_list_shells() -> Vec<ShellProfile> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        let pf = std::env::var("ProgramFiles").unwrap_or_else(|_| r"C:\Program Files".into());
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        push_if_exists(&mut out, "pwsh", "PowerShell 7", &format!(r"{pf}\PowerShell\7\pwsh.exe"), &["-NoLogo"]);
        push_if_exists(
            &mut out,
            "powershell",
            "Windows PowerShell",
            &format!(r"{windir}\System32\WindowsPowerShell\v1.0\powershell.exe"),
            &["-NoLogo"],
        );
        let cmd = std::env::var("COMSPEC").unwrap_or_else(|_| format!(r"{windir}\System32\cmd.exe"));
        push_if_exists(&mut out, "cmd", "Command Prompt", &cmd, &[]);
        push_if_exists(&mut out, "gitbash", "Git Bash", &format!(r"{pf}\Git\bin\bash.exe"), &["--login", "-i"]);
        push_if_exists(&mut out, "wsl", "WSL", &format!(r"{windir}\System32\wsl.exe"), &[]);
    }
    #[cfg(not(windows))]
    {
        if let Ok(sh) = std::env::var("SHELL") {
            let name = std::path::Path::new(&sh)
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "shell".into());
            push_if_exists(&mut out, &name.clone(), &name, &sh, &["-l"]);
        }
        push_if_exists(&mut out, "zsh", "zsh", "/bin/zsh", &["-l"]);
        push_if_exists(&mut out, "bash", "bash", "/bin/bash", &["-l"]);
        push_if_exists(&mut out, "sh", "sh", "/bin/sh", &[]);
    }
    out
}

#[tauri::command]
pub fn pty_open_local(
    app: tauri::AppHandle,
    state: tauri::State<crate::AppState>,
    session_id: String,
    rows: u16,
    cols: u16,
    shell: Option<String>,
    args: Option<Vec<String>>,
    name: Option<String>,
) -> Result<String, String> {
    let shell_path = shell.unwrap_or_else(default_shell);
    let shell_name = name.filter(|n| !n.trim().is_empty()).unwrap_or_else(|| {
        std::path::Path::new(&shell_path)
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "shell".into())
    });

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: rows.max(10),
            cols: cols.max(20),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| e.to_string())?;

    let mut cmd = CommandBuilder::new(&shell_path);
    for a in args.unwrap_or_default() {
        cmd.arg(a);
    }
    for (k, v) in std::env::vars() {
        cmd.env(k, v);
    }
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("USERPROFILE") {
        cmd.cwd(home);
    }

    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer: Writer = Arc::new(Mutex::new(
        pair.master.take_writer().map_err(|e| e.to_string())?,
    ));
    let master: Master = Arc::new(Mutex::new(pair.master));
    let child: ChildH = Arc::new(Mutex::new(child));

    {
        let mut map = state.local_sessions.lock().unwrap();
        map.insert(
            session_id.clone(),
            LocalSession {
                writer: writer.clone(),
                master,
                child,
            },
        );
    }

    let sessions = state.local_sessions.clone();
    let id = session_id.clone();
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
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
                }
            }
        }
        let _ = app.emit("pty-exit", PtyExit { id: id.clone() });
        if let Ok(mut map) = sessions.lock() {
            map.remove(&id);
        }
    });

    Ok(shell_name)
}

#[tauri::command]
pub fn pty_input_local(
    state: tauri::State<crate::AppState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let map = state.local_sessions.lock().unwrap();
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
pub fn pty_resize_local(
    state: tauri::State<crate::AppState>,
    session_id: String,
    rows: u16,
    cols: u16,
) -> Result<(), String> {
    let map = state.local_sessions.lock().unwrap();
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
pub fn pty_close_local(
    state: tauri::State<crate::AppState>,
    session_id: String,
) -> Result<(), String> {
    let mut map = state.local_sessions.lock().unwrap();
    if let Some(s) = map.remove(&session_id) {
        if let Ok(mut c) = s.child.lock() {
            let _ = c.kill();
        }
    }
    Ok(())
}
