use std::fs;
use std::path::PathBuf;

use crate::models::{new_id, Host};

pub fn ssh_dir() -> PathBuf {
    let base = std::env::var("USERPROFILE").unwrap_or_else(|_| ".".into());
    PathBuf::from(base).join(".ssh")
}

pub fn scan_recovered() -> Vec<Host> {
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
                    ex.identity_file.clone_from(&h.identity_file);
                }
                if ex.proxy_command.is_empty() {
                    ex.proxy_command.clone_from(&h.proxy_command);
                }
                if ex.port.is_empty() {
                    ex.port.clone_from(&h.port);
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
