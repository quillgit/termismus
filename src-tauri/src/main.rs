#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

mod backup;
mod clipboard;
mod cloud;
mod models;
mod pty;
mod recovery;
mod sftp;
mod ssh;
mod vault;

pub struct AppState {
    pub local_sessions: pty::LocalSessions,
    pub ssh_sessions: ssh::SshSessions,
    pub cloud: cloud::CloudStateRef,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            local_sessions: pty::new_sessions(),
            ssh_sessions: ssh::new_sessions(),
            cloud: cloud::new_state(),
        }
    }
}

fn main() {
    let builder = tauri::Builder::default();

    // Single-instance guard: must be the first plugin registered. A second
    // launch exits immediately and brings the existing window to the front
    // instead of spawning another process (each one holds its own WebView).
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
        use tauri::Manager;
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
        }
    }));

    builder
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            // vault
            vault::vault_exists,
            vault::vault_location,
            vault::create_vault,
            vault::unlock_vault,
            vault::save_vault,
            vault::recovered_hosts,
            // backup
            backup::backup_create,
            backup::backup_restore,
            backup::pick_save_file,
            backup::pick_open_file,
            // native SSH
            ssh::ssh_open,
            ssh::ssh_input,
            ssh::ssh_resize,
            ssh::ssh_close,
            // local terminal
            pty::pty_list_shells,
            pty::pty_open_local,
            pty::pty_input_local,
            pty::pty_resize_local,
            pty::pty_close_local,
            // SFTP / file browsing
            sftp::sftp_list_local,
            sftp::sftp_list_remote,
            sftp::sftp_upload,
            sftp::sftp_download,
            // cloud sync
            cloud::cloud_register,
            cloud::cloud_login,
            cloud::cloud_restore_session,
            cloud::cloud_logout,
            cloud::cloud_status,
            cloud::cloud_push,
            cloud::cloud_pull,
            cloud::cloud_history,
            // clipboard
            clipboard::clipboard_read,
            clipboard::clipboard_write,
        ])
        .run(tauri::generate_context!())
        .expect("error while running TERMISMUS");
}
