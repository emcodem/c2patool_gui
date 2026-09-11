use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use tauri::Manager;

mod trust;
use trust::{get_trust_sources, save_trust_sources};

#[cfg(target_os = "windows")]
const C2PATOOL_BYTES: &[u8] = include_bytes!("../binaries/c2patool-x86_64-pc-windows-msvc.exe");
#[cfg(target_os = "windows")]
const C2PATOOL_FILENAME: &str = "c2patool.exe";

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const C2PATOOL_BYTES: &[u8] = include_bytes!("../binaries/c2patool-aarch64-apple-darwin");
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
const C2PATOOL_BYTES: &[u8] = include_bytes!("../binaries/c2patool-x86_64-apple-darwin");
#[cfg(target_os = "macos")]
const C2PATOOL_FILENAME: &str = "c2patool";

static C2PATOOL_PATH: OnceLock<PathBuf> = OnceLock::new();

/// The c2patool binary is embedded in this executable (see the `include_bytes!`
/// constants above) so the app ships as a single portable file. On first use we
/// write it out to a per-user cache dir and reuse that extracted copy afterward.
fn ensure_c2patool(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(p) = C2PATOOL_PATH.get() {
        return Ok(p.clone());
    }

    let cache_dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("failed to resolve cache dir: {e}"))?;
    let bin_dir = cache_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).map_err(|e| format!("failed to create cache dir: {e}"))?;

    let dest = bin_dir.join(C2PATOOL_FILENAME);

    let needs_write = match std::fs::metadata(&dest) {
        Ok(meta) => meta.len() != C2PATOOL_BYTES.len() as u64,
        Err(_) => true,
    };

    if needs_write {
        let mut file = std::fs::File::create(&dest)
            .map_err(|e| format!("failed to create {}: {e}", dest.display()))?;
        file.write_all(C2PATOOL_BYTES)
            .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|e| e.to_string())?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&dest, perms).map_err(|e| e.to_string())?;
        }
    }

    let _ = C2PATOOL_PATH.set(dest.clone());
    Ok(dest)
}

#[tauri::command]
fn analyze_file(app: tauri::AppHandle, path: String) -> Result<serde_json::Value, String> {
    let bin_path = ensure_c2patool(&app)?;

    let mut args = vec!["-d".to_string(), path];

    // c2patool's "URL or path" arg parser misreads an absolute Windows path
    // (e.g. `C:\...`) as a URL with scheme `c`, so we run it with its cwd set
    // to the trust file's directory and pass just the filename instead.
    let trust_pem = trust::merged_pem_path(&app)?;
    let trust_dir = trust_pem.parent().map(|p| p.to_path_buf());
    if trust_pem.is_file() {
        args.push("trust".to_string());
        args.push("--trust_anchors".to_string());
        args.push(
            trust_pem
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| trust_pem.to_string_lossy().into_owned()),
        );
    }

    let mut command = std::process::Command::new(&bin_path);
    command.args(&args);
    if let Some(dir) = trust_dir {
        command.current_dir(dir);
    }

    let output = command
        .output()
        .map_err(|e| format!("failed to run c2patool: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(if stderr.trim().is_empty() {
            format!("c2patool exited with status {}", output.status)
        } else {
            stderr
        });
    }

    let stdout_text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str::<serde_json::Value>(&stdout_text).map_err(|e| {
        format!("failed to parse c2patool JSON output: {e}\n\nraw output:\n{stdout_text}")
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            analyze_file,
            get_trust_sources,
            save_trust_sources
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                if let Err(e) = trust::get_trust_sources(handle) {
                    eprintln!("failed to initialize default trust sources: {e}");
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
