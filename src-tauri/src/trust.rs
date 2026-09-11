use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

const SONY_TRUST_URL: &str = "https://imagevalidation.authenticity.sony.net/trust/sony.pem";
const C2PA_OFFICIAL_TRUST_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSource {
    pub id: String,
    pub label: String,
    pub source: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrustSourceStatus {
    pub id: String,
    pub ok: bool,
    pub error: Option<String>,
}

fn default_sources() -> Vec<TrustSource> {
    vec![
        TrustSource {
            id: "c2pa-official".into(),
            label: "C2PA Official Trust List".into(),
            source: C2PA_OFFICIAL_TRUST_URL.into(),
            enabled: true,
        },
        TrustSource {
            id: "sony".into(),
            label: "Sony".into(),
            source: SONY_TRUST_URL.into(),
            enabled: true,
        },
    ]
}

fn sources_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("failed to resolve app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create app data dir: {e}"))?;
    Ok(dir.join("trust-sources.json"))
}

pub fn merged_pem_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_cache_dir()
        .map_err(|e| format!("failed to resolve cache dir: {e}"))?
        .join("trust");
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create trust cache dir: {e}"))?;
    Ok(dir.join("merged-trust-anchors.pem"))
}

fn fetch_source(source: &str) -> Result<String, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        ureq::get(source)
            .call()
            .map_err(|e| format!("request failed: {e}"))?
            .into_string()
            .map_err(|e| format!("failed to read response body: {e}"))
    } else {
        std::fs::read_to_string(source).map_err(|e| format!("failed to read file: {e}"))
    }
}

/// Fetches/reads every enabled source, concatenates the PEM contents into one
/// file, and returns per-source status so the UI can surface fetch failures
/// without losing the sources the user configured.
fn rebuild_merged_file(
    app: &tauri::AppHandle,
    sources: &[TrustSource],
) -> Result<Vec<TrustSourceStatus>, String> {
    let mut merged = String::new();
    let mut statuses = Vec::new();

    for s in sources.iter().filter(|s| s.enabled) {
        match fetch_source(&s.source) {
            Ok(content) => {
                merged.push_str(content.trim());
                merged.push('\n');
                statuses.push(TrustSourceStatus {
                    id: s.id.clone(),
                    ok: true,
                    error: None,
                });
            }
            Err(e) => {
                eprintln!("trust source '{}' ({}) failed: {e}", s.id, s.source);
                statuses.push(TrustSourceStatus {
                    id: s.id.clone(),
                    ok: false,
                    error: Some(e),
                });
            }
        }
    }

    let dest = merged_pem_path(app)?;
    if merged.trim().is_empty() {
        let _ = std::fs::remove_file(&dest);
    } else {
        let mut file = std::fs::File::create(&dest)
            .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
        file.write_all(merged.as_bytes())
            .map_err(|e| format!("failed to write {}: {e}", dest.display()))?;
    }

    Ok(statuses)
}

#[tauri::command]
pub fn get_trust_sources(app: tauri::AppHandle) -> Result<Vec<TrustSource>, String> {
    let path = sources_path(&app)?;
    if !path.exists() {
        let defaults = default_sources();
        save_trust_sources(app.clone(), defaults.clone())?;
        return Ok(defaults);
    }
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("failed to parse trust sources: {e}"))
}

#[tauri::command]
pub fn save_trust_sources(
    app: tauri::AppHandle,
    sources: Vec<TrustSource>,
) -> Result<Vec<TrustSourceStatus>, String> {
    let path = sources_path(&app)?;
    let text =
        serde_json::to_string_pretty(&sources).map_err(|e| format!("failed to serialize: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    rebuild_merged_file(&app, &sources)
}
