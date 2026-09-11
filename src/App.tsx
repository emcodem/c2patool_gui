import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import JsonTree, { type RevealTarget } from "./JsonTree";
import TrustSettings from "./TrustSettings";
import ValidationSummary from "./ValidationSummary";
import "./App.css";

function App() {
  const [filePath, setFilePath] = useState<string | null>(null);
  const [report, setReport] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTrustSettings, setShowTrustSettings] = useState(false);
  const [reveal, setReveal] = useState<RevealTarget | null>(null);
  const [copied, setCopied] = useState(false);

  async function copyJson() {
    if (report === null) return;
    await writeText(JSON.stringify(report, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  function navigateTo(path: string) {
    setReveal((prev) => ({ path, nonce: (prev?.nonce ?? 0) + 1 }));
  }

  async function analyze(path: string) {
    setLoading(true);
    setError(null);
    setReport(null);
    setReveal(null);
    try {
      const result = await invoke<unknown>("analyze_file", { path });
      setReport(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  async function pickFile() {
    const selected = await open({
      multiple: false,
      title: "Choose a file to inspect",
    });
    if (typeof selected === "string") {
      setFilePath(selected);
      await analyze(selected);
    }
  }

  return (
    <main className="app">
      <header className="toolbar">
        <button onClick={pickFile} disabled={loading}>
          {loading ? "Analyzing…" : "Open File…"}
        </button>
        {filePath && <span className="file-path" title={filePath}>{filePath}</span>}
        {report !== null && (
          <button onClick={copyJson}>{copied ? "Copied!" : "Copy JSON"}</button>
        )}
        <button className="trust-settings-btn" onClick={() => setShowTrustSettings(true)}>
          Trust Sources…
        </button>
      </header>

      {error && <pre className="error">{error}</pre>}

      {!error && !loading && report !== null && (
        <>
          <ValidationSummary data={report} onNavigate={navigateTo} />
          <JsonTree data={report} reveal={reveal} />
        </>
      )}

      {!filePath && !loading && !error && (
        <p className="hint">Open a file to run c2patool's detailed C2PA analysis.</p>
      )}

      {showTrustSettings && <TrustSettings onClose={() => setShowTrustSettings(false)} />}
    </main>
  );
}

export default App;
