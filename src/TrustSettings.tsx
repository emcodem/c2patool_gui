import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

type TrustSource = {
  id: string;
  label: string;
  source: string;
  enabled: boolean;
};

type TrustSourceStatus = {
  id: string;
  ok: boolean;
  error: string | null;
};

function newId() {
  return crypto.randomUUID();
}

export default function TrustSettings({ onClose }: { onClose: () => void }) {
  const [sources, setSources] = useState<TrustSource[]>([]);
  const [statuses, setStatuses] = useState<Record<string, TrustSourceStatus>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newLabel, setNewLabel] = useState("");
  const [newSource, setNewSource] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<TrustSource[]>("get_trust_sources")
      .then(setSources)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  async function persist(next: TrustSource[]) {
    setSources(next);
    setSaving(true);
    setError(null);
    try {
      const results = await invoke<TrustSourceStatus[]>("save_trust_sources", { sources: next });
      const map: Record<string, TrustSourceStatus> = {};
      for (const r of results) map[r.id] = r;
      setStatuses(map);
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  }

  function toggle(id: string) {
    persist(sources.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s)));
  }

  function remove(id: string) {
    persist(sources.filter((s) => s.id !== id));
  }

  function add() {
    if (!newLabel.trim() || !newSource.trim()) return;
    persist([...sources, { id: newId(), label: newLabel.trim(), source: newSource.trim(), enabled: true }]);
    setNewLabel("");
    setNewSource("");
  }

  return (
    <div className="trust-overlay" onClick={onClose}>
      <div className="trust-panel" onClick={(e) => e.stopPropagation()}>
        <div className="trust-panel-header">
          <h2>Trust Sources</h2>
          <button className="trust-close" onClick={onClose}>
            ✕
          </button>
        </div>
        <p className="trust-hint">
          PEM files (local path or URL) used as trust anchors when validating manifests. Enabled
          sources are merged and passed to c2patool as <code>trust --trust_anchors</code>.
        </p>

        {loading && <p>Loading…</p>}
        {error && <pre className="error">{error}</pre>}

        {!loading && (
          <ul className="trust-list">
            {sources.map((s) => {
              const status = statuses[s.id];
              return (
                <li key={s.id} className="trust-item">
                  <input
                    type="checkbox"
                    checked={s.enabled}
                    onChange={() => toggle(s.id)}
                    disabled={saving}
                  />
                  <div className="trust-item-body">
                    <div className="trust-item-label">{s.label}</div>
                    <div className="trust-item-source" title={s.source}>
                      {s.source}
                    </div>
                    {status && !status.ok && (
                      <div className="trust-item-error">Fetch failed: {status.error}</div>
                    )}
                  </div>
                  <button className="trust-remove" onClick={() => remove(s.id)} disabled={saving}>
                    Remove
                  </button>
                </li>
              );
            })}
            {sources.length === 0 && <li className="trust-empty">No trust sources configured.</li>}
          </ul>
        )}

        <div className="trust-add">
          <input
            type="text"
            placeholder="Label"
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
          />
          <input
            type="text"
            placeholder="URL or file path to PEM"
            value={newSource}
            onChange={(e) => setNewSource(e.target.value)}
          />
          <button onClick={add} disabled={saving || !newLabel.trim() || !newSource.trim()}>
            Add
          </button>
        </div>
      </div>
    </div>
  );
}
