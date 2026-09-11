import { Component, useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";

// Mirrors src-tauri/src/bmff.rs's BmffCoverage (see that file for the
// spec citations behind how these fields are computed).
type BmffBoxInfo = { type: string; offset: number; size: number };
type ExcludedRange = { start: number; length: number; xpath: string; boxType: string };
type BmffCoverage = {
  fileSize: number;
  topLevelBoxes: BmffBoxInfo[];
  excludedRanges: ExcludedRange[];
  warnings: string[];
};

// "excluded" = genuinely not covered by any hash (e.g. the manifest's own
// storage box, which can't hash itself). "merkle" = excluded from the flat
// top-level hash but covered separately by a per-chunk Merkle tree — see the
// merkleBoxTypes comment below. Both differ from "covered" (in the flat hash).
type SegmentStatus = "covered" | "merkle" | "excluded";
type Segment = { start: number; length: number; status: SegmentStatus; label: string };

const MAX_LABELED_SEGMENTS = 3000;

function buildSegments(
  fileSize: number,
  boxes: { offset: number; size: number; type: string }[],
  excluded: { start: number; length: number; boxType?: string }[],
  coveredLabelFor: (start: number) => string,
  merkleBoxTypes: Set<string> = new Set(),
): Segment[] {
  const points = new Set<number>([0, fileSize]);
  for (const b of boxes) {
    points.add(b.offset);
    points.add(b.offset + b.size);
  }
  for (const e of excluded) {
    points.add(Math.max(0, e.start));
    points.add(Math.min(fileSize, e.start + e.length));
  }
  const sorted = Array.from(points)
    .filter((p) => p >= 0 && p <= fileSize)
    .sort((a, b) => a - b);

  const raw: Segment[] = [];
  for (let i = 0; i < sorted.length - 1; i++) {
    const start = sorted[i];
    const end = sorted[i + 1];
    if (end <= start) continue;
    const hit = excluded.find((e) => e.start <= start && start < e.start + e.length);
    const status: SegmentStatus = !hit ? "covered" : hit.boxType && merkleBoxTypes.has(hit.boxType) ? "merkle" : "excluded";
    const label = hit?.boxType ?? coveredLabelFor(start);
    raw.push({ start, length: end - start, status, label });
  }

  if (raw.length <= MAX_LABELED_SEGMENTS) return raw;

  // Pathological case (e.g. a heavily fragmented live/DASH-style file with
  // thousands of moof/mdat pairs): fall back to merging by status only, so
  // the bar still renders and stays accurate, just less granular.
  const merged: Segment[] = [];
  for (const seg of raw) {
    const last = merged[merged.length - 1];
    if (last && last.status === seg.status) {
      last.length += seg.length;
    } else {
      merged.push({ ...seg, label: `(merged, ${seg.status})` });
    }
  }
  return merged;
}

function labelForBmff(boxes: BmffBoxInfo[]) {
  return (start: number) => boxes.find((b) => b.offset <= start && start < b.offset + b.size)?.type ?? "(gap)";
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const STATUS_META: Record<SegmentStatus, { label: string; tooltip: string }> = {
  covered: { label: "hashed directly", tooltip: "hashed / covered" },
  merkle: { label: "Merkle-tree protected", tooltip: "excluded from the flat hash, but covered by a separate per-chunk Merkle tree" },
  excluded: { label: "excluded", tooltip: "excluded from the hash entirely (e.g. the manifest's own storage box)" },
};

function CoverageBar({ fileSize, segments }: { fileSize: number; segments: Segment[] }) {
  const bytesByStatus = (status: SegmentStatus) =>
    segments.filter((s) => s.status === status).reduce((sum, s) => sum + s.length, 0);
  const excludedBytes = bytesByStatus("excluded");
  const merkleBytes = bytesByStatus("merkle");
  const coveredBytes = fileSize - excludedBytes - merkleBytes;
  const pct = (n: number) => (fileSize > 0 ? ((n / fileSize) * 100).toFixed(1) : "0");

  return (
    <div className="coverage-map-body">
      <div className="coverage-bar">
        {segments.map((s, i) => (
          <div
            key={i}
            className={`coverage-seg coverage-${s.status}`}
            style={{ flexGrow: s.length, flexBasis: 0 }}
            title={`${s.label}\n${STATUS_META[s.status].tooltip}\nbytes ${s.start.toLocaleString()}–${(s.start + s.length).toLocaleString()} (${formatBytes(s.length)})`}
          />
        ))}
      </div>
      <div className="coverage-legend">
        <span>
          <span className="coverage-swatch coverage-covered" /> hashed directly ({pct(coveredBytes)}%)
        </span>
        {merkleBytes > 0 && (
          <span>
            <span className="coverage-swatch coverage-merkle" /> Merkle-tree protected ({pct(merkleBytes)}%)
          </span>
        )}
        {excludedBytes > 0 && (
          <span>
            <span className="coverage-swatch coverage-excluded" /> excluded ({formatBytes(excludedBytes)})
          </span>
        )}
        <span className="coverage-total">{formatBytes(fileSize)} total</span>
      </div>
      {merkleBytes > 0 && (
        <p className="coverage-note">
          This asset validates its media data in chunks via a Merkle tree (common for large/streamed
          video) instead of one flat hash over that region — the highlighted part above is still
          cryptographically covered, just via a different mechanism (C2PA spec §18.6.2).
        </p>
      )}
    </div>
  );
}

function findHashAssertion(assertionStore: Record<string, unknown>) {
  for (const key of ["c2pa.hash.bmff.v3", "c2pa.hash.bmff.v2"]) {
    const value = assertionStore[key];
    if (value && typeof value === "object") return { kind: "bmff" as const, key, value: value as Record<string, unknown> };
  }
  const dataHash = assertionStore["c2pa.hash.data"];
  if (dataHash && typeof dataHash === "object") {
    return { kind: "data" as const, key: "c2pa.hash.data", value: dataHash as Record<string, unknown> };
  }
  return null;
}

function ManifestCoverage({
  manifestLabel,
  assertionStore,
  filePath,
}: {
  manifestLabel: string;
  assertionStore: Record<string, unknown>;
  filePath: string;
}) {
  const [segments, setSegments] = useState<Segment[] | null>(null);
  const [fileSize, setFileSize] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [unsupported, setUnsupported] = useState<string | null>(null);

  const found = findHashAssertion(assertionStore);

  useEffect(() => {
    let cancelled = false;
    setSegments(null);
    setFileSize(null);
    setError(null);
    setUnsupported(null);

    if (!found) {
      setUnsupported("No c2pa.hash.data or c2pa.hash.bmff assertion in this manifest — nothing to visualize.");
      return;
    }

    setLoading(true);
    (async () => {
      try {
        if (found.kind === "bmff") {
          const exclusions = Array.isArray(found.value.exclusions) ? found.value.exclusions : [];
          const result = await invoke<BmffCoverage>("compute_bmff_coverage", { path: filePath, exclusions });
          if (cancelled) return;
          // Per C2PA spec §18.6.2: when a bmff-hash-map has both `hash` and
          // `merkle`, the mandatory `/mdat` exclusion doesn't mean "unhashed"
          // — that box's content is instead covered by the Merkle tree, in
          // per-chunk pieces, for streaming/partial validation.
          const hasMerkle = Array.isArray(found.value.merkle) && found.value.merkle.length > 0;
          const merkleBoxTypes = hasMerkle ? new Set(["mdat"]) : new Set<string>();
          setFileSize(result.fileSize);
          setSegments(
            buildSegments(result.fileSize, result.topLevelBoxes, result.excludedRanges, labelForBmff(result.topLevelBoxes), merkleBoxTypes),
          );
        } else {
          const size = await invoke<number>("file_size", { path: filePath });
          if (cancelled) return;
          const exclusions = Array.isArray(found.value.exclusions)
            ? (found.value.exclusions as { start: number; length: number }[])
            : [];
          setFileSize(size);
          setSegments(buildSegments(size, [], exclusions, () => "file data"));
        }
      } catch (e) {
        if (!cancelled) setError(String(e));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [manifestLabel, filePath]);

  return (
    <div className="coverage-map">
      <div className="coverage-map-header">
        <span className="coverage-map-label">{manifestLabel}</span>
        {found && <span className="coverage-map-kind">{found.key}</span>}
      </div>
      {loading && <div className="coverage-status">Reading file structure…</div>}
      {error && <pre className="coverage-error">{error}</pre>}
      {unsupported && <div className="coverage-status">{unsupported}</div>}
      {segments && fileSize !== null && <CoverageBar fileSize={fileSize} segments={segments} />}
    </div>
  );
}

// Isolates a genuine rendering bug in one manifest's coverage card so it
// can't blank the rest of the app (validation summary, JSON tree, etc.) —
// this app has no error boundary elsewhere, so without this a render
// exception here would unmount the entire React tree.
class CoverageErrorBoundary extends Component<
  { children: ReactNode; label: string },
  { error: Error | null }
> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error) {
    console.error("CoverageMap failed to render:", error);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="coverage-map">
          <div className="coverage-map-header">
            <span className="coverage-map-label">{this.props.label}</span>
          </div>
          <pre className="coverage-error">
            Byte coverage map failed to render: {this.state.error.message || String(this.state.error)}
          </pre>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function CoverageMap({ data, filePath }: { data: unknown; filePath: string }) {
  if (typeof data !== "object" || data === null) return null;
  const manifests = (data as Record<string, unknown>)["manifests"];
  if (typeof manifests !== "object" || manifests === null) return null;

  const entries = Object.entries(manifests as Record<string, unknown>).filter(
    (entry): entry is [string, Record<string, unknown>] => typeof entry[1] === "object" && entry[1] !== null,
  );
  if (entries.length === 0) return null;

  return (
    <details className="coverage-maps app-section" open>
      <summary className="section-title">Byte Coverage Map</summary>
      <div className="coverage-maps-body">
        {entries.map(([label, manifest]) => {
          const assertionStore = manifest["assertion_store"];
          if (typeof assertionStore !== "object" || assertionStore === null) return null;
          return (
            <CoverageErrorBoundary key={label} label={label}>
              <ManifestCoverage
                manifestLabel={label}
                assertionStore={assertionStore as Record<string, unknown>}
                filePath={filePath}
              />
            </CoverageErrorBoundary>
          );
        })}
      </div>
    </details>
  );
}
