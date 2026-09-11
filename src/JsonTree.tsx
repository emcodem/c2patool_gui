import { useEffect, useMemo, useRef, useState } from "react";

type NodeProps = {
  keyLabel: string | null;
  value: unknown;
  depth: number;
  path: string;
  filter: string;
  forceOpen: boolean;
  revealPath: string | null;
  revealNonce: number;
};

function matches(text: string, filter: string) {
  return filter.length > 0 && text.toLowerCase().includes(filter);
}

function valueMatches(value: unknown, filter: string): boolean {
  if (filter.length === 0) return false;
  if (value === null) return matches("null", filter);
  if (typeof value === "object") return false;
  return matches(String(value), filter);
}

function subtreeMatches(value: unknown, filter: string): boolean {
  if (filter.length === 0) return false;
  if (value !== null && typeof value === "object") {
    const entries = Array.isArray(value) ? value.entries() : Object.entries(value as object);
    for (const [k, v] of entries as Iterable<[string | number, unknown]>) {
      if (matches(String(k), filter)) return true;
      if (subtreeMatches(v, filter)) return true;
    }
    return false;
  }
  return valueMatches(value, filter);
}

function ValueLabel({ value }: { value: unknown }) {
  if (value === null) return <span className="v-null">null</span>;
  if (typeof value === "string") return <span className="v-string">"{value}"</span>;
  if (typeof value === "number") return <span className="v-number">{value}</span>;
  if (typeof value === "boolean") return <span className="v-boolean">{String(value)}</span>;
  return <span className="v-unknown">{JSON.stringify(value)}</span>;
}

function TreeNode({ keyLabel, value, depth, path, filter, forceOpen, revealPath, revealNonce }: NodeProps) {
  const isContainer = value !== null && typeof value === "object";
  const isArray = Array.isArray(value);
  const selfMatches =
    (keyLabel !== null && matches(keyLabel, filter)) || (!isContainer && valueMatches(value, filter));
  const childMatches = isContainer && subtreeMatches(value, filter);
  const shouldShow = filter.length === 0 || selfMatches || childMatches;

  const isTarget = revealPath !== null && path === revealPath;
  const isRevealAncestor = revealPath !== null && (path === revealPath || revealPath.startsWith(`${path}.`));

  const [manualOpen, setManualOpen] = useState<boolean | null>(null);
  const rowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isRevealAncestor) setManualOpen(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealNonce]);

  useEffect(() => {
    if (isTarget) {
      rowRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealNonce]);

  const open = manualOpen !== null ? manualOpen : forceOpen || childMatches || depth < 1;

  if (!shouldShow) return null;

  const rowClass = (base: string) => (isTarget ? `${base} tree-highlight` : base);

  if (!isContainer) {
    return (
      <div ref={rowRef} className={rowClass("tree-row")} style={{ paddingLeft: depth * 16 }}>
        <span className="tree-toggle-spacer" />
        {keyLabel !== null && <span className="tree-key">{keyLabel}: </span>}
        <ValueLabel value={value} />
      </div>
    );
  }

  const entries: [string, unknown][] = isArray
    ? (value as unknown[]).map((v, i) => [String(i), v])
    : Object.entries(value as Record<string, unknown>);

  const isEmpty = entries.length === 0;
  const bracket = isArray ? ["[", "]"] : ["{", "}"];

  const signature = !isArray ? (value as Record<string, unknown>).signature : null;
  const signerName =
    signature !== null && typeof signature === "object"
      ? (signature as Record<string, unknown>).common_name
      : null;
  const signerIssuer =
    signature !== null && typeof signature === "object"
      ? (signature as Record<string, unknown>).issuer
      : null;

  return (
    <div className="tree-node">
      <div
        ref={rowRef}
        className={rowClass("tree-row tree-row-container")}
        style={{ paddingLeft: depth * 16 }}
        onClick={() => !isEmpty && setManualOpen(!open)}
      >
        {!isEmpty ? (
          <span className="tree-toggle">{open ? "▾" : "▸"}</span>
        ) : (
          <span className="tree-toggle-spacer" />
        )}
        {keyLabel !== null && <span className="tree-key">{keyLabel}: </span>}
        <span className="tree-bracket">
          {bracket[0]}
          {!open && !isEmpty && <span className="tree-summary"> {entries.length} items </span>}
          {isEmpty && bracket[1]}
        </span>
        {typeof signerName === "string" && (
          <span
            className="tree-signer"
            title={typeof signerIssuer === "string" ? `Issued by: ${signerIssuer}` : undefined}
          >
            signed by: {signerName}
          </span>
        )}
      </div>
      {open && !isEmpty && (
        <div className="tree-children">
          {entries.map(([k, v]) => (
            <TreeNode
              key={k}
              keyLabel={k}
              value={v}
              depth={depth + 1}
              path={`${path}.${k}`}
              filter={filter}
              forceOpen={forceOpen}
              revealPath={revealPath}
              revealNonce={revealNonce}
            />
          ))}
          <div className="tree-row tree-row-close" style={{ paddingLeft: depth * 16 }}>
            <span className="tree-toggle-spacer" />
            <span className="tree-bracket">{bracket[1]}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export type RevealTarget = { path: string; nonce: number };

export default function JsonTree({ data, reveal }: { data: unknown; reveal?: RevealTarget | null }) {
  const [filterInput, setFilterInput] = useState("");
  const filter = useMemo(() => filterInput.trim().toLowerCase(), [filterInput]);

  return (
    <div className="json-tree-wrap">
      <div className="json-table-toolbar">
        <input
          type="text"
          placeholder="Filter by field or value…"
          value={filterInput}
          onChange={(e) => setFilterInput(e.target.value)}
        />
      </div>
      <div className="json-tree-scroll">
        <TreeNode
          keyLabel={null}
          value={data}
          depth={0}
          path=""
          filter={filter}
          forceOpen={filter.length > 0}
          revealPath={reveal?.path ?? null}
          revealNonce={reveal?.nonce ?? 0}
        />
      </div>
    </div>
  );
}
