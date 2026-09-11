import { useMemo, useState } from "react";

type NodeProps = {
  keyLabel: string | null;
  value: unknown;
  depth: number;
  path: string;
  filter: string;
  forceOpen: boolean;
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

function TreeNode({ keyLabel, value, depth, path, filter, forceOpen }: NodeProps) {
  const isContainer = value !== null && typeof value === "object";
  const isArray = Array.isArray(value);
  const selfMatches =
    (keyLabel !== null && matches(keyLabel, filter)) || (!isContainer && valueMatches(value, filter));
  const childMatches = isContainer && subtreeMatches(value, filter);
  const shouldShow = filter.length === 0 || selfMatches || childMatches;

  const [manualOpen, setManualOpen] = useState<boolean | null>(null);
  const open = manualOpen !== null ? manualOpen : forceOpen || childMatches || depth < 1;

  if (!shouldShow) return null;

  if (!isContainer) {
    return (
      <div className="tree-row" style={{ paddingLeft: depth * 16 }}>
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

  return (
    <div className="tree-node">
      <div
        className="tree-row tree-row-container"
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

export default function JsonTree({ data }: { data: unknown }) {
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
        />
      </div>
    </div>
  );
}
