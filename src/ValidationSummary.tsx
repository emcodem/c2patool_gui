import { lookupStatusCode, type StatusCategory } from "./validationCodes";
import { findPathForValidationUrl } from "./findInTree";

type ResultEntry = {
  code: string;
  url?: string;
  explanation?: string;
};

type ManifestResults = Partial<Record<StatusCategory, ResultEntry[]>>;

const CATEGORY_META: Record<StatusCategory, { label: string; className: string }> = {
  failure: { label: "Failure", className: "vs-failure" },
  informational: { label: "Informational", className: "vs-informational" },
  success: { label: "Success", className: "vs-success" },
};

function Entry({
  entry,
  category,
  data,
  onNavigate,
}: {
  entry: ResultEntry;
  category: StatusCategory;
  data: unknown;
  onNavigate?: (path: string) => void;
}) {
  const spec = lookupStatusCode(entry.code);
  const canNavigate = !!(onNavigate && entry.url);

  return (
    <li
      className={`vs-entry ${CATEGORY_META[category].className} ${canNavigate ? "vs-clickable" : ""}`}
      onClick={() => {
        if (!canNavigate) return;
        const path = findPathForValidationUrl(data, entry.url!);
        if (path) onNavigate!(path);
      }}
      title={canNavigate ? "Click to locate in the JSON tree" : undefined}
    >
      <div className="vs-entry-head">
        <code className="vs-code">{entry.code}</code>
      </div>
      {entry.explanation && <div className="vs-explanation">{entry.explanation}</div>}
      {spec && <div className="vs-meaning">{spec.meaning}</div>}
    </li>
  );
}

export default function ValidationSummary({
  data,
  onNavigate,
}: {
  data: unknown;
  onNavigate?: (path: string) => void;
}) {
  if (typeof data !== "object" || data === null) return null;
  const validationResults = (data as Record<string, unknown>)["validation_results"];
  if (typeof validationResults !== "object" || validationResults === null) return null;

  const manifestEntries = Object.entries(validationResults as Record<string, ManifestResults>);
  if (manifestEntries.length === 0) return null;

  return (
    <div className="validation-summary">
      <p className="vs-note">
        Note: <code>validation_state</code> only reflects structural/cryptographic integrity (hashes
        and signature are internally consistent). It does <strong>not</strong> mean the signer is
        trusted — that's judged separately below, against whatever trust anchors are configured.
      </p>
      {manifestEntries.map(([manifestLabel, results]) => {
        const failures = results.failure ?? [];
        const informational = results.informational ?? [];
        const successes = results.success ?? [];
        const noteworthy = [...failures, ...informational];

        return (
          <div key={manifestLabel} className="vs-manifest">
            <div className="vs-manifest-head">
              <span className="vs-manifest-label">{manifestLabel}</span>
              <span className="vs-counts">
                {failures.length > 0 && <span className="vs-count vs-failure">{failures.length} failure</span>}
                {informational.length > 0 && (
                  <span className="vs-count vs-informational">{informational.length} informational</span>
                )}
                <span className="vs-count vs-success">{successes.length} success</span>
              </span>
            </div>
            {noteworthy.length > 0 ? (
              <ul className="vs-list">
                {failures.map((e, i) => (
                  <Entry key={`f${i}`} entry={e} category="failure" data={data} onNavigate={onNavigate} />
                ))}
                {informational.map((e, i) => (
                  <Entry key={`i${i}`} entry={e} category="informational" data={data} onNavigate={onNavigate} />
                ))}
              </ul>
            ) : (
              <div className="vs-clean">No failures or informational issues.</div>
            )}
          </div>
        );
      })}
    </div>
  );
}
