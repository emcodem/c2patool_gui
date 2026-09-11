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

type TrustStatus = "trusted" | "untrusted" | "unknown";

// Per spec (see validationCodes.ts): "signingCredential.trusted" is a success
// code, "signingCredential.untrusted" a failure code. Neither is guaranteed
// to be present (e.g. trust checking wasn't performed), hence "unknown".
function trustStatus(results: ManifestResults): TrustStatus {
  if ((results.success ?? []).some((e) => e.code === "signingCredential.trusted")) return "trusted";
  if ((results.failure ?? []).some((e) => e.code === "signingCredential.untrusted")) return "untrusted";
  return "unknown";
}

const TRUST_META: Record<TrustStatus, { label: string; className: string }> = {
  trusted: { label: "Trusted signer", className: "vs-success" },
  untrusted: { label: "Untrusted signer", className: "vs-failure" },
  unknown: { label: "Trust unknown", className: "vs-informational" },
};

// "activeManifest" is c2patool's fixed key for the primary manifest's
// validation results; other validation_results keys (e.g. ingredient
// deltas) aren't guaranteed to match a `manifests` key, so we only resolve
// signer info when we can do so without guessing.
function resolveManifestKey(data: Record<string, unknown>, resultsKey: string): string | null {
  if (resultsKey === "activeManifest") {
    const active = data["active_manifest"];
    return typeof active === "string" ? active : null;
  }
  const manifests = data["manifests"];
  if (typeof manifests === "object" && manifests !== null && resultsKey in manifests) return resultsKey;
  return null;
}

function getSigner(data: Record<string, unknown>, manifestKey: string | null): { commonName: string; issuer?: string } | null {
  if (!manifestKey) return null;
  const manifests = data["manifests"];
  if (typeof manifests !== "object" || manifests === null) return null;
  const manifest = (manifests as Record<string, unknown>)[manifestKey];
  if (typeof manifest !== "object" || manifest === null) return null;
  const signature = (manifest as Record<string, unknown>)["signature"];
  if (typeof signature !== "object" || signature === null) return null;
  const commonName = (signature as Record<string, unknown>)["common_name"];
  const issuer = (signature as Record<string, unknown>)["issuer"];
  if (typeof commonName !== "string") return null;
  return { commonName, issuer: typeof issuer === "string" ? issuer : undefined };
}

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
  const record = data as Record<string, unknown>;
  const validationResults = record["validation_results"];
  if (typeof validationResults !== "object" || validationResults === null) return null;

  const manifestEntries = Object.entries(validationResults as Record<string, ManifestResults>);
  if (manifestEntries.length === 0) return null;

  const validationState = record["validation_state"];

  return (
    <details className="validation-summary app-section" open>
      <summary className="section-title">
        Validation Summary
        {typeof validationState === "string" && (
          <span
            className={`vs-state-badge ${validationState === "Valid" ? "vs-success" : "vs-failure"}`}
          >
            validation_state: {validationState}
          </span>
        )}
      </summary>
      <div className="validation-summary-body">
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
        const manifestKey = resolveManifestKey(record, manifestLabel);
        const signer = getSigner(record, manifestKey);
        const trust = trustStatus(results);

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
            <div className="vs-signer-row">
              {signer && (
                <span className="vs-signer" title={signer.issuer ? `Issued by: ${signer.issuer}` : undefined}>
                  Signer: {signer.commonName}
                </span>
              )}
              <span className={`vs-count ${TRUST_META[trust].className}`}>{TRUST_META[trust].label}</span>
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
    </details>
  );
}
