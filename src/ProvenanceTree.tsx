import { cawgSigner } from "./cawgIdentity";
import { asRecord, manifestInfo, manifestPath, type Navigate } from "./manifestInfo";

// Builds the ingredient graph starting at the active manifest: each manifest's
// c2pa.ingredient* assertions point (by JUMBF url) at the manifest of the
// asset that went into it, so following them walks the asset's history back
// to its original captures/generations.

type TrustStatus = "trusted" | "untrusted" | "unknown";

type ActionInfo = { action: string; digitalSourceType: string | null; description: string | null };

type TreeNode = {
  // Label under data.manifests, or null for an ingredient without a C2PA manifest.
  manifestLabel: string | null;
  relationship: string | null;
  // Actions in the *parent* manifest that reference this ingredient (e.g. "placed").
  usedVia: string[];
  ingredientTitle: string | null;
  ingredientFormat: string | null;
  cycle: boolean;
  children: TreeNode[];
};

const URN_RE = /urn:c2pa:[0-9a-fA-F-]+(?::[^/]*)?/;

// Ingredient v3 uses activeManifest; v1/v2 use c2pa_manifest.
function ingredientManifestUrn(ingredient: Record<string, unknown>): string | null {
  const ref = asRecord(ingredient["activeManifest"]) ?? asRecord(ingredient["c2pa_manifest"]);
  const url = typeof ref?.url === "string" ? ref.url : null;
  return url?.match(URN_RE)?.[0] ?? null;
}

function actionsOf(manifest: Record<string, unknown>): { action: ActionInfo; ingredientKeys: string[] }[] {
  const store = asRecord(manifest["assertion_store"]) ?? {};
  const result: { action: ActionInfo; ingredientKeys: string[] }[] = [];
  for (const [key, value] of Object.entries(store)) {
    if (!key.startsWith("c2pa.actions")) continue;
    const actions = asRecord(value)?.["actions"];
    if (!Array.isArray(actions)) continue;
    for (const raw of actions) {
      const a = asRecord(raw);
      if (!a || typeof a.action !== "string") continue;
      const params = asRecord(a.parameters);
      const refs = [
        ...(Array.isArray(params?.ingredients) ? params.ingredients : []),
        ...(params?.ingredient ? [params.ingredient] : []),
      ];
      const ingredientKeys = refs
        .map((r) => asRecord(r)?.url)
        .filter((u): u is string => typeof u === "string")
        .map((u) => u.split("/").pop() ?? u);
      result.push({
        action: {
          action: a.action,
          digitalSourceType: typeof a.digitalSourceType === "string" ? a.digitalSourceType : null,
          description: typeof a.description === "string" ? a.description : null,
        },
        ingredientKeys,
      });
    }
  }
  return result;
}

const shortAction = (action: string) => action.replace(/^c2pa\./, "");
const shortSourceType = (uri: string) => uri.split("/").pop() ?? uri;
const isAiSourceType = (uri: string | null) => !!uri && /trainedAlgorithmicMedia/i.test(uri);

function buildNode(
  manifests: Record<string, unknown>,
  manifestLabel: string,
  base: Omit<TreeNode, "manifestLabel" | "children" | "cycle">,
  ancestors: Set<string>,
): TreeNode {
  if (ancestors.has(manifestLabel)) return { ...base, manifestLabel, cycle: true, children: [] };
  const manifest = asRecord(manifests[manifestLabel]);
  if (!manifest) return { ...base, manifestLabel, cycle: false, children: [] };

  const store = asRecord(manifest["assertion_store"]) ?? {};
  const actions = actionsOf(manifest);
  const nextAncestors = new Set(ancestors).add(manifestLabel);
  const children: TreeNode[] = [];

  for (const [key, value] of Object.entries(store)) {
    if (!key.startsWith("c2pa.ingredient")) continue;
    const ingredient = asRecord(value);
    if (!ingredient) continue;
    const childBase = {
      relationship: typeof ingredient.relationship === "string" ? ingredient.relationship : null,
      usedVia: actions
        .filter((a) => a.ingredientKeys.includes(key) && a.action.action !== "c2pa.created")
        .map((a) => shortAction(a.action.action)),
      ingredientTitle: typeof ingredient["dc:title"] === "string" ? (ingredient["dc:title"] as string) : null,
      ingredientFormat: typeof ingredient["dc:format"] === "string" ? (ingredient["dc:format"] as string) : null,
    };
    const urn = ingredientManifestUrn(ingredient);
    children.push(
      urn && urn in manifests
        ? buildNode(manifests, urn, childBase, nextAncestors)
        : { ...childBase, manifestLabel: null, cycle: false, children: [] },
    );
  }

  return { ...base, manifestLabel, cycle: false, children };
}

const CAWG_URL_RE = /\/(cawg\.identity(?:__\d+)?)$/;
const TRUSTED_CODES = ["signingCredential.trusted", "cawg.x509.credential.trusted"];
const UNTRUSTED_CODES = ["signingCredential.untrusted", "cawg.x509.credential.untrusted"];

// Trust key for a manifest's claim signature, and for one of its CAWG
// identity assertions: the two are separate signatures with separate trust
// anchors, but c2patool reports both with signingCredential.* codes, so
// they're told apart by the url.
const claimKey = (urn: string) => urn;
const cawgKey = (urn: string, assertionLabel: string) => `${urn}/${assertionLabel}`;

// Trust codes found anywhere under `value`, keyed as above. "trusted" wins
// over "untrusted" for the same key, matching how ValidationSummary judges
// the active manifest.
function collectTrust(value: unknown, into: Map<string, TrustStatus>) {
  if (Array.isArray(value)) return value.forEach((v) => collectTrust(v, into));
  const record = asRecord(value);
  if (!record) return;
  if (typeof record.code === "string" && typeof record.url === "string") {
    const urn = record.url.match(URN_RE)?.[0];
    if (urn) {
      const cawg = record.url.match(CAWG_URL_RE)?.[1];
      const key = cawg ? cawgKey(urn, cawg) : claimKey(urn);
      if (TRUSTED_CODES.includes(record.code)) into.set(key, "trusted");
      else if (UNTRUSTED_CODES.includes(record.code) && into.get(key) !== "trusted") into.set(key, "untrusted");
    }
    return;
  }
  Object.values(record).forEach((v) => collectTrust(v, into));
}

type TrustVerdict = {
  status: TrustStatus;
  // Set when the verdict wasn't produced by this run but by the manifest that
  // imported the ingredient, which stored its validation result alongside it.
  checkedBy?: { signer: string | null; time: string | null };
};

// c2patool fully trust-checks only the active manifest. For ingredients it
// reports ingredientDeltas: only where its own result *differs* from the
// validation results the importing manifest stored in its ingredient
// assertion (C2PA spec, "Validation of ingredients"). No delta means "same as
// stored", so the importer's verdict is the best available answer then.
function trustByManifest(data: Record<string, unknown>, manifests: Record<string, unknown>): Map<string, TrustVerdict> {
  const current = new Map<string, TrustStatus>();
  collectTrust(data["validation_results"], current);

  const fromImporters = new Map<string, Required<TrustVerdict>>();
  for (const value of Object.values(manifests)) {
    const manifest = asRecord(value);
    if (!manifest) continue;
    const { signer, time } = manifestInfo(manifest);
    const store = asRecord(manifest["assertion_store"]) ?? {};
    for (const [key, assertion] of Object.entries(store)) {
      if (!key.startsWith("c2pa.ingredient")) continue;
      const ingredient = asRecord(assertion);
      const found = new Map<string, TrustStatus>();
      // v3 ingredients carry validationResults; v1/v2 a flat validation_status list.
      collectTrust(ingredient?.["validationResults"] ?? ingredient?.["validation_status"], found);
      for (const [urn, status] of found) {
        const existing = fromImporters.get(urn);
        // Several manifests may have imported the same ingredient; prefer the latest check.
        if (!existing || (time ?? "") > (existing.checkedBy.time ?? "")) {
          fromImporters.set(urn, { status, checkedBy: { signer, time } });
        }
      }
    }
  }

  const result = new Map<string, TrustVerdict>(fromImporters);
  for (const [urn, status] of current) result.set(urn, { status });
  return result;
}

const TRUST_META: Record<TrustStatus, { label: string; className: string }> = {
  trusted: { label: "trusted", className: "vs-success" },
  untrusted: { label: "untrusted", className: "vs-failure" },
  unknown: { label: "trust unknown", className: "vs-informational" },
};

function TrustBadge({ verdict, cawg = false }: { verdict: TrustVerdict | undefined; cawg?: boolean }) {
  const anchors = cawg ? "configured CAWG identity trust anchors" : "configured trust anchors";
  if (!verdict) {
    return (
      <span
        className="vs-count vs-informational"
        title="Neither this run nor any manifest that imported this ingredient reported a trust verdict for its signing certificate."
      >
        {TRUST_META.unknown.label}
      </span>
    );
  }
  const meta = TRUST_META[verdict.status];
  if (!verdict.checkedBy) {
    return (
      <span className={`vs-count ${meta.className}`} title={`Checked in this run against the ${anchors}.`}>
        {meta.label}
      </span>
    );
  }
  const by = verdict.checkedBy.signer ?? "an unknown signer";
  const at = formatTime(verdict.checkedBy.time);
  return (
    <span
      className={`vs-count ${meta.className} pt-checked-by`}
      title={
        `Checked by ${by} when it imported this ingredient${at ? ` (signed ${at})` : ""}, against ${by}'s trust list at that time — not yours.\n` +
        "This run didn't report a different result: c2patool only reports ingredient trust where it differs from the importer's check."
      }
    >
      {meta.label} (checked by {by})
    </span>
  );
}

function formatTime(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
}

function NodeView({
  node,
  manifests,
  trust,
  isRoot,
  onNavigate,
}: {
  node: TreeNode;
  manifests: Record<string, unknown>;
  trust: Map<string, TrustVerdict>;
  isRoot: boolean;
  onNavigate?: Navigate;
}) {
  const manifest = node.manifestLabel ? asRecord(manifests[node.manifestLabel]) : null;
  const info = manifest ? manifestInfo(manifest) : null;
  const actions = manifest ? actionsOf(manifest).map((a) => a.action) : [];
  const ai = actions.some((a) => isAiSourceType(a.digitalSourceType));

  const edge = [node.relationship, ...node.usedVia].filter(Boolean).join(" · ");

  const label = info?.signer ?? (node.manifestLabel ? "(unknown signer)" : "(no C2PA manifest)");
  const store = asRecord(manifest?.["assertion_store"]) ?? {};
  const identities = Object.entries(store)
    .filter(([key]) => CAWG_URL_RE.test(`/${key}`))
    .map(([key, value]) => ({ key, signer: cawgSigner(asRecord(value) ?? {}) }));

  return (
    <li className="pt-node">
      <div className="pt-card">
        <div className="pt-head">
          {edge && <span className="pt-edge">{edge}</span>}
          {isRoot && <span className="vs-count vs-success">this file</span>}
          {node.manifestLabel && onNavigate ? (
            <button
              type="button"
              className="pt-signer coverage-link"
              title={info?.issuer ? `Issued by: ${info.issuer}\nShow in the JSON tree` : "Show in the JSON tree"}
              onClick={() => onNavigate(manifestPath(node.manifestLabel!))}
            >
              {label}
            </button>
          ) : (
            <span className="pt-signer">{label}</span>
          )}
          {node.manifestLabel && <TrustBadge verdict={trust.get(claimKey(node.manifestLabel))} />}
          {ai && <span className="vs-count pt-ai">AI</span>}
          {node.cycle && <span className="vs-count vs-failure">cycle — already shown above</span>}
        </div>
        <div className="coverage-map-meta">
          {info?.product && <span>Product: {info.product}</span>}
          {(info?.title ?? node.ingredientTitle) && <span>Title: {info?.title ?? node.ingredientTitle}</span>}
          {!manifest && node.ingredientFormat && <span>Format: {node.ingredientFormat}</span>}
          {info?.issuer && <span>Org: {info.issuer}</span>}
          {formatTime(info?.time ?? null) && <span>Signed: {formatTime(info?.time ?? null)}</span>}
        </div>
        {node.manifestLabel &&
          identities.map(({ key, signer }) => (
            <div key={key} className="pt-identity">
              {onNavigate ? (
                <button
                  type="button"
                  className="pt-identity-label coverage-link"
                  title="Separate signature by a named organization or person, judged against CAWG identity trust anchors (not the C2PA trust list). Show in the JSON tree"
                  onClick={() => onNavigate(`${manifestPath(node.manifestLabel!)}.assertion_store.${key}`)}
                >
                  CAWG identity
                </button>
              ) : (
                <span className="pt-identity-label">CAWG identity</span>
              )}
              <span className="pt-identity-name">
                {signer?.organization ?? signer?.commonName ?? "(signer not readable)"}
              </span>
              <TrustBadge verdict={trust.get(cawgKey(node.manifestLabel!, key))} cawg />
            </div>
          ))}
        {actions.length > 0 && (
          <ul className="pt-actions">
            {actions.map((a, i) => (
              <li key={i}>
                <code>{shortAction(a.action)}</code>
                {a.digitalSourceType && (
                  <span className={isAiSourceType(a.digitalSourceType) ? "pt-ai-text" : undefined}>
                    {" "}
                    ({shortSourceType(a.digitalSourceType)})
                  </span>
                )}
                {a.description && <span className="pt-desc"> — {a.description}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>
      {node.children.length > 0 && (
        <ul className="pt-children">
          {node.children.map((child, i) => (
            <NodeView key={i} node={child} manifests={manifests} trust={trust} isRoot={false} onNavigate={onNavigate} />
          ))}
        </ul>
      )}
    </li>
  );
}

export default function ProvenanceTree({ data, onNavigate }: { data: unknown; onNavigate?: Navigate }) {
  const record = asRecord(data);
  const manifests = asRecord(record?.["manifests"]);
  const active = record?.["active_manifest"];
  if (!record || !manifests || typeof active !== "string" || !(active in manifests)) return null;

  const root = buildNode(
    manifests,
    active,
    { relationship: null, usedVia: [], ingredientTitle: null, ingredientFormat: null },
    new Set(),
  );
  const trust = trustByManifest(record, manifests);

  return (
    <details className="provenance-tree app-section" open>
      <summary className="section-title">Provenance Tree</summary>
      <p className="vs-note">
        Newest step on top; each indented entry is an ingredient that went into the entry above it. Labels on the
        left of a name show how it was used (relationship · actions).
      </p>
      <ul className="pt-root">
        <NodeView node={root} manifests={manifests} trust={trust} isRoot onNavigate={onNavigate} />
      </ul>
    </details>
  );
}
