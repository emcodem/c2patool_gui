import { createContext, useContext, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
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
  // Assertion label of this ingredient in the parent's assertion store
  // (e.g. "c2pa.ingredient.v3__1"); actions reference ingredients by it.
  ingredientKey: string | null;
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
      ingredientKey: key,
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

type StoredVerdict = { status: TrustStatus; manifestLabel: string; signer: string | null; time: string | null };

type TrustVerdict = {
  // Always the verdict of *this* run, i.e. of the user's Trust Sources.
  status: TrustStatus;
  // Whether c2patool reported it explicitly. If not, it was inferred from
  // `stored`: c2patool re-checks ingredient certificates but only reports
  // where its result differs from the stored one.
  reported: boolean;
  // What the manifest that imported this ingredient stored at the time, with
  // its own trust list.
  stored?: StoredVerdict;
};

// c2patool re-checks every ingredient certificate against the configured
// trust anchors but reports ingredientDeltas only where its result *differs*
// from the validation results the importing manifest stored in its ingredient
// assertion (C2PA spec, "Validation of ingredients"). So no delta means this
// run agrees with the stored result.
function trustByManifest(data: Record<string, unknown>, manifests: Record<string, unknown>): Map<string, TrustVerdict> {
  const current = new Map<string, TrustStatus>();
  collectTrust(data["validation_results"], current);

  const fromImporters = new Map<string, StoredVerdict>();
  // A manifest stores results for the ingredient it imported *and* for that
  // ingredient's own ingredients (ingredientDeltas), so the checker isn't
  // necessarily the direct parent.
  for (const [manifestLabel, value] of Object.entries(manifests)) {
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
        if (!existing || (time ?? "") > (existing.time ?? "")) {
          fromImporters.set(urn, { status, manifestLabel, signer, time });
        }
      }
    }
  }

  const result = new Map<string, TrustVerdict>();
  for (const [key, stored] of fromImporters) result.set(key, { status: stored.status, reported: false, stored });
  for (const [key, status] of current) result.set(key, { status, reported: true, stored: fromImporters.get(key) });
  return result;
}

const TRUST_META: Record<TrustStatus, { label: string; className: string }> = {
  trusted: { label: "cert trusted", className: "vs-success" },
  untrusted: { label: "cert untrusted", className: "vs-failure" },
  unknown: { label: "cert trust unknown", className: "vs-informational" },
};

// What a stored ingredient verdict covers. The importer only had the
// ingredient's manifest (embedded in the file it received), not the
// ingredient's original media, so it judged the signing certificate.
const STORED_VERDICT_SCOPE =
  "Both results are about the signing certificate of this step's manifest. " +
  "Neither your check nor the importer's had the original media of this step, only the manifest embedded in the file.";

// Ingredient relationships defined by the C2PA spec.
const RELATIONSHIP_HINTS: Record<string, string> = {
  parentOf: "parentOf: the asset this step started from and edited (at most one per step)",
  componentOf: "componentOf: a part that was placed into this step's asset, e.g. a clip in a composition",
  inputTo: "inputTo: used as input without becoming part of the asset, e.g. a prompt or reference image for an AI model",
};

// Plain-language names for the assertions a CAWG identity can reference.
// A hard-binding hash (c2pa.hash.data/.bmff/.boxes) covers the whole file:
// every track (video, audio, subtitles, ...) and its metadata, minus the
// ranges/boxes listed in its own `exclusions`.
function friendlyAssertion(label: string): string {
  if (label.startsWith("c2pa.hash.")) return "content hash";
  if (label.startsWith("c2pa.actions")) return "actions";
  if (label.startsWith("c2pa.ingredient")) return "ingredient link";
  if (label.startsWith("c2pa.thumbnail")) return "thumbnail";
  if (label.startsWith("c2pa.metadata") || label.startsWith("stds.")) return "metadata";
  return label;
}

function assertionHint(label: string): string {
  return label.startsWith("c2pa.hash.")
    ? "\nHash over the whole file: all tracks (video, audio, subtitles, …) and their metadata," +
        "\nexcept the boxes listed in its exclusions (see the Byte Coverage Map)."
    : "";
}

// The assertions the identity's signer_payload lists (by JUMBF url). Only
// these are signed by the named actor; everything else in the manifest is
// covered by the claim signature alone.
function referencedAssertions(identity: Record<string, unknown>): string[] {
  const refs = asRecord(identity["signer_payload"])?.["referenced_assertions"];
  if (!Array.isArray(refs)) return [];
  return refs
    .map((r) => asRecord(r)?.url)
    .filter((u): u is string => typeof u === "string")
    .map((u) => u.split("/").pop() ?? u);
}

// Labels of the enabled Trust Sources (null until loaded), for the tooltip of
// verdicts made in this run.
const ActiveTrustSources = createContext<string[] | null>(null);

function TrustBadge({
  verdict,
  parent,
  cawg = false,
}: {
  verdict: TrustVerdict | undefined;
  // The step that directly imported this one, to tell whether it or a later step did the check.
  parent?: { manifestLabel: string | null; name: string | null };
  cawg?: boolean;
}) {
  const activeSources = useContext(ActiveTrustSources);
  const anchors = cawg ? "configured CAWG identity trust anchors" : "configured trust anchors";
  if (!verdict) {
    return (
      <span
        className="vs-count vs-informational"
        title="Neither this run nor any manifest that imported this ingredient reported a trust result for its signing certificate."
      >
        {TRUST_META.unknown.label}
      </span>
    );
  }
  const meta = TRUST_META[verdict.status];
  const lines: string[] = [];

  const sources =
    activeSources === null
      ? ""
      : activeSources.length > 0
        ? ` Active Trust Sources: ${activeSources.join(", ")}.`
        : " No Trust Sources are enabled.";
  lines.push(`Rated in this run by this app (c2patool) against the ${anchors}.${sources}`);
  // The Trust Sources panel only feeds the C2PA trust list; CAWG identities
  // have separate anchors that this app doesn't configure yet.
  if (cawg) {
    lines.push(
      "The Trust Sources only cover C2PA claim certificates; no CAWG identity trust anchors are configured, so identity certificates aren't trusted.",
    );
  }

  const stored = verdict.stored;
  const by = stored ? (stored.signer ?? "an unknown signer") : null;
  const differs = !!stored && stored.status !== verdict.status;
  let storedLine = "";
  const nested = !!stored && parent?.manifestLabel != null && stored.manifestLabel !== parent.manifestLabel;
  const when = nested
    ? `when it imported the file containing this step (${parent?.name ?? "the step above"} stored no result itself)`
    : "when it imported this step";
  if (stored) {
    const at = formatTime(stored.time);
    const storedText = stored.status === "trusted" ? "trusted" : "not trusted";
    if (!verdict.reported) {
      lines.push(
        `c2patool only reports ingredient certificates where its result differs from the one stored in the file. ` +
          `It reported nothing here, so your Trust Sources agree with ${by}, which stored "${storedText}" ${when}${at ? ` (${at})` : ""}.`,
      );
    } else if (differs) {
      storedLine = `${by} stored "${storedText}" ${when}${at ? ` (${at})` : ""}, using its own trust list at that time. Your Trust Sources disagree.`;
      lines.push(storedLine);
    }
    lines.push(STORED_VERDICT_SCOPE);
  }

  // Lead with what the badge says about the *other* signer, since a single
  // badge is easily read as only "your" result.
  const ratedAs = verdict.status === "trusted" ? "trusted" : "not trusted";
  const summary = !parent
    ? "This is the file you opened. No other signer has rated its certificate."
    : !stored
      ? "No earlier signer stored a result for this certificate."
      : differs
        ? `${by} came to a different result, see the dashed badge next to this one.`
        : `${by} came to the same result: it also rated this certificate as ${ratedAs} ${when}.`;
  lines.unshift(summary, "");

  return (
    <>
      <span className={`vs-count ${meta.className}`} title={lines.join("\n")}>
        {verdict.status === "trusted" ? "cert trusted by your Trust Sources" : "cert not trusted by your Trust Sources"}
      </span>
      {differs && (
        // Someone else's differing result gets its own badge in its own color,
        // so a green "yours" never visually covers a red "theirs" (or vice versa).
        <span
          className={`vs-count ${TRUST_META[stored!.status].className} pt-other-result`}
          title={`${storedLine}\n${STORED_VERDICT_SCOPE}`}
        >
          {stored!.status === "trusted" ? "cert trusted by" : "cert not trusted by"} {by}
        </span>
      )}
    </>
  );
}

function formatTime(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
}

function AssertionList({
  label,
  hint,
  assertions,
  manifestLabel,
  onNavigate,
  muted = false,
}: {
  label: string;
  hint: string;
  assertions: string[];
  manifestLabel: string;
  onNavigate?: Navigate;
  muted?: boolean;
}) {
  if (assertions.length === 0) return null;
  return (
    <div className={`pt-covers ${muted ? "pt-covers-muted" : ""}`}>
      <span className="pt-covers-label" title={hint}>
        {label}:
      </span>
      {assertions.map((a) =>
        onNavigate ? (
          <button
            key={a}
            type="button"
            className="pt-chip coverage-link"
            title={`${a}${assertionHint(a)}\nShow in the JSON tree`}
            onClick={() => onNavigate(`${manifestPath(manifestLabel)}.assertion_store.${a}`)}
          >
            {friendlyAssertion(a)}
          </button>
        ) : (
          <span key={a} className="pt-chip" title={`${a}${assertionHint(a)}`}>
            {friendlyAssertion(a)}
          </span>
        ),
      )}
    </div>
  );
}

// Scrolls to an ingredient's card in the tree and flashes it, so following
// an action to "what it used" doesn't lose the reader in a long tree.
function revealCard(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  el.scrollIntoView({ behavior: "smooth", block: "center" });
  el.classList.remove("pt-flash");
  void el.offsetWidth; // restart the animation if clicked twice
  el.classList.add("pt-flash");
}

function nodeName(node: TreeNode, manifests: Record<string, unknown>): string {
  const manifest = node.manifestLabel ? asRecord(manifests[node.manifestLabel]) : null;
  return (manifest && manifestInfo(manifest).signer) ?? node.ingredientTitle ?? node.ingredientKey ?? "(ingredient)";
}

function NodeView({
  node,
  parent,
  nodeId,
  manifests,
  trust,
  isRoot,
  onNavigate,
}: {
  node: TreeNode;
  parent?: { manifestLabel: string | null; name: string | null };
  // DOM id of this node's card; children get `${nodeId}-${index}`.
  nodeId: string;
  manifests: Record<string, unknown>;
  trust: Map<string, TrustVerdict>;
  isRoot: boolean;
  onNavigate?: Navigate;
}) {
  const manifest = node.manifestLabel ? asRecord(manifests[node.manifestLabel]) : null;
  const info = manifest ? manifestInfo(manifest) : null;
  const actionEntries = manifest ? actionsOf(manifest) : [];
  const actions = actionEntries.map((a) => a.action);
  const childIndexByKey = new Map(node.children.map((c, i) => [c.ingredientKey, i]));
  const ai = actions.some((a) => isAiSourceType(a.digitalSourceType));


  const label = info?.signer ?? (node.manifestLabel ? "(unknown signer)" : "(no C2PA manifest)");
  const store = asRecord(manifest?.["assertion_store"]) ?? {};
  const identities = Object.entries(store)
    .filter(([key]) => CAWG_URL_RE.test(`/${key}`))
    .map(([key, value]) => {
      const referenced = referencedAssertions(asRecord(value) ?? {});
      return {
        key,
        signer: cawgSigner(asRecord(value) ?? {}),
        referenced,
        notIncluded: Object.keys(store).filter((k) => !referenced.includes(k) && !CAWG_URL_RE.test(`/${k}`)),
      };
    });

  return (
    <li className="pt-node">
      <div className="pt-card" id={nodeId}>
        {!isRoot && (
          <div className="pt-ingredient-of">
            Ingredient of the step above
            {node.relationship && (
              <>
                {": "}
                <code title={RELATIONSHIP_HINTS[node.relationship] ?? undefined} className="pt-rel">
                  {node.relationship}
                </code>
              </>
            )}
            {node.usedVia.length > 0 && (
              <>
                {" · used by "}
                {node.usedVia.length === 1 ? "action" : "actions"}{" "}
                {node.usedVia.map((a, i) => (
                  <span key={i}>
                    {i > 0 && ", "}
                    <code>{a}</code>
                  </span>
                ))}
              </>
            )}
          </div>
        )}
        <div className="pt-head">
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
          {node.manifestLabel && <TrustBadge verdict={trust.get(claimKey(node.manifestLabel))} parent={parent} />}
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
          identities.map(({ key, signer, referenced, notIncluded }) => (
            <div key={key} className="pt-identity">
              <div className="pt-identity-head">
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
              <TrustBadge verdict={trust.get(cawgKey(node.manifestLabel!, key))} parent={parent} cawg />
              </div>
              <AssertionList
                label="Signed by this identity"
                hint="The organization named above signed exactly these parts of the manifest."
                assertions={referenced}
                manifestLabel={node.manifestLabel!}
                onNavigate={onNavigate}
              />
              <AssertionList
                label="Not signed by this identity"
                hint="These parts are signed only by the claim signature (the product), not by the organization."
                assertions={notIncluded}
                manifestLabel={node.manifestLabel!}
                onNavigate={onNavigate}
                muted
              />
            </div>
          ))}
        {actions.length > 0 && <div className="pt-section-label">Actions in this step</div>}
        {actions.length > 0 && (
          <ul className="pt-actions">
            {actionEntries.map(({ action: a, ingredientKeys }, i) => (
              <li key={i}>
                <code>{shortAction(a.action)}</code>
                {a.digitalSourceType && (
                  <span className={isAiSourceType(a.digitalSourceType) ? "pt-ai-text" : undefined}>
                    {" "}
                    ({shortSourceType(a.digitalSourceType)})
                  </span>
                )}
                {a.description && <span className="pt-desc"> — {a.description}</span>}
                {ingredientKeys.length > 0 && (
                  <span className="pt-targets">
                    {" → "}
                    {ingredientKeys.map((key, k) => {
                      const index = childIndexByKey.get(key);
                      const child = index === undefined ? null : node.children[index];
                      return (
                        <span key={key}>
                          {k > 0 && ", "}
                          {child ? (
                            <button
                              type="button"
                              className="coverage-link"
                              title={`Ingredient ${key}\nShow its card below`}
                              onClick={() => revealCard(`${nodeId}-${index}`)}
                            >
                              {nodeName(child, manifests)}
                            </button>
                          ) : (
                            <code title="Referenced ingredient not found in this manifest">{key}</code>
                          )}
                        </span>
                      );
                    })}
                  </span>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
      {node.children.length > 0 && (
        <ul className="pt-children">
          {node.children.map((child, i) => (
            <NodeView
              key={i}
              node={child}
              parent={{ manifestLabel: node.manifestLabel, name: info?.signer ?? null }}
              nodeId={`${nodeId}-${i}`}
              manifests={manifests}
              trust={trust}
              isRoot={false}
              onNavigate={onNavigate}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

type TrustSource = { label: string; enabled: boolean };

export default function ProvenanceTree({ data, onNavigate }: { data: unknown; onNavigate?: Navigate }) {
  const [activeSources, setActiveSources] = useState<string[] | null>(null);
  // Re-read on every new report: the user may have changed the Trust Sources
  // between analyses.
  useEffect(() => {
    let cancelled = false;
    invoke<TrustSource[]>("get_trust_sources")
      .then((sources) => {
        if (!cancelled) setActiveSources(sources.filter((s) => s.enabled).map((s) => s.label));
      })
      .catch(() => {
        if (!cancelled) setActiveSources(null);
      });
    return () => {
      cancelled = true;
    };
  }, [data]);

  const record = asRecord(data);
  const manifests = asRecord(record?.["manifests"]);
  const active = record?.["active_manifest"];
  if (!record || !manifests || typeof active !== "string" || !(active in manifests)) return null;

  const root = buildNode(
    manifests,
    active,
    { ingredientKey: null, relationship: null, usedVia: [], ingredientTitle: null, ingredientFormat: null },
    new Set(),
  );
  const trust = trustByManifest(record, manifests);

  return (
    <ActiveTrustSources.Provider value={activeSources}>
      <details className="provenance-tree app-section" open>
        <summary className="section-title">Provenance Tree</summary>
        <p className="vs-note">
          Newest step on top; each indented entry is an ingredient that went into the entry above it, with a line
          saying how it was used. Certificate badges name who rated the certificate: your Trust Sources in this run,
          or the step that stored a result when it imported the file.
        </p>
        <ul className="pt-root">
          <NodeView node={root} nodeId="pt-node" manifests={manifests} trust={trust} isRoot onNavigate={onNavigate} />
        </ul>
      </details>
    </ActiveTrustSources.Provider>
  );
}
