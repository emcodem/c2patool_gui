// Small readers for c2patool's detailed (-d) report shape, shared by the
// sections that describe individual manifests.

export type Navigate = (path: string) => void;

// Paths use JsonTree's dotted scheme (root "", then `${path}.${key}`), same
// as findInTree.ts produces for the validation summary.
export const manifestPath = (label: string) => `.manifests.${label}`;

export function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

const str = (value: unknown) => (typeof value === "string" ? value : null);

// claim_generator_info is an object in v2 claims but an array in some
// generators' output; v1 claims only carry a free-text claim_generator.
export function productName(claim: Record<string, unknown> | null): string | null {
  if (!claim) return null;
  const info = claim["claim_generator_info"];
  const first = asRecord(Array.isArray(info) ? info[0] : info);
  if (first && typeof first.name === "string") {
    return typeof first.version === "string" ? `${first.name} ${first.version}` : first.name;
  }
  return str(claim["claim_generator"]);
}

export type ManifestInfo = {
  signer: string | null;
  issuer: string | null;
  time: string | null;
  product: string | null;
  title: string | null;
};

export function manifestInfo(manifest: Record<string, unknown>): ManifestInfo {
  const signature = asRecord(manifest["signature"]);
  const claim = asRecord(manifest["claim"]);
  return {
    signer: str(signature?.common_name),
    issuer: str(signature?.issuer),
    time: str(signature?.time),
    product: productName(claim),
    title: str(claim?.["dc:title"]),
  };
}
