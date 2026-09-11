// Best-effort mapping from a validation_results entry's JUMBF `url` reference
// (e.g. "self#jumbf=/c2pa/<manifest-id>/c2pa.assertions/c2pa.thumbnail.claim.jpeg")
// to a path in the parsed report JSON, using the same dotted path scheme
// JsonTree builds internally (see JsonTree.tsx's `${path}.${k}`).
//
// This is a heuristic, not a precise JUMBF-box resolver: it looks for either
// (a) a field whose value equals the exact url string, or (b) an object key
// matching the url's last path segment (how assertion_store entries are keyed).
export function findPathForValidationUrl(data: unknown, jumbfUrl: string): string | null {
  const lastSegment = jumbfUrl.split("/").pop() ?? jumbfUrl;

  let exactValueMatch: string | null = null;
  let keyNameMatch: string | null = null;

  function walk(value: unknown, path: string) {
    if (value === null || typeof value !== "object") return;
    const entries: [string, unknown][] = Array.isArray(value)
      ? value.map((v, i): [string, unknown] => [String(i), v])
      : Object.entries(value as Record<string, unknown>);

    for (const [k, v] of entries) {
      const childPath = `${path}.${k}`;
      if (typeof v === "string") {
        if (!exactValueMatch && v === jumbfUrl) {
          exactValueMatch = childPath;
        }
      } else if (v !== null && typeof v === "object") {
        if (!keyNameMatch && k === lastSegment) {
          keyNameMatch = childPath;
        }
        walk(v, childPath);
      }
    }
  }

  walk(data, "");
  return keyNameMatch ?? exactValueMatch;
}
