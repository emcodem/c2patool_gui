// Reads who signed a CAWG X.509 identity assertion (cawg.identity, sig_type
// "cawg.x509.cose"). c2patool's detailed report only carries the raw COSE_Sign1
// signature (base64); its protected header holds the signer's certificate
// chain (x5chain), leaf first. Rather than a full CBOR + X.509 decoder, this
// finds the first DER certificate in those bytes and reads its subject.

export type CawgSubject = { organization: string | null; commonName: string | null };

type Tlv = { tag: number; start: number; contentStart: number; end: number };

function readTlv(bytes: Uint8Array, pos: number): Tlv | null {
  if (pos + 2 > bytes.length) return null;
  const tag = bytes[pos];
  let len = bytes[pos + 1];
  let contentStart = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || contentStart + n > bytes.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[contentStart + i];
    contentStart += n;
  }
  const end = contentStart + len;
  return end <= bytes.length ? { tag, start: pos, contentStart, end } : null;
}

function children(bytes: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let pos = parent.contentStart;
  while (pos < parent.end) {
    const tlv = readTlv(bytes, pos);
    if (!tlv) break;
    out.push(tlv);
    pos = tlv.end;
  }
  return out;
}

const OID_O = [0x55, 0x04, 0x0a];
const OID_CN = [0x55, 0x04, 0x03];

function sameBytes(bytes: Uint8Array, tlv: Tlv, expected: number[]): boolean {
  if (tlv.end - tlv.contentStart !== expected.length) return false;
  return expected.every((b, i) => bytes[tlv.contentStart + i] === b);
}

// Name ::= SEQUENCE OF SET OF SEQUENCE { type OID, value DirectoryString }
function readName(bytes: Uint8Array, name: Tlv): CawgSubject {
  const result: CawgSubject = { organization: null, commonName: null };
  const decoder = new TextDecoder();
  for (const rdn of children(bytes, name)) {
    for (const atv of children(bytes, rdn)) {
      const [type, value] = children(bytes, atv);
      if (!type || !value || type.tag !== 0x06) continue;
      const text = decoder.decode(bytes.subarray(value.contentStart, value.end));
      if (sameBytes(bytes, type, OID_O)) result.organization ??= text;
      else if (sameBytes(bytes, type, OID_CN)) result.commonName ??= text;
    }
  }
  return result;
}

// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version?, serial,
// signature, issuer, validity, subject, ... }, ... }
function subjectOfCertAt(bytes: Uint8Array, pos: number): CawgSubject | null {
  const cert = readTlv(bytes, pos);
  if (!cert || cert.tag !== 0x30) return null;
  const tbs = children(bytes, cert)[0];
  if (!tbs || tbs.tag !== 0x30) return null;
  const fields = children(bytes, tbs);
  const offset = fields[0]?.tag === 0xa0 ? 1 : 0;
  const subject = fields[offset + 4];
  return subject?.tag === 0x30 ? readName(bytes, subject) : null;
}

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

export function cawgSigner(assertion: Record<string, unknown>): CawgSubject | null {
  const signature = assertion["signature"];
  if (typeof signature !== "string") return null;
  const bytes = base64ToBytes(signature);
  if (!bytes) return null;
  // A DER certificate starts SEQUENCE(long form, 2-byte length) wrapping the
  // tbsCertificate SEQUENCE (same form); the first match is the leaf (x5chain order).
  for (let i = 0; i + 6 < bytes.length; i++) {
    if (bytes[i] === 0x30 && bytes[i + 1] === 0x82 && bytes[i + 4] === 0x30 && bytes[i + 5] === 0x82) {
      const subject = subjectOfCertAt(bytes, i);
      if (subject && (subject.organization || subject.commonName)) return subject;
    }
  }
  return null;
}
