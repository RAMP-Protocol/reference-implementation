// Web Bot Auth (WBA) request-signature verification — RFC 9421 HTTP Message
// Signatures under the web-bot-auth profile.
//
// This is the request-side counterpart to verify.ts (which verifies signed
// *URLs*). It realizes ADR-015 D2 (cryptographic crawler identity) and D3 (a
// signed purpose declaration whose coverage by the signature is the acceptance
// primitive). It is framework-agnostic — no Hono, no network — so the same
// module backs both the multi-runtime Hono app and the native CloudFront edge
// handler. Key resolution is injected (`resolveBotKey`); this module never
// fetches a JWKS directory itself.
//
// References: RFC 9421 (HTTP Message Signatures), draft-meunier-web-bot-auth.

import { decodeBase64Url } from './verify.js';

const WEB_BOT_AUTH_TAG = 'web-bot-auth';
const DEFAULT_PURPOSE_HEADER = 'x-intended-use';
const SIG_PREFIX_LEN = 16;

export type WbaFailure =
  | 'missing_signature'
  | 'missing_signature_input'
  | 'malformed_signature_input'
  | 'malformed_signature'
  | 'unsupported_tag'
  | 'missing_purpose_header'
  | 'authority_not_covered'
  | 'path_not_covered'
  | 'purpose_not_covered'
  | 'unknown_key'
  | 'expired'
  | 'signature_mismatch';

export interface WebBotAuthInput {
  method: string;
  /** Request authority (host[:port]); compared case-insensitively. */
  authority: string;
  /** Request path only (no query string). */
  path: string;
  /** Request headers — a Headers instance or a plain (lowercased-key) record. */
  headers: Headers | Record<string, string | undefined>;
  /**
   * Resolve the bot's Ed25519 public key from the signature's keyid and/or its
   * Signature-Agent directory URL. Injected — see keys.ts for a JWKS-backed
   * implementation. Returns undefined when the key is unknown.
   */
  resolveBotKey: (
    keyid: string | undefined,
    agent: string | undefined,
  ) => Promise<CryptoKey | undefined>;
  /** Clock for `expires` enforcement (ms since epoch). Defaults to Date.now. */
  now?: () => number;
  /** Purpose header name. Default 'x-intended-use'. */
  purposeHeader?: string;
  /**
   * Components that MUST be covered by the signature for the request to be
   * fast-path-eligible. Default: ['@authority', '@path', <purposeHeader>].
   */
  requiredComponents?: readonly string[];
}

export interface WebBotAuthResult {
  valid: boolean;
  reason?: WbaFailure;
  /** Signature label (dictionary key in Signature-Input). */
  label?: string;
  keyid?: string;
  /** Signature-Agent header value (the bot's directory URL), if present. */
  agent?: string;
  /** The declared purpose token (purpose header value), if present. */
  purpose?: string;
  /** Covered component identifiers, lowercased, quotes stripped. */
  covered?: string[];
  /** First 16 chars of the base64url signature — a ledger join key. */
  sigPrefix?: string;
}

export async function verifyWebBotAuthRequest(input: WebBotAuthInput): Promise<WebBotAuthResult> {
  const purposeHeader = (input.purposeHeader ?? DEFAULT_PURPOSE_HEADER).toLowerCase();
  const required = (input.requiredComponents ?? ['@authority', '@path', purposeHeader]).map((c) =>
    c.toLowerCase(),
  );
  const getHeader = headerReader(input.headers);

  const rawSigInput = getHeader('signature-input');
  if (!rawSigInput) return fail('missing_signature_input');
  const rawSig = getHeader('signature');
  if (!rawSig) return fail('missing_signature');

  const parsed = parseSignatureInput(rawSigInput);
  if (!parsed) return fail('malformed_signature_input');
  const { label, components: covered, paramsString, params } = parsed;
  const ctx: FailExtras = { label, keyid: params.keyid, covered };

  if (params.tag !== undefined && params.tag !== WEB_BOT_AUTH_TAG) {
    return fail('unsupported_tag', { label });
  }

  const sig = decodeSignature(rawSig, label);
  if (!sig) return fail('malformed_signature', { label });
  ctx.sigPrefix = sig.prefix;

  // Coverage enforcement (D3, the keystone): identity without a signed purpose
  // is not fast-path-eligible. Every required component must be in the covered
  // list, else there is no agreement to the terms.
  const coverageReason = coverageCheck(covered, required, purposeHeader);
  if (coverageReason) return fail(coverageReason, ctx);

  const purpose = getHeader(purposeHeader);
  if (covered.includes(purposeHeader) && purpose === undefined) {
    // Signature claims to cover the purpose header but it is absent — the base
    // cannot be reconstructed and intent is unprovable.
    return fail('missing_purpose_header', ctx);
  }

  const agent = getHeader('signature-agent');
  if (isExpired(params.expires, input.now)) return fail('expired', ctx);

  const key = await input.resolveBotKey(params.keyid, agent);
  if (!key) return fail('unknown_key', ctx);

  const base = buildSignatureBase({
    components: covered,
    paramsString,
    method: input.method,
    authority: input.authority,
    path: input.path,
    getHeader,
  });
  const ok = await crypto.subtle.verify('Ed25519', key, sig.bytes, new TextEncoder().encode(base));
  if (!ok) return fail('signature_mismatch', ctx);

  return success({ label, covered, sigPrefix: sig.prefix, keyid: params.keyid, agent, purpose });
}

// Each required component maps to a precise coverage failure; the first missing
// one wins. Returns undefined when everything required is covered.
function coverageCheck(
  covered: readonly string[],
  required: readonly string[],
  purposeHeader: string,
): WbaFailure | undefined {
  for (const req of required) {
    if (covered.includes(req)) continue;
    if (req === '@authority') return 'authority_not_covered';
    if (req === '@path') return 'path_not_covered';
    if (req === purposeHeader) return 'purpose_not_covered';
    return 'signature_mismatch';
  }
  return undefined;
}

// `expires` is optional; when present, a signature whose deadline has passed is
// rejected even though the free tier carries no quota or round-trip.
function isExpired(expires: number | undefined, now: (() => number) | undefined): boolean {
  if (expires === undefined) return false;
  return Math.floor((now?.() ?? Date.now()) / 1000) >= expires;
}

function decodeSignature(
  rawSig: string,
  label: string,
): { bytes: Uint8Array; prefix: string } | undefined {
  const sigB64 = parseSignatureForLabel(rawSig, label);
  if (sigB64 === undefined) return undefined;
  const bytes = decodeBase64Url(sigB64);
  if (!bytes) return undefined;
  return { bytes, prefix: sigB64.slice(0, SIG_PREFIX_LEN) };
}

function success(extras: FailExtras): WebBotAuthResult {
  const out: WebBotAuthResult = { valid: true };
  if (extras.label !== undefined) out.label = extras.label;
  if (extras.keyid !== undefined) out.keyid = extras.keyid;
  if (extras.agent !== undefined) out.agent = extras.agent;
  if (extras.purpose !== undefined) out.purpose = extras.purpose;
  if (extras.covered !== undefined) out.covered = extras.covered;
  if (extras.sigPrefix !== undefined) out.sigPrefix = extras.sigPrefix;
  return out;
}

interface FailExtras {
  label?: string | undefined;
  keyid?: string | undefined;
  agent?: string | undefined;
  purpose?: string | undefined;
  covered?: string[] | undefined;
  sigPrefix?: string | undefined;
}

function fail(reason: WbaFailure, extras: FailExtras = {}): WebBotAuthResult {
  const out: WebBotAuthResult = { valid: false, reason };
  if (extras.label !== undefined) out.label = extras.label;
  if (extras.keyid !== undefined) out.keyid = extras.keyid;
  if (extras.agent !== undefined) out.agent = extras.agent;
  if (extras.purpose !== undefined) out.purpose = extras.purpose;
  if (extras.covered !== undefined) out.covered = extras.covered;
  if (extras.sigPrefix !== undefined) out.sigPrefix = extras.sigPrefix;
  return out;
}

function headerReader(
  headers: Headers | Record<string, string | undefined>,
): (name: string) => string | undefined {
  if (typeof (headers as Headers).get === 'function') {
    const h = headers as Headers;
    return (name) => h.get(name) ?? undefined;
  }
  // Plain record — normalize keys to lowercase once.
  const record = headers as Record<string, string | undefined>;
  const lower = new Map<string, string>();
  for (const [k, v] of Object.entries(record)) {
    if (v !== undefined) lower.set(k.toLowerCase(), v);
  }
  return (name) => lower.get(name.toLowerCase());
}

interface ParsedSignatureInput {
  label: string;
  /** Covered component identifiers, lowercased with surrounding quotes stripped. */
  components: string[];
  /** Exact wire substring after `<label>=` — reused verbatim for @signature-params. */
  paramsString: string;
  params: {
    keyid?: string;
    tag?: string;
    created?: number;
    expires?: number;
  };
}

// Parse a single-label Signature-Input dictionary entry, e.g.
//   sig1=("@authority" "@path" "x-intended-use");created=1700000000;keyid="k1";alg="ed25519";tag="web-bot-auth"
// Returns the covered component list plus the exact parameter serialization
// (everything after `<label>=`) so the signature base can reuse the wire bytes
// for the @signature-params line rather than re-serializing structured fields.
export function parseSignatureInput(raw: string): ParsedSignatureInput | undefined {
  const trimmed = raw.trim();
  const eq = trimmed.indexOf('=');
  if (eq <= 0) return undefined;
  const label = trimmed.slice(0, eq).trim();
  const rest = trimmed.slice(eq + 1);
  if (!label || !rest.startsWith('(')) return undefined;
  const close = rest.indexOf(')');
  if (close < 0) return undefined;

  const inner = rest.slice(1, close);
  const components = inner
    .split(/\s+/)
    .map((tok) => tok.trim())
    .filter((tok) => tok.length > 0)
    .map(stripQuotes)
    .map((c) => c.toLowerCase());

  // The @signature-params value is the verbatim wire serialization of the inner
  // component list plus its parameters — i.e. everything after `<label>=`.
  const paramsString = rest;
  const params = parseParams(rest.slice(close + 1));
  return { label, components, paramsString, params };
}

function parseParams(tail: string): ParsedSignatureInput['params'] {
  const params: ParsedSignatureInput['params'] = {};
  // tail looks like ";created=..;keyid=\"..\";alg=\"..\";tag=\"..\""
  for (const seg of tail.split(';')) {
    const s = seg.trim();
    if (!s) continue;
    const eq = s.indexOf('=');
    if (eq < 0) continue;
    const k = s.slice(0, eq).trim().toLowerCase();
    const v = stripQuotes(s.slice(eq + 1).trim());
    if (k === 'keyid') params.keyid = v;
    else if (k === 'tag') params.tag = v;
    else if (k === 'created') setNumber(params, 'created', v);
    else if (k === 'expires') setNumber(params, 'expires', v);
  }
  return params;
}

// Parse the Signature dictionary and return the base64url payload for `label`,
// e.g. `sig1=:AbC...:` -> `AbC...`.
export function parseSignatureForLabel(raw: string, label: string): string | undefined {
  for (const entry of splitDictionary(raw)) {
    const eq = entry.indexOf('=');
    if (eq <= 0) continue;
    if (entry.slice(0, eq).trim() !== label) continue;
    const val = entry.slice(eq + 1).trim();
    if (!val.startsWith(':') || !val.endsWith(':') || val.length < 2) return undefined;
    return val.slice(1, -1);
  }
  return undefined;
}

// Split a structured-field dictionary on top-level commas (commas inside the
// `:...:` byte-sequence delimiters are not separators in practice for our
// single-entry signer, but we guard against them).
function splitDictionary(raw: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let inBytes = false;
  let start = 0;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch === ':') inBytes = !inBytes;
    else if (!inBytes && ch === '(') depth += 1;
    else if (!inBytes && ch === ')') depth -= 1;
    else if (!inBytes && depth === 0 && ch === ',') {
      out.push(raw.slice(start, i));
      start = i + 1;
    }
  }
  out.push(raw.slice(start));
  return out;
}

interface BaseInput {
  components: string[];
  paramsString: string;
  method: string;
  authority: string;
  path: string;
  getHeader: (name: string) => string | undefined;
}

// Build the RFC 9421 signature base: one line per covered component, then the
// trailing "@signature-params" line whose value is the exact wire parameter
// serialization. Each line is `"<id>": <value>` with a trailing newline; the
// final @signature-params line has no trailing newline.
export function buildSignatureBase(input: BaseInput): string {
  const lines: string[] = [];
  for (const comp of input.components) {
    lines.push(`"${comp}": ${componentValue(comp, input)}`);
  }
  lines.push(`"@signature-params": ${input.paramsString}`);
  return lines.join('\n');
}

function componentValue(comp: string, input: BaseInput): string {
  switch (comp) {
    case '@method':
      return input.method.toUpperCase();
    case '@authority':
      return input.authority.toLowerCase();
    case '@path':
      return input.path;
    default: {
      const v = input.getHeader(comp);
      return (v ?? '').trim();
    }
  }
}

function stripQuotes(s: string): string {
  if (s.length >= 2 && s.startsWith('"') && s.endsWith('"')) return s.slice(1, -1);
  return s;
}

function setNumber(
  params: ParsedSignatureInput['params'],
  key: 'created' | 'expires',
  raw: string,
): void {
  if (/^\d+$/.test(raw)) params[key] = Number(raw);
}
