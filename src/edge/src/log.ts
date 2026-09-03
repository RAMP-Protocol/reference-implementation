// The edge worker's structured-log vocabulary: the one place a record's shape
// is decided, so it cannot drift between the call sites that emit them.
//
// The console is the only telemetry channel every target runtime shares —
// Workers, Fastly and Lambda@Edge all collect stdout and nothing else — so
// these records are the worker's entire observable trail.

import type { Context } from 'hono';

import type { AppVariables } from './types.js';

// logEvent owns the canonical {method, path, request_id} base every edge
// record carries, so the shape cannot drift between call sites. Levels:
// info = a delivery this worker authorized, warn = expected denial traffic
// (every unpaid bot produces one), error = operational failure worth alerting
// on. One decision emits exactly one record. The signature (and the raw query
// string carrying it) is never logged; of the signed-URL params, only the
// public identifiers (kid, agent_id) may appear.
export function logEvent(
  c: Context<{ Variables: AppVariables }>,
  level: LogLevel,
  event: string,
  extra: Record<string, string>,
): void {
  logRecord(level, event, {
    ...extra,
    method: c.req.method,
    path: c.req.path,
    request_id: c.get('requestId'),
  });
}

export type LogLevel = 'info' | 'warn' | 'error';

// logRecord is the ONE place a record reaches the log stream, so every record
// this worker writes has the same on-the-wire form. Request-scoped callers go
// through logEvent above; this entry point exists for the few that have no
// request to describe.
//
// The fields are serialized rather than passed as an object, because the
// collected log line is the only form a reader ever sees. Each runtime formats
// a console argument with its own inspector — Node renders `{ a: 'b' }`, with
// unquoted keys and single quotes — so an object argument reaches CloudWatch as
// a debug rendering that no JSON parser accepts, and the rendering differs
// between the three target runtimes. JSON.stringify pins one byte-identical
// payload everywhere, which is what makes the evidence chain's join on url_hash
// possible at all.
export function logRecord(level: LogLevel, event: string, fields: Record<string, string>): void {
  const record = JSON.stringify(fields);
  // Branched (not console[level]) so the noConsole lint rule can statically
  // see that only the allowed info/warn/error methods are ever called.
  if (level === 'error') {
    console.error(event, record);
  } else if (level === 'info') {
    console.info(event, record);
  } else {
    console.warn(event, record);
  }
}

export function logDeny(
  c: Context<{ Variables: AppVariables }>,
  event: string,
  reason: string,
): void {
  logEvent(c, 'warn', event, { reason });
}

// DeliveryFacts are the public identifiers a verified signed URL carried. They
// are read off the verified result rather than re-parsed from the URL, so the
// record can only ever describe what verification actually accepted.
export interface DeliveryFacts {
  kid?: string;
  agentId?: string;
}

// DELIVERY_EVENT names the one record a verified delivery emits. The evidence
// chain joins a delivery to its transaction on this record's url_hash.
export const DELIVERY_EVENT = 'edge.deliver.authorized';

// logDelivery emits that record: the URL digest, the public identifiers, and
// which branch served the request.
//
// url_hash is the SHA-256 of the request URL VERBATIM — the exact string the
// verifier was handed, hashed as bytes with no normalization. That is the same
// definition the Exchange stores its digest under, which is what lets the two
// be compared at all. It is emphatically NOT the canonical form the verifier
// derives internally to check the signature: canonicalization drops the sig
// parameter, so hashing it would produce a digest that can never equal the
// stored one. The join therefore holds exactly while the URL reaches this
// worker unmodified; a CDN that rewrites the query breaks it, and no amount of
// normalizing here could repair that without abandoning the shared definition.
// originStatus is the origin's HTTP status, passed only by a caller that waited
// for the response. It is OMITTED, never defaulted, when this worker never saw
// one: on the CloudFront path the request is handed back to the CDN and the
// origin answers later, out of this worker's sight. A zero or an invented 200
// there would be the worker asserting something it did not observe, and the
// renderer would have no way to tell that apart from a real answer.
export async function logDelivery(
  c: Context<{ Variables: AppVariables }>,
  facts: DeliveryFacts,
  outcome: string,
  originStatus?: number,
): Promise<void> {
  logEvent(c, 'info', DELIVERY_EVENT, {
    url_hash: await sha256Hex(c.req.url),
    outcome,
    ...(facts.kid !== undefined ? { kid: facts.kid } : {}),
    ...(facts.agentId !== undefined ? { agent_id: facts.agentId } : {}),
    ...(originStatus !== undefined ? { origin_status: String(originStatus) } : {}),
  });
}

// sha256Hex hashes a string's verbatim UTF-8 bytes. The protocol SDK ships the
// same helper (its hashUrl), but does not export it from the package, so the
// three lines are written here rather than reaching into the package's
// internals; the digest is defined as plain SHA-256 over the URL bytes, and
// the delivery test pins this against a URL produced by the real signer.
async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
