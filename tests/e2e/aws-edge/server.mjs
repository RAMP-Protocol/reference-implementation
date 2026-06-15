// CloudFront canned-policy signed-URL verifier used as a local stand-in for
// a real CloudFront distribution in the RAMP demo E2E. Runs the exact
// cryptographic check CloudFront performs (RSA-SHA1 over the canned policy
// JSON) against the Exchange-minted URL; if valid, proxies to the origin.
//
// The canned-policy format is:
//
//   <URL>?Expires=<epoch>&Signature=<cloudfront-base64url>&Key-Pair-Id=<kid>
//
// with Signature := RSA-SHA1(private_key, canonical-policy-JSON), and
// CloudFront-base64url is standard base64 with + -> -, / -> ~, = -> _.
//
// Env:
//   EXCHANGE_URL       e.g. http://exchange:8081          (fetch public key)
//   ORIGIN_URL         e.g. http://publisher:80           (proxy on success)
//   PROVIDER           publisher identifier for ramp.json
//   EXCHANGES_JSON     JSON array advertised in ramp.json/exchanges
//   PORT               listen port (default 8788)

import { createHash, createPublicKey, createVerify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';

// Shared with the Hono edge worker (src/edge/src/publisher-manifest.mjs, copied
// into the image at build time) so this shim cannot drift from the canonical
// publisher-manifest shape. Guarded by tests/e2e/harness/test_manifest_parity.py.
import { buildPublisherManifest, WELL_KNOWN_PATH } from './publisher-manifest.mjs';

const PORT = Number.parseInt(process.env.PORT ?? '8788', 10);
const ORIGIN_URL = required('ORIGIN_URL');
const PROVIDER = required('PROVIDER');
const EXCHANGES = JSON.parse(required('EXCHANGES_JSON'));
// Authorized third-party catalog pushers (optional). Consumed by the Exchange
// contributor-authz check (rampwellknown.AuthorizesContributor).
const CATALOG_CONTRIBUTORS = process.env.CATALOG_CONTRIBUTORS_JSON
  ? JSON.parse(process.env.CATALOG_CONTRIBUTORS_JSON)
  : [];
// CloudFront RSA verify key provisioned out-of-band (trusted key group model);
// the cdn-keys.json route is retired (D4). MUST be the public half of the
// Exchange's RSA key. Read from RAMP_CF_PUBLIC_PEM, or the file at
// RAMP_CF_PUBLIC_PEM_FILE (the e2e stack writes an ephemeral key to a shared
// volume at stack-up rather than committing it).
const CF_PUBLIC_PEM = pemFromEnvOrFile('RAMP_CF_PUBLIC_PEM');

let publicKey;

function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`missing env ${name}`);
    process.exit(2);
  }
  return v;
}

// pemFromEnvOrFile returns the PEM from <name>, or (when unset) the file at
// <name>_FILE. Exits when neither is set or the file is unreadable, so a
// mis-provisioned stack fails fast rather than starting with no verify key.
function pemFromEnvOrFile(name) {
  const direct = process.env[name];
  if (direct) return direct;
  const file = process.env[`${name}_FILE`];
  if (!file) {
    console.error(`missing env ${name} (and ${name}_FILE)`);
    process.exit(2);
  }
  try {
    const pem = readFileSync(file, 'utf8');
    console.log(`resolved ${name} from ${name}_FILE (${file})`);
    return pem;
  } catch (err) {
    console.error(`missing env ${name}: ${name}_FILE (${file}) unreadable: ${err}`);
    process.exit(2);
  }
}

function loadPublicKey() {
  publicKey = createPublicKey(CF_PUBLIC_PEM);
  console.log('loaded RSA public key');
}

function cfBase64Decode(s) {
  const std = s.replaceAll('-', '+').replaceAll('~', '/').replaceAll('_', '=');
  return Buffer.from(std, 'base64');
}

function verifyCannedPolicy(url) {
  const expires = url.searchParams.get('Expires');
  const kid = url.searchParams.get('Key-Pair-Id');
  const sigEnc = url.searchParams.get('Signature');
  if (!expires || !kid || !sigEnc) {
    return { valid: false, reason: 'missing-cloudfront-params' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (Number.parseInt(expires, 10) < now) {
    return { valid: false, reason: 'expired' };
  }
  // Reconstruct the canonical resource URL by stripping CF params.
  const canonical = new URL(url.toString());
  canonical.searchParams.delete('Expires');
  canonical.searchParams.delete('Signature');
  canonical.searchParams.delete('Key-Pair-Id');
  const resource = canonical.toString();

  const policy = JSON.stringify({
    Statement: [
      {
        Resource: resource,
        Condition: { DateLessThan: { 'AWS:EpochTime': Number.parseInt(expires, 10) } },
      },
    ],
  });

  const sig = cfBase64Decode(sigEnc);
  const verifier = createVerify('RSA-SHA1');
  verifier.update(policy);
  verifier.end();
  const ok = verifier.verify(publicKey, sig);
  return ok ? { valid: true, resource } : { valid: false, reason: 'signature_mismatch' };
}

async function proxyToOrigin(req, res) {
  const incomingUrl = new URL(req.url, `http://${req.headers.host}`);
  const origin = new URL(ORIGIN_URL);
  origin.pathname = incomingUrl.pathname;
  origin.search = '';
  const upstream = await fetch(origin.toString(), { method: req.method });
  res.writeHead(upstream.status, Object.fromEntries(upstream.headers));
  if (upstream.body) {
    const reader = upstream.body.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      res.write(value);
    }
  }
  res.end();
}

function reply(res, status, body, headers = {}) {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }
  if (url.pathname === WELL_KNOWN_PATH) {
    // Built from the shared canonical builder so this shim cannot drift. Pass
    // undefined (not an empty array) for no contributors so the field is omitted,
    // matching buildPublisherManifest's contract.
    const contributors = CATALOG_CONTRIBUTORS.length > 0 ? CATALOG_CONTRIBUTORS : undefined;
    reply(res, 200, buildPublisherManifest(PROVIDER, EXCHANGES, contributors));
    return;
  }
  if (req.method !== 'GET') {
    reply(res, 405, { error: 'method not allowed' });
    return;
  }
  const result = verifyCannedPolicy(url);
  if (!result.valid) {
    reply(res, 403, { error: 'Invalid signature', reason: result.reason });
    return;
  }
  try {
    await proxyToOrigin(req, res);
  } catch (err) {
    reply(res, 502, { error: 'origin fetch failed', detail: String(err) });
  }
}

loadPublicKey();
const server = createServer((req, res) => {
  handle(req, res).catch((err) => {
    console.error('unhandled', err);
    try {
      reply(res, 500, { error: 'internal' });
    } catch {
      /* ignore */
    }
  });
});
server.listen(PORT, '0.0.0.0', () => {
  console.log(`aws-edge shim listening on :${PORT} proxying to ${ORIGIN_URL}`);
});

// Expose the SHA-256 of the loaded public key for smoke checks.
setTimeout(() => {
  try {
    const der = publicKey.export({ type: 'spki', format: 'der' });
    console.log('pubkey sha256:', createHash('sha256').update(der).digest('hex').slice(0, 16));
  } catch (err) {
    console.error('pubkey sha256 failed:', err);
  }
}, 0);
