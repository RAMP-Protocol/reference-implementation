import { readFileSync } from 'node:fs';
import { URL, fileURLToPath } from 'node:url';

import Ajv2020 from 'ajv/dist/2020.js';

// The edge is the manifest producer whose output is hand-built rather than
// schema-validated — the Go producers go through the generated types. Both
// discovery documents are pinned to the SAME canonical schemas the Go consumer
// enforces, so a required field, renamed enum, or shape change fails in the
// suite instead of silently serving a document the broker probe would reject.
//
// Two test files need those assertions — the emitter tests and the
// deploy-template tests — so the Ajv setup is shared rather than copied. Copying
// it would also fail the duplication gate, which runs at threshold 0 over the
// TypeScript under src/.
//
// strict:false: the schemas carry a non-standard `comment` keyword for docs.
const ajv = new Ajv2020({ strict: false });

// Both schemas are compiled ONCE, here at module scope, and the assertions are
// exported ready-made. Exporting `compile` instead would let two importers ask
// this one Ajv instance for the same schema twice, and Ajv refuses a second
// schema carrying an $id it already holds.
function compile(relPath: string): (doc: unknown) => void {
  const schemaPath = fileURLToPath(new URL(relPath, import.meta.url));
  // biome-ignore lint/suspicious/noExplicitAny: a JSON Schema document is untyped.
  const schema = JSON.parse(readFileSync(schemaPath, 'utf8')) as any;
  const validate = ajv.compile(schema);
  return (doc: unknown) => {
    if (!validate(doc)) {
      throw new Error(`schema validation failed: ${JSON.stringify(validate.errors)}`);
    }
  };
}

/** Throws unless doc satisfies the canonical /.well-known/ramp.json schema. */
export const assertValidManifest = compile(
  '../../../../internal/rampwellknown/schema/ramp-well-known.json',
);

/**
 * Throws unless doc satisfies the canonical Web Bot Auth directory schema
 * (/.well-known/http-message-signatures-directory).
 */
export const assertValidWba = compile(
  '../../../../internal/rampwellknown/schema/ramp-wba-directory.json',
);
