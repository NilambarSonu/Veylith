import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson } from '../../packages/policy-engine/src/audit/chain.js';
import type { LabCase } from './types.js';
export const datasetRoot = 'security-lab/v1';
export function verifyManifest() {
  const manifestBytes = readFileSync(`${datasetRoot}/manifest.json`);
  const manifest = JSON.parse(manifestBytes.toString());
  for (const [file, expected] of Object.entries(manifest.files)) {
    const actual = createHash('sha256')
      .update(readFileSync(`${datasetRoot}/${file}`))
      .digest('hex');
    if (actual !== expected) throw new Error(`Frozen dataset integrity failure: ${file}`);
  }
  const cases: LabCase[] = JSON.parse(readFileSync(`${datasetRoot}/holdout.json`, 'utf8'));
  for (const c of cases) {
    // Dataset canonicalization is Unicode-preserving, lexically sorted JSON.
    const hash = createHash('sha256').update(canonicalJson(c)).digest('hex');
    if (hash !== manifest.caseHashes[c.id])
      throw new Error(`Frozen label integrity failure: ${c.id}`);
  }
  return { manifest, manifestSha256: createHash('sha256').update(manifestBytes).digest('hex') };
}
