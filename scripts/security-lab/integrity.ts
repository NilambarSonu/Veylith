import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { canonicalJson } from '../../packages/policy-engine/src/audit/chain.js';
import type { LabCase } from './types.js';

export const datasetRoot = 'security-lab/v1';

export interface ManifestVerificationResult {
  readonly manifest: Record<string, unknown>;
  readonly manifestSha256: string;
}

export function verifyManifest(): ManifestVerificationResult {
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

export interface DatasetProvenance {
  readonly datasetPath: string;
  readonly datasetSha256: string;
  readonly manifestVerified: boolean;
  readonly manifestVerification: 'verified' | 'not_applicable';
  readonly manifestSha256: string;
  readonly datasetRawBytes: Buffer;
  readonly cases: LabCase[];
}

export function getSafeRelativePath(targetPath: string, repoRoot: string): string {
  const abs = resolve(repoRoot, targetPath);
  const rel = relative(repoRoot, abs).split('\\').join('/');
  return rel;
}

export function resolveDatasetProvenance(options?: {
  readonly customDatasetPath?: string | null;
  readonly repoRoot?: string;
}): DatasetProvenance {
  const root = options?.repoRoot ?? resolve(process.cwd());
  const customPath = options?.customDatasetPath?.trim();

  if (customPath) {
    const safeDatasetPath = getSafeRelativePath(customPath, root);
    const absPath = resolve(root, customPath);

    let rawBytes: Buffer;
    try {
      rawBytes = readFileSync(absPath);
    } catch (err) {
      throw new Error(
        `Custom dataset unreadable or not found at '${safeDatasetPath}': ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    let parsedCases: LabCase[];
    try {
      const parsed = JSON.parse(rawBytes.toString('utf8'));
      if (!Array.isArray(parsed) || parsed.length === 0) {
        throw new Error('Custom dataset must contain a non-empty array of cases.');
      }
      parsedCases = parsed as LabCase[];
    } catch (err) {
      throw new Error(
        `Invalid custom dataset JSON at '${safeDatasetPath}': ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const datasetSha256 = createHash('sha256').update(rawBytes).digest('hex');

    return {
      datasetPath: safeDatasetPath,
      datasetSha256,
      manifestVerified: false,
      manifestVerification: 'not_applicable',
      manifestSha256: 'not_applicable',
      datasetRawBytes: rawBytes,
      cases: parsedCases,
    };
  }

  // Default frozen benchmark dataset
  const frozenRelativePath = `${datasetRoot}/live-reserve.json`;
  const absFrozenPath = resolve(root, frozenRelativePath);
  const safeDatasetPath = getSafeRelativePath(frozenRelativePath, root);

  let rawBytes: Buffer;
  try {
    rawBytes = readFileSync(absFrozenPath);
  } catch (err) {
    throw new Error(
      `Frozen benchmark dataset unreadable at '${safeDatasetPath}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  let parsedCases: LabCase[];
  try {
    const parsed = JSON.parse(rawBytes.toString('utf8'));
    if (!Array.isArray(parsed) || parsed.length === 0) {
      throw new Error('Frozen dataset must contain a non-empty array of cases.');
    }
    parsedCases = parsed as LabCase[];
  } catch (err) {
    throw new Error(
      `Invalid frozen benchmark dataset JSON at '${safeDatasetPath}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const datasetSha256 = createHash('sha256').update(rawBytes).digest('hex');
  const manifestResult = verifyManifest();

  // Validate that live-reserve.json raw-bytes SHA-256 matches manifest entry
  const manifestFiles = (manifestResult.manifest as { files?: Record<string, string> }).files;
  if (manifestFiles && manifestFiles['live-reserve.json'] !== datasetSha256) {
    throw new Error(
      `Frozen dataset integrity failure: live-reserve.json digest (${datasetSha256}) does not match manifest (${manifestFiles['live-reserve.json']})`,
    );
  }

  return {
    datasetPath: safeDatasetPath,
    datasetSha256,
    manifestVerified: true,
    manifestVerification: 'verified',
    manifestSha256: manifestResult.manifestSha256,
    datasetRawBytes: rawBytes,
    cases: parsedCases,
  };
}
