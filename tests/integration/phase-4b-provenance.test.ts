import { describe, it, expect, afterAll } from 'vitest';
import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import {
  resolveDatasetProvenance,
  verifyManifest,
  getSafeRelativePath,
} from '../../scripts/security-lab/integrity.js';

describe('Phase 4B.3: Evidence Provenance Remediation', () => {
  const repoRoot = path.resolve(__dirname, '../..');
  const tmpRoot = path.join(
    os.tmpdir(),
    `veylith-provenance-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
  );

  let mockServer: http.Server | undefined;

  afterAll(async () => {
    if (mockServer) {
      mockServer.closeAllConnections();
      await new Promise<void>((resolve) => mockServer!.close(() => resolve()));
    }
    if (fs.existsSync(tmpRoot)) {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  describe('1. Default frozen dataset provenance', () => {
    it('preserves frozen manifest verification and records actual manifestSha256 and datasetSha256', () => {
      const provenance = resolveDatasetProvenance({ repoRoot });
      const manifestResult = verifyManifest();

      expect(provenance.manifestVerified).toBe(true);
      expect(provenance.manifestVerification).toBe('verified');
      expect(provenance.manifestSha256).toBe(manifestResult.manifestSha256);
      expect(provenance.datasetPath).toBe('security-lab/v1/live-reserve.json');

      const expectedRawSha256 = crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.resolve(repoRoot, 'security-lab/v1/live-reserve.json')))
        .digest('hex');

      expect(provenance.datasetSha256).toBe(expectedRawSha256);
      expect(provenance.datasetSha256).toBe(
        'e4f918504d7a54bf89a4f599fe6c6a2ef7de9a42c86909613c80de5f826ee276',
      );
      expect(provenance.cases).toHaveLength(6);
      expect(provenance.cases[0]!.id).toBe('VEY-2E-LIVE-01');
    });
  });

  describe('2. Custom dataset raw-byte SHA-256 computation', () => {
    it('computes exact raw-byte SHA-256 for compat-case.json fixture', () => {
      const fixtureRelPath = 'security-lab/compat-case.json';
      const provenance = resolveDatasetProvenance({
        customDatasetPath: fixtureRelPath,
        repoRoot,
      });

      const expectedRawSha256 = crypto
        .createHash('sha256')
        .update(fs.readFileSync(path.resolve(repoRoot, fixtureRelPath)))
        .digest('hex');

      expect(provenance.datasetSha256).toBe(expectedRawSha256);
      expect(provenance.datasetSha256).toBe(
        '943b72268b7ac8d158e14b85347d20f7694a10ccab93f18fd2e8a28b816096dd',
      );
      expect(provenance.cases).toHaveLength(1);
      expect(provenance.cases[0]!.id).toBe('SYNTH-COMPAT-LIVE-01');
    });

    it('computes exact raw-byte SHA-256 for newly created custom datasets', () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const customPath = path.join(tmpRoot, 'custom-test-cases.json');
      const testContent = JSON.stringify([
        {
          id: 'TEST-CANARY-01',
          scenarioId: 'G1',
          stage: 'call_response',
          input: 'Test input payload for provenance hashing',
          expectedSecurityDecision: 'allow',
        },
      ]);
      fs.writeFileSync(customPath, testContent);

      const expectedHash = crypto
        .createHash('sha256')
        .update(Buffer.from(testContent))
        .digest('hex');
      const provenance = resolveDatasetProvenance({
        customDatasetPath: customPath,
        repoRoot,
      });

      expect(provenance.datasetSha256).toBe(expectedHash);
    });
  });

  describe('3. Custom dataset relative path resolution', () => {
    it('records clean repository-relative path without directory traversal or home directory leaks', () => {
      const relPath = 'security-lab/compat-case.json';
      const absPath = path.resolve(repoRoot, relPath);
      const dotSlashPath = `./${relPath}`;

      expect(getSafeRelativePath(relPath, repoRoot)).toBe(relPath);
      expect(getSafeRelativePath(absPath, repoRoot)).toBe(relPath);
      expect(getSafeRelativePath(dotSlashPath, repoRoot)).toBe(relPath);

      const provFromRel = resolveDatasetProvenance({ customDatasetPath: relPath, repoRoot });
      const provFromAbs = resolveDatasetProvenance({ customDatasetPath: absPath, repoRoot });
      const provFromDot = resolveDatasetProvenance({ customDatasetPath: dotSlashPath, repoRoot });

      expect(provFromRel.datasetPath).toBe(relPath);
      expect(provFromAbs.datasetPath).toBe(relPath);
      expect(provFromDot.datasetPath).toBe(relPath);
      expect(provFromAbs.datasetPath).not.toContain(os.homedir());
    });
  });

  describe('4. Custom dataset manifest non-applicability representation', () => {
    it('marks manifest verification explicitly as not applicable and never claims verification', () => {
      const provenance = resolveDatasetProvenance({
        customDatasetPath: 'security-lab/compat-case.json',
        repoRoot,
      });

      expect(provenance.manifestVerified).toBe(false);
      expect(provenance.manifestVerification).toBe('not_applicable');
      expect(provenance.manifestSha256).toBe('not_applicable');
      expect(provenance.manifestSha256).not.toBe(provenance.datasetSha256);
      expect(provenance.manifestSha256).not.toBe('mock-test-manifest');
    });
  });

  describe('5. Prohibition of mock-test-manifest in real execution', () => {
    it('verifies mock-test-manifest is completely absent from live runner and integrity code', () => {
      const liveTsContent = fs.readFileSync(
        path.resolve(repoRoot, 'scripts/security-lab/live.ts'),
        'utf8',
      );
      const integrityTsContent = fs.readFileSync(
        path.resolve(repoRoot, 'scripts/security-lab/integrity.ts'),
        'utf8',
      );

      expect(liveTsContent).not.toContain('mock-test-manifest');
      expect(integrityTsContent).not.toContain('mock-test-manifest');
    });

    it('generates attempt.json in live runner without mock-test-manifest and with correct schema', async () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const customDatasetPath = path.join(tmpRoot, 'runner-canary-case.json');
      const destinationDir = path.join(tmpRoot, 'live-runner-dest');
      const preloadPath = path.join(tmpRoot, 'mock-preload.cjs');

      const canaryCase = [
        {
          id: 'SYNTH-RUNNER-CANARY-01',
          scenarioId: 'G1',
          stage: 'call_response',
          input: 'Explain the principle of least privilege in one sentence.',
          expectedSecurityDecision: 'allow',
        },
      ];
      fs.writeFileSync(customDatasetPath, JSON.stringify(canaryCase, null, 2));

      // Mock HTTP server
      mockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (d) => (body += d));
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              id: 'chatcmpl-mock',
              choices: [
                {
                  message: {
                    content: JSON.stringify({
                      flagged: false,
                      threatCategory: 'none',
                      action: 'allow',
                      confidence: 0.99,
                      explanation: 'Benign security question',
                    }),
                  },
                },
              ],
              usage: {
                prompt_tokens: 100,
                completion_tokens: 25,
                total_tokens: 125,
              },
              status: 'completed',
            }),
          );
        });
      });

      await new Promise<void>((resolve) => mockServer!.listen(0, '127.0.0.1', resolve));
      const mockPort = (mockServer.address() as AddressInfo).port;

      fs.writeFileSync(
        preloadPath,
        `
const origFetch = globalThis.fetch;
const mockPort = ${mockPort};
globalThis.fetch = async (input, init) => {
  const urlStr = typeof input === 'string' ? input : (input instanceof URL ? input.href : input.url);
  if (urlStr.includes('api.fireworks.ai')) {
    return origFetch('http://127.0.0.1:' + mockPort + '/inference', init);
  }
  return origFetch(input, init);
};
`,
      );

      const scriptPath = path.resolve(repoRoot, 'scripts/security-lab/live.ts');

      const exitCode = await new Promise<number>((resolve, reject) => {
        const child = spawn(
          process.execPath,
          [
            '--import',
            preloadPath,
            '--import',
            'tsx',
            scriptPath,
            '--allow-paid',
            '--provider=fireworks',
            '--allow-unverified-pricing',
            '--max-requests=1',
            '--max-total-tokens=4096',
            '--max-cost-usd=0.01',
            '--input-rate=1.0',
            '--output-rate=1.0',
            '--cached-rate=0.5',
          ],
          {
            cwd: repoRoot,
            env: {
              ...process.env,
              FIREWORKS_API_KEY: 'fw_test_mock_key',
              SECURITY_LAB_DESTINATION: destinationDir,
              SECURITY_LAB_DATASET: customDatasetPath,
            },
          },
        );

        let stderr = '';
        child.stderr.on('data', (d) => (stderr += d.toString()));
        child.on('error', reject);
        child.on('close', (code) => {
          if (code !== 0) {
            reject(new Error(`live.ts failed with code ${code}: ${stderr}`));
          } else {
            resolve(code);
          }
        });
      });

      expect(exitCode).toBe(0);

      const attemptJsonPath = path.join(destinationDir, 'attempt.json');
      expect(fs.existsSync(attemptJsonPath)).toBe(true);

      const attemptData = JSON.parse(fs.readFileSync(attemptJsonPath, 'utf8'));
      expect(attemptData.manifestSha256).toBe('not_applicable');
      expect(attemptData.manifestVerification).toBe('not_applicable');
      expect(attemptData.manifestVerified).toBe(false);
      expect(attemptData.datasetSha256).toBe(
        crypto.createHash('sha256').update(fs.readFileSync(customDatasetPath)).digest('hex'),
      );
      expect(attemptData.manifestSha256).not.toContain('mock-test-manifest');
    });
  });

  describe('6. Safe failure on invalid or unreadable custom dataset', () => {
    it('throws descriptive error on non-existent file path without creating attempt.json', () => {
      expect(() =>
        resolveDatasetProvenance({
          customDatasetPath: 'security-lab/non-existent-case.json',
          repoRoot,
        }),
      ).toThrow(/Custom dataset unreadable or not found/);
    });

    it('throws descriptive error on invalid JSON syntax without creating attempt.json', () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const badJsonPath = path.join(tmpRoot, 'broken.json');
      fs.writeFileSync(badJsonPath, '{ invalid json syntax');

      expect(() =>
        resolveDatasetProvenance({
          customDatasetPath: badJsonPath,
          repoRoot,
        }),
      ).toThrow(/Invalid custom dataset JSON/);
    });

    it('throws descriptive error on non-array JSON payload', () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const nonArrayPath = path.join(tmpRoot, 'object-not-array.json');
      fs.writeFileSync(nonArrayPath, JSON.stringify({ not: 'an array' }));

      expect(() =>
        resolveDatasetProvenance({
          customDatasetPath: nonArrayPath,
          repoRoot,
        }),
      ).toThrow(/Custom dataset must contain a non-empty array of cases/);
    });

    it('throws descriptive error on empty array JSON payload', () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const emptyArrayPath = path.join(tmpRoot, 'empty.json');
      fs.writeFileSync(emptyArrayPath, '[]');

      expect(() =>
        resolveDatasetProvenance({
          customDatasetPath: emptyArrayPath,
          repoRoot,
        }),
      ).toThrow(/Custom dataset must contain a non-empty array of cases/);
    });

    it('fails safely in live.ts subprocess before creating destination attempt.json', async () => {
      fs.mkdirSync(tmpRoot, { recursive: true });
      const badDest = path.join(tmpRoot, 'dest-should-not-have-attempt');
      const nonExistentDataset = path.join(tmpRoot, 'missing-file.json');
      const scriptPath = path.resolve(repoRoot, 'scripts/security-lab/live.ts');

      const exitCode = await new Promise<number>((resolve) => {
        const child = spawn(
          process.execPath,
          [
            '--import',
            'tsx',
            scriptPath,
            '--allow-paid',
            '--provider=fireworks',
            '--allow-unverified-pricing',
          ],
          {
            cwd: repoRoot,
            env: {
              ...process.env,
              FIREWORKS_API_KEY: 'fw_mock_key',
              SECURITY_LAB_DESTINATION: badDest,
              SECURITY_LAB_DATASET: nonExistentDataset,
            },
          },
        );

        child.on('close', (code) => resolve(code ?? 1));
      });

      expect(exitCode).not.toBe(0);
      expect(fs.existsSync(path.join(badDest, 'attempt.json'))).toBe(false);
    });
  });
});
