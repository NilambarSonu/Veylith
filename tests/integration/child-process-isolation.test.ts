/**
 * Real Child-Process Credential Isolation & Redaction Tests.
 *
 * Verifies:
 *   1. Actual child processes spawned with getSafeChildEnvironment() observe strict per-server boundaries.
 *   2. Synthetic tokens for Server A are NEVER visible to Server B child processes.
 *   3. Host sensitive variables are stripped under default-deny.
 *   4. Logs and missing-credential errors do not leak credential values.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn } from 'node:child_process';
import {
  getSafeChildEnvironment,
  type ServerCredentialPolicy,
} from '../../apps/stdio-adapter/src/security.js';
import { StdioLogger } from '../../apps/stdio-adapter/src/logger.js';
import { Writable } from 'node:stream';

describe('Real Child-Process Credential Isolation and Redaction', () => {
  const SYNTH_TOKEN_ALPHA = 'synth_alpha_isolated_token_11111';
  const SYNTH_TOKEN_BETA = 'synth_beta_isolated_token_22222';
  const SYNTH_HOST_SECRET = 'synth_host_sensitive_do_not_leak_99999';

  beforeAll(() => {
    process.env['SYNTHETIC_TOKEN_ALPHA'] = SYNTH_TOKEN_ALPHA;
    process.env['SYNTHETIC_TOKEN_BETA'] = SYNTH_TOKEN_BETA;
    process.env['SYNTHETIC_HOST_SECRET'] = SYNTH_HOST_SECRET;
  });

  afterAll(() => {
    delete process.env['SYNTHETIC_TOKEN_ALPHA'];
    delete process.env['SYNTHETIC_TOKEN_BETA'];
    delete process.env['SYNTHETIC_HOST_SECRET'];
  });

  function runChildAndGetEnv(env: Record<string, string>): Promise<Record<string, string>> {
    return new Promise((resolve, reject) => {
      const proc = spawn(
        process.execPath,
        ['-e', 'process.stdout.write(JSON.stringify(process.env))'],
        {
          env,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );

      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (chunk) => {
        stdout += chunk.toString();
      });

      proc.stderr.on('data', (chunk) => {
        stderr += chunk.toString();
      });

      proc.on('error', reject);

      proc.on('exit', (code) => {
        if (code !== 0) {
          return reject(new Error(`Child exited with code ${code}: ${stderr}`));
        }
        try {
          resolve(JSON.parse(stdout));
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  it('proves actual child process Alpha receives only Alpha credentials and never Beta credentials', async () => {
    const policies: ServerCredentialPolicy[] = [
      {
        serverId: 'server-alpha',
        allowedEnvVars: ['SYNTHETIC_TOKEN_ALPHA'],
      },
      {
        serverId: 'server-beta',
        allowedEnvVars: ['SYNTHETIC_TOKEN_BETA'],
      },
    ];

    const envAlpha = getSafeChildEnvironment({
      serverId: 'server-alpha',
      policy: policies,
    });

    const childEnv = await runChildAndGetEnv(envAlpha);

    // Alpha credential is appropriately inherited
    expect(childEnv['SYNTHETIC_TOKEN_ALPHA']).toBe(SYNTH_TOKEN_ALPHA);

    // Beta credential is completely absent / inaccessible
    expect(childEnv['SYNTHETIC_TOKEN_BETA']).toBeUndefined();

    // Host sensitive secret is completely stripped by default-deny
    expect(childEnv['SYNTHETIC_HOST_SECRET']).toBeUndefined();
  });

  it('proves actual child process Beta receives only Beta credentials and never Alpha credentials', async () => {
    const policies: ServerCredentialPolicy[] = [
      {
        serverId: 'server-alpha',
        allowedEnvVars: ['SYNTHETIC_TOKEN_ALPHA'],
      },
      {
        serverId: 'server-beta',
        allowedEnvVars: ['SYNTHETIC_TOKEN_BETA'],
      },
    ];

    const envBeta = getSafeChildEnvironment({
      serverId: 'server-beta',
      policy: policies,
    });

    const childEnv = await runChildAndGetEnv(envBeta);

    // Beta credential is appropriately inherited
    expect(childEnv['SYNTHETIC_TOKEN_BETA']).toBe(SYNTH_TOKEN_BETA);

    // Alpha credential is completely absent / inaccessible
    expect(childEnv['SYNTHETIC_TOKEN_ALPHA']).toBeUndefined();

    // Host sensitive secret is completely stripped by default-deny
    expect(childEnv['SYNTHETIC_HOST_SECRET']).toBeUndefined();
  });

  it('redacts sensitive tokens in logger output when redactSecrets is enabled', () => {
    const logOutput: string[] = [];
    const stream = new Writable({
      write(chunk, _encoding, callback) {
        logOutput.push(chunk.toString());
        callback();
      },
    });

    const logger = new StdioLogger('info', true, stream);

    logger.info('Upstream server initialized', {
      serverId: 'server-alpha',
      apiKey: SYNTH_TOKEN_ALPHA,
      customSecret: 'my_secret_key_abcdef12345',
    });

    const joinedLogs = logOutput.join('\n');

    // The raw token value must NOT appear anywhere in the log output
    expect(joinedLogs).not.toContain(SYNTH_TOKEN_ALPHA);
    expect(joinedLogs).not.toContain('my_secret_key_abcdef12345');

    // The redacted placeholder must be present
    expect(joinedLogs).toContain('[REDACTED]');
  });

  it('produces a clear, sanitized error when required credentials are missing without leaking secrets', () => {
    const policy: ServerCredentialPolicy = {
      serverId: 'db-server',
      requiredEnvVars: ['DATABASE_URL', 'AUTH_TOKEN'],
    };

    expect(() => {
      getSafeChildEnvironment({
        serverId: 'db-server',
        policy,
      });
    }).toThrowError(/Missing required credential 'DATABASE_URL' for trusted server 'db-server'/);
  });
});
