import { describe, it, expect } from 'vitest';
import {
  getSafeChildEnvironment,
  PROTECTED_GATEWAY_VARS,
  type ServerCredentialPolicy,
} from '../src/security.js';

describe('Veylith Credential Handling & Isolation', () => {
  const syntheticHostEnv: Record<string, string> = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: '/Users/synthetic',
    USER: 'synthetic_user',
    SHELL: '/bin/zsh',
    LANG: 'en_US.UTF-8',
    // Sensitive synthetic host secrets that must never leak by default:
    META_MODEL_API_KEY: 'sk-meta-synthetic-parent-key-12345',
    META_API_KEY: 'sk-meta-synthetic-alt-key-67890',
    OPENAI_API_KEY: 'sk-openai-synthetic-secret-abcdef',
    AWS_SECRET_ACCESS_KEY: 'synthetic-aws-secret-key-11111',
    GITHUB_TOKEN: 'ghp_synthetic_parent_github_token_22222',
    DATABASE_URL: 'postgres://admin:secret@db.internal:5432/prod',
    SYNTHETIC_ALPHA_TOKEN: 'alpha-token-secret-value-33333',
    SYNTHETIC_BETA_KEY: 'beta-key-secret-value-44444',
  };

  it('enforces default-deny: no sensitive credentials inherited by unconfigured servers', () => {
    const env = getSafeChildEnvironment({
      serverId: 'untrusted-mcp-server',
      sourceEnv: syntheticHostEnv,
    });

    // Standard OS vars are inherited
    expect(env['PATH']).toBeDefined();
    expect(env['HOME']).toBeDefined();

    // All sensitive keys are stripped
    expect(env['META_MODEL_API_KEY']).toBeUndefined();
    expect(env['META_API_KEY']).toBeUndefined();
    expect(env['OPENAI_API_KEY']).toBeUndefined();
    expect(env['AWS_SECRET_ACCESS_KEY']).toBeUndefined();
    expect(env['GITHUB_TOKEN']).toBeUndefined();
    expect(env['DATABASE_URL']).toBeUndefined();
    expect(env['SYNTHETIC_ALPHA_TOKEN']).toBeUndefined();
    expect(env['SYNTHETIC_BETA_KEY']).toBeUndefined();
  });

  it('enforces strict credential isolation across two different servers', () => {
    const policies: ServerCredentialPolicy[] = [
      {
        serverId: 'server-alpha-github',
        allowedEnvVars: ['SYNTHETIC_ALPHA_TOKEN'],
      },
      {
        serverId: 'server-beta-database',
        allowedEnvVars: ['SYNTHETIC_BETA_KEY'],
      },
    ];

    // 1. Server Alpha environment
    const alphaEnv = getSafeChildEnvironment({
      serverId: 'server-alpha-github',
      policy: policies,
      sourceEnv: syntheticHostEnv,
    });

    expect(alphaEnv['SYNTHETIC_ALPHA_TOKEN']).toBe('alpha-token-secret-value-33333');
    // Alpha must NOT receive Beta's key or parent secrets
    expect(alphaEnv['SYNTHETIC_BETA_KEY']).toBeUndefined();
    expect(alphaEnv['META_MODEL_API_KEY']).toBeUndefined();
    expect(alphaEnv['DATABASE_URL']).toBeUndefined();

    // 2. Server Beta environment
    const betaEnv = getSafeChildEnvironment({
      serverId: 'server-beta-database',
      policy: policies,
      sourceEnv: syntheticHostEnv,
    });

    expect(betaEnv['SYNTHETIC_BETA_KEY']).toBe('beta-key-secret-value-44444');
    // Beta must NOT receive Alpha's token or parent secrets
    expect(betaEnv['SYNTHETIC_ALPHA_TOKEN']).toBeUndefined();
    expect(betaEnv['META_MODEL_API_KEY']).toBeUndefined();
    expect(betaEnv['GITHUB_TOKEN']).toBeUndefined();
  });

  it('rejects attempts to override protected gateway environment variables', () => {
    for (const protectedVar of Array.from(PROTECTED_GATEWAY_VARS)) {
      expect(() => {
        getSafeChildEnvironment({
          serverId: 'malicious-server',
          customEnv: { [protectedVar]: 'attacker-override' },
          sourceEnv: syntheticHostEnv,
        });
      }).toThrow(`Cannot override protected gateway environment variable '${protectedVar}'`);
    }
  });

  it('produces a clear, sanitized error when a required credential is missing', () => {
    const policy: ServerCredentialPolicy = {
      serverId: 'db-server',
      requiredEnvVars: ['REQUIRED_CUSTOM_DATABASE_KEY'],
      allowedEnvVars: ['REQUIRED_CUSTOM_DATABASE_KEY'],
    };

    expect(() => {
      getSafeChildEnvironment({
        serverId: 'db-server',
        policy,
        sourceEnv: syntheticHostEnv, // Missing REQUIRED_CUSTOM_DATABASE_KEY
      });
    }).toThrow(
      "Missing required credential 'REQUIRED_CUSTOM_DATABASE_KEY' for trusted server 'db-server'",
    );
  });

  it('does not leak secret values in error messages', () => {
    const policy: ServerCredentialPolicy = {
      serverId: 'secure-vault',
      requiredEnvVars: ['VAULT_MASTER_KEY'],
    };

    try {
      getSafeChildEnvironment({
        serverId: 'secure-vault',
        policy,
        sourceEnv: {},
      });
      expect.fail('Should have thrown');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      expect(msg).toContain('VAULT_MASTER_KEY');
      expect(msg).not.toContain('secret');
      expect(msg).not.toContain('sk-');
    }
  });
});
