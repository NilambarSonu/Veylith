/**
 * Security and process lifecycle safeguards for Veylith Stdio Adapter.
 *
 * Implements:
 *   1. Command execution validation (prevents shell injection & dangerous commands)
 *   2. Safe environment inheritance (prevents leaking parent credentials to child tools)
 *   3. Buffer bounds enforcement
 */

import { getDefaultEnvironment } from '@modelcontextprotocol/client/stdio';

/** Default maximum buffer size for stdio read buffers (10 MB). */
export const DEFAULT_MAX_BUFFER_SIZE = 10 * 1024 * 1024;

/** Dangerous shell metacharacters that must not appear in command executable paths. */
const SHELL_METACHARS = /[;&|`$><\n\r]/;

/** Disallowed naked shell binaries that could allow arbitrary command execution. */
const DISALLOWED_SHELLS = new Set([
  'sh',
  'bash',
  'zsh',
  'csh',
  'tcsh',
  'dash',
  'cmd.exe',
  'powershell.exe',
]);

/** Protected gateway environment variables that must NEVER be overridden or injected into child tools. */
export const PROTECTED_GATEWAY_VARS = new Set([
  'GATEWAY_PORT',
  'VEYLITH_GATEWAY_URL',
  'UPSTREAM_MCP_URL',
  'UPSTREAM_COMMAND',
  'FAIL_CLOSED',
  'LOG_LEVEL',
  'META_MODEL_API_KEY',
  'META_API_KEY',
  'META_AI_MODE',
  'META_API_BASE_URL',
  'META_MODEL',
]);

/** Known secret environment variables that must NEVER be leaked to upstream child processes without authorization. */
export const SENSITIVE_ENV_VARS = new Set([
  'META_MODEL_API_KEY',
  'META_API_KEY',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'NPM_TOKEN',
  'DATABASE_URL',
  'POSTGRES_PASSWORD',
  'MYSQL_PWD',
  'SSH_PRIVATE_KEY',
  'API_SECRET',
  'ACCESS_TOKEN',
  'BEARER_TOKEN',
]);

/** Pattern to identify general credential-like environment variable names. */
const CREDENTIAL_NAME_PATTERN = /(_KEY|_TOKEN|_SECRET|_PASSWORD|_AUTH|_PASS)$/i;

export interface ServerCredentialPolicy {
  /** The unique identity of the trusted upstream server (e.g. 'github-server', 'db-server'). */
  readonly serverId: string;
  /** Explicitly allowlisted environment variable names that this server is permitted to receive. */
  readonly allowedEnvVars?: readonly string[];
  /** Required environment variable names. If any are missing from host environment, an error is reported. */
  readonly requiredEnvVars?: readonly string[];
}

export interface SafeChildEnvironmentOptions {
  /** The server identity requesting environment initialization. */
  readonly serverId?: string;
  /** Explicit per-server credential policy, or array of policies. */
  readonly policy?: ServerCredentialPolicy | readonly ServerCredentialPolicy[];
  /** Custom additional environment variables provided specifically for this child process. */
  readonly customEnv?: Record<string, string>;
  /** Source environment map to draw from (defaults to process.env). */
  readonly sourceEnv?: Record<string, string | undefined>;
}

export interface CommandValidationResult {
  valid: boolean;
  reason?: string;
}

/**
 * Validates an upstream command before spawning it as a child process.
 * Prevents shell chaining, command injection, and unapproved execution.
 */
export function validateCommand(command: string, args: string[] = []): CommandValidationResult {
  const trimmedCmd = command.trim();
  if (!trimmedCmd) {
    return { valid: false, reason: 'Command cannot be empty' };
  }

  // Reject shell metacharacters in executable name
  if (SHELL_METACHARS.test(trimmedCmd)) {
    return {
      valid: false,
      reason: `Command executable contains unapproved shell metacharacters: ${trimmedCmd}`,
    };
  }

  // Reject bare shells unless accompanied by a specific script path (not -c)
  const baseName = trimmedCmd.split(/[/|\\]/).pop() ?? trimmedCmd;
  if (DISALLOWED_SHELLS.has(baseName.toLowerCase())) {
    if (args.includes('-c') || args.includes('/c') || args.includes('-e')) {
      return {
        valid: false,
        reason: `Invoking shell '${baseName}' with inline command flags (-c / -e) is strictly prohibited by Veylith`,
      };
    }
  }

  // Check arguments for null bytes or suspicious injection
  for (const arg of args) {
    if (arg.includes('\0')) {
      return { valid: false, reason: 'Command arguments contain null bytes' };
    }
  }

  return { valid: true };
}

/**
 * Returns a sanitized environment map for upstream child processes.
 *
 * Enforces:
 *   1. Default-deny: no sensitive inherited credentials.
 *   2. Per-server credential allowlisting: only authorized variable names are forwarded to matching server.
 *   3. Credential isolation: credentials authorized for Server A are NEVER forwarded to Server B.
 *   4. Rejection of protected gateway variable overrides.
 *   5. Sanitized missing credential error reporting without leaking secret values.
 */
export function getSafeChildEnvironment(
  optionsOrCustomEnv?: Record<string, string> | SafeChildEnvironmentOptions,
): Record<string, string> {
  let serverId: string | undefined;
  let policy: ServerCredentialPolicy | readonly ServerCredentialPolicy[] | undefined;
  let customEnv: Record<string, string> | undefined;
  let sourceEnv: Record<string, string | undefined> = process.env;

  const isExplicitOptions =
    Boolean(optionsOrCustomEnv) &&
    typeof optionsOrCustomEnv === 'object' &&
    ('serverId' in optionsOrCustomEnv ||
      'policy' in optionsOrCustomEnv ||
      'sourceEnv' in optionsOrCustomEnv);

  if (isExplicitOptions) {
    const opts = optionsOrCustomEnv as SafeChildEnvironmentOptions;
    serverId = opts.serverId;
    policy = opts.policy;
    customEnv = opts.customEnv;
    sourceEnv = opts.sourceEnv ?? process.env;
  } else if (optionsOrCustomEnv) {
    customEnv = optionsOrCustomEnv as Record<string, string>;
  }

  // Find matching server policy if configured
  let matchingPolicy: ServerCredentialPolicy | undefined;
  if (policy) {
    if (Array.isArray(policy)) {
      matchingPolicy = policy.find((p) => p.serverId === serverId);
    } else {
      const singlePolicy = policy as ServerCredentialPolicy;
      if (singlePolicy.serverId === serverId) {
        matchingPolicy = singlePolicy;
      }
    }
  }

  // 1. Verify required credentials if specified in policy
  if (matchingPolicy?.requiredEnvVars) {
    for (const reqVar of matchingPolicy.requiredEnvVars) {
      const val = customEnv?.[reqVar] ?? sourceEnv[reqVar];
      if (val === undefined || val === '') {
        throw new Error(
          `Missing required credential '${reqVar}' for trusted server '${matchingPolicy.serverId}'`,
        );
      }
    }
  }

  // 2. Reject attempts to override protected gateway environment variables
  if (customEnv && isExplicitOptions) {
    for (const key of Object.keys(customEnv)) {
      if (PROTECTED_GATEWAY_VARS.has(key.toUpperCase())) {
        throw new Error(`Cannot override protected gateway environment variable '${key}'`);
      }
    }
  }

  // 3. Start from official MCP SDK default safe baseline (standard OS vars)
  const base = getDefaultEnvironment();
  const merged: Record<string, string> = { ...base };

  const allowedSet = new Set(matchingPolicy?.allowedEnvVars?.map((v) => v.toUpperCase()) ?? []);

  // 4. Inherit authorized allowlisted variables from source environment (e.g. process.env)
  if (matchingPolicy?.allowedEnvVars) {
    for (const allowedVar of matchingPolicy.allowedEnvVars) {
      if (PROTECTED_GATEWAY_VARS.has(allowedVar.toUpperCase())) {
        continue; // Never inherit protected gateway internal variables
      }
      const val = sourceEnv[allowedVar];
      if (val !== undefined) {
        merged[allowedVar] = val;
      }
    }
  }

  // 5. Merge customEnv variables with default-deny filtering
  if (customEnv) {
    for (const [k, v] of Object.entries(customEnv)) {
      const upper = k.toUpperCase();
      const isSensitive = SENSITIVE_ENV_VARS.has(upper) || CREDENTIAL_NAME_PATTERN.test(upper);

      if (isSensitive) {
        // Only allow if explicitly authorized for this server
        if (allowedSet.has(upper)) {
          merged[k] = v;
        }
      } else {
        // Non-sensitive variable
        merged[k] = v;
      }
    }
  }

  // 6. Final safety scrubbing: remove any protected gateway variables or unauthorized secrets
  for (const key of Object.keys(merged)) {
    const upper = key.toUpperCase();
    if (PROTECTED_GATEWAY_VARS.has(upper)) {
      delete merged[key];
      continue;
    }

    const isSensitive = SENSITIVE_ENV_VARS.has(upper) || CREDENTIAL_NAME_PATTERN.test(upper);
    if (isSensitive && !allowedSet.has(upper)) {
      delete merged[key];
    }
  }

  return merged;
}
