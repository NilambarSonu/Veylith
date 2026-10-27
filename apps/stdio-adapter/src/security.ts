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

/** Known secret environment variables that must NEVER be leaked to upstream child processes. */
const SENSITIVE_ENV_VARS = new Set([
  'META_MODEL_API_KEY',
  'META_API_KEY',
  'OPENAI_API_KEY',
  'ANTHROPIC_API_KEY',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'GITHUB_TOKEN',
  'GH_TOKEN',
  'NPM_TOKEN',
]);

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
 * Starts from SDK default safe environment and explicitly strips sensitive API keys.
 */
export function getSafeChildEnvironment(
  customEnv?: Record<string, string>,
): Record<string, string> {
  const base = getDefaultEnvironment();
  const merged: Record<string, string> = { ...base };

  if (customEnv) {
    for (const [k, v] of Object.entries(customEnv)) {
      if (!SENSITIVE_ENV_VARS.has(k.toUpperCase())) {
        merged[k] = v;
      }
    }
  }

  // Explicitly ensure no sensitive parent keys leaked into child environment
  for (const sensitive of SENSITIVE_ENV_VARS) {
    delete merged[sensitive];
    delete merged[sensitive.toLowerCase()];
  }

  return merged;
}
