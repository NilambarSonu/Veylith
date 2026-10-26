/**
 * Deterministic security rules and invariant checks for Veylith.
 *
 * Tier 1 evaluation: fast, zero-latency, auditable in-memory matching.
 * Covers:
 *   - Prohibited tool names
 *   - Destructive shell / OS commands
 *   - Destructive SQL statements
 *   - Path traversal to sensitive system files
 *   - Data exfiltration to untrusted destinations
 *   - Hard prompt-injection trigger directives
 *   - Known credential formats (API keys, private keys, tokens)
 */

import type { ThreatCategory } from '@veylith/core';

export interface RuleMatch {
  readonly ruleId: string;
  readonly threatCategory: ThreatCategory;
  readonly matchedPattern: string;
  readonly description: string;
  readonly location: string;
  readonly snippet: string;
}

export class DeterministicRuleSet {
  // 1. Destructive Shell & OS Commands
  private readonly destructiveShellPatterns: readonly {
    pattern: RegExp;
    id: string;
    desc: string;
  }[] = [
    {
      pattern: /\brm\s+-(?:r[fF]|[fF]r)\s+(?:\/|\*|~\/)/i,
      id: 'rule-shell-rm-rf-root',
      desc: 'Destructive filesystem deletion (rm -rf / or *)',
    },
    {
      pattern: /\bmkfs(?:\.[a-z0-9]+)?\s+/i,
      id: 'rule-shell-mkfs',
      desc: 'Filesystem format command (mkfs)',
    },
    {
      pattern: /\bdd\s+if=.*?of=\/dev\/(?:[sh]d[a-z]|nvme)/i,
      id: 'rule-shell-dd-disk',
      desc: 'Direct raw disk overwrite (dd)',
    },
    {
      pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
      id: 'rule-shell-forkbomb',
      desc: 'Denial of service fork bomb',
    },
    {
      pattern: /\bchmod\s+(?:-R\s+)?777\s+\//i,
      id: 'rule-shell-chmod-777-root',
      desc: 'Unsafe full system permission open (chmod 777 /)',
    },
    {
      pattern: /\bshutdown\s+-(?:h|r)\s+(?:now|0)/i,
      id: 'rule-shell-shutdown',
      desc: 'Host system shutdown command',
    },
  ];

  // 2. Destructive SQL Commands
  private readonly destructiveSqlPatterns: readonly {
    pattern: RegExp;
    id: string;
    desc: string;
  }[] = [
    {
      pattern: /\bDROP\s+(?:TABLE|DATABASE|SCHEMA)\b/i,
      id: 'rule-sql-drop',
      desc: 'Destructive SQL DROP statement',
    },
    {
      pattern: /\bTRUNCATE\s+TABLE\b/i,
      id: 'rule-sql-truncate',
      desc: 'Destructive SQL TRUNCATE statement',
    },
    {
      pattern: /\bDELETE\s+FROM\s+[a-z0-9_]+\s*(?:;|\s*$)/i,
      id: 'rule-sql-unbounded-delete',
      desc: 'Unbounded SQL DELETE without WHERE clause',
    },
  ];

  // 3. Path Traversal toward Sensitive Files
  private readonly sensitiveFilePatterns: readonly { pattern: RegExp; id: string; desc: string }[] =
    [
      {
        pattern: /(?:\.\.\/|\.\.\\){2,}(?:etc\/shadow|etc\/passwd)/i,
        id: 'rule-path-traversal-etc',
        desc: 'Path traversal toward /etc system files',
      },
      {
        pattern: /(?:\.\.\/|\.\.\\)*(?:\.ssh\/(?:id_rsa|id_ed25519|authorized_keys))/i,
        id: 'rule-path-traversal-ssh',
        desc: 'Path access toward SSH private keys or credentials',
      },
      {
        pattern: /(?:\.\.\/|\.\.\\)*(?:\.aws\/credentials|\.env(?:\.local)?)$/i,
        id: 'rule-path-traversal-env',
        desc: 'Path access toward local credentials or .env files',
      },
    ];

  // 4. Data Exfiltration Destinations
  private readonly untrustedDestinations: readonly { pattern: RegExp; id: string; desc: string }[] =
    [
      {
        pattern:
          /https?:\/\/(?:webhook\.site|requestbin\.(?:net|com)|pipedream\.net|ngrok\.io|attacker\.com)/i,
        id: 'rule-exfil-untrusted-endpoint',
        desc: 'Known webhook/exfiltration service endpoint',
      },
      {
        pattern:
          /https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d+)?\/(?:exfil|steal|log|collect)/i,
        id: 'rule-exfil-private-ip',
        desc: 'Outbound exfiltration to private network collector',
      },
    ];

  // 5. Hard Prompt Injection & Directive Overrides
  private readonly promptInjectionDirectives: readonly {
    pattern: RegExp;
    id: string;
    desc: string;
  }[] = [
    {
      pattern: /\bIGNORE\s+(?:ALL\s+)?(?:PRIOR|PREVIOUS)\s+INSTRUCTIONS\b/i,
      id: 'rule-prompt-injection-ignore-instructions',
      desc: 'Instruction override: IGNORE PRIOR INSTRUCTIONS directive',
    },
    {
      pattern: /\bSYSTEM\s+(?:PROMPT|INSTRUCTION)\s*:/i,
      id: 'rule-prompt-injection-system-directive',
      desc: 'Impersonation of system instructions / role spoofing',
    },
    {
      pattern: /\bYOU\s+MUST\s+(?:NOW\s+)?DISCLOSE\b/i,
      id: 'rule-prompt-injection-disclosure',
      desc: 'Coercive secret disclosure command',
    },
    {
      pattern: /\bADMIN(?:ISTRATOR)?\s+OVERRIDE\s*:/i,
      id: 'rule-prompt-injection-admin-override',
      desc: 'Fake administrative override header',
    },
    {
      pattern: /\bDISREGARD\s+(?:USER\s+|SECURITY\s+)?(?:RULES|INSTRUCTIONS)\b/i,
      id: 'rule-prompt-injection-disregard-rules',
      desc: 'Instruction override: DISREGARD RULES/INSTRUCTIONS',
    },
  ];

  // 6. Credential & Secret Leak Patterns
  private readonly credentialLeakPatterns: readonly {
    pattern: RegExp;
    id: string;
    desc: string;
  }[] = [
    {
      pattern: /\bsk-(?:live-|proj-|test-)?[a-zA-Z0-9]{20,}\b/,
      id: 'rule-cred-api-key',
      desc: 'Unredacted API key (e.g. sk-...)',
    },
    {
      pattern: /\bAKIA[0-9A-Z]{16}\b/,
      id: 'rule-cred-aws-key',
      desc: 'Unredacted AWS Access Key ID',
    },
    {
      pattern: /\bgh[pousr]_[a-zA-Z0-9]{36,}\b/,
      id: 'rule-cred-github-token',
      desc: 'Unredacted GitHub Personal Access Token',
    },
    {
      pattern: /-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA|PGP)?\s*PRIVATE\s+KEY-----/,
      id: 'rule-cred-private-key',
      desc: 'Exposed cryptographic private key header',
    },
    {
      pattern: /\bBearer\s+ey[a-zA-Z0-9_-]{20,}\.ey[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b/,
      id: 'rule-cred-jwt',
      desc: 'Raw Authorization Bearer JWT token',
    },
  ];

  /**
   * Scan text or structured data for deterministic rule violations.
   * Recursively traverses objects and arrays.
   */
  scan(
    data: unknown,
    stage: 'discovery' | 'call_arguments' | 'call_response',
    pathPrefix = '',
  ): RuleMatch | null {
    if (data === null || data === undefined) return null;

    if (typeof data === 'string') {
      return this.checkString(data, stage, pathPrefix);
    }

    if (Array.isArray(data)) {
      for (let i = 0; i < data.length; i++) {
        const match = this.scan(data[i], stage, `${pathPrefix}[${i}]`);
        if (match) return match;
      }
      return null;
    }

    if (typeof data === 'object') {
      for (const [key, value] of Object.entries(data)) {
        const currentPath = pathPrefix ? `${pathPrefix}.${key}` : key;
        const match = this.scan(value, stage, currentPath);
        if (match) return match;
      }
    }

    return null;
  }

  private checkString(
    str: string,
    stage: 'discovery' | 'call_arguments' | 'call_response',
    location: string,
  ): RuleMatch | null {
    // Stage: Discovery & Responses -> Check prompt injection directives
    for (const rule of this.promptInjectionDirectives) {
      const match = rule.pattern.exec(str);
      if (match) {
        return {
          ruleId: rule.id,
          threatCategory: stage === 'discovery' ? 'tool_poisoning' : 'malicious_response',
          matchedPattern: match[0],
          description: rule.desc,
          location,
          snippet: this.makeSafeSnippet(str, match.index, match[0].length),
        };
      }
    }

    // Stage: Call Arguments -> Check destructive commands and path traversal
    if (stage === 'call_arguments') {
      for (const rule of this.destructiveShellPatterns) {
        const match = rule.pattern.exec(str);
        if (match) {
          return {
            ruleId: rule.id,
            threatCategory: 'destructive_command',
            matchedPattern: match[0],
            description: rule.desc,
            location,
            snippet: this.makeSafeSnippet(str, match.index, match[0].length),
          };
        }
      }

      for (const rule of this.destructiveSqlPatterns) {
        const match = rule.pattern.exec(str);
        if (match) {
          return {
            ruleId: rule.id,
            threatCategory: 'destructive_command',
            matchedPattern: match[0],
            description: rule.desc,
            location,
            snippet: this.makeSafeSnippet(str, match.index, match[0].length),
          };
        }
      }

      for (const rule of this.sensitiveFilePatterns) {
        const match = rule.pattern.exec(str);
        if (match) {
          return {
            ruleId: rule.id,
            threatCategory: 'suspicious_arguments',
            matchedPattern: match[0],
            description: rule.desc,
            location,
            snippet: this.makeSafeSnippet(str, match.index, match[0].length),
          };
        }
      }
    }

    // Stages: Discovery & Call Arguments -> Check untrusted destinations
    if (stage === 'discovery' || stage === 'call_arguments') {
      for (const rule of this.untrustedDestinations) {
        const match = rule.pattern.exec(str);
        if (match) {
          return {
            ruleId: rule.id,
            threatCategory: stage === 'discovery' ? 'tool_poisoning' : 'suspicious_arguments',
            matchedPattern: match[0],
            description: rule.desc,
            location,
            snippet: this.makeSafeSnippet(str, match.index, match[0].length),
          };
        }
      }
    }

    // All stages -> Check for credential leakage
    for (const rule of this.credentialLeakPatterns) {
      const match = rule.pattern.exec(str);
      if (match) {
        return {
          ruleId: rule.id,
          threatCategory: 'credential_leak',
          matchedPattern: rule.id,
          description: rule.desc,
          location,
          snippet: '[REDACTED_CREDENTIAL_PATTERN]',
        };
      }
    }

    return null;
  }

  private makeSafeSnippet(text: string, index: number, matchLength: number): string {
    const start = Math.max(0, index - 20);
    const end = Math.min(text.length, index + matchLength + 20);
    const raw = text.substring(start, end).replace(/\s+/g, ' ').trim();
    return `...${raw}...`;
  }
}
