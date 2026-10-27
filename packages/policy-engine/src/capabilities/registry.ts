/**
 * Tool Capability Registry and Definition Tracking for Veylith.
 *
 * Implements:
 *   1. Explicit capability classifications:
 *      - PURE_OR_READ: pure functions, mathematical calculations, read-only search/fetch
 *      - SHELL_EXEC: terminal/operating system command execution
 *      - FS_MUTATION: filesystem writes, updates, recursive deletes
 *      - SQL_EXEC: database queries, DDL, DML execution
 *      - NETWORK_OUT: outbound HTTP/socket transmission
 *      - UNKNOWN: unverified tools (defaults to conservative restriction)
 *   2. Binding of capabilities to trusted server identity and tool identity.
 *   3. Never trusting unverified self-descriptions or tool annotations.
 *   4. Detecting and quarantining dynamic tool definition mutations (schema/description tampering).
 */

import { createHash } from 'node:crypto';
import type { ToolCapability } from '@veylith/core';

export interface TrustedToolBinding {
  /** The server identity this binding applies to (e.g. 'github-server', 'local-fs', or '*' for global). */
  readonly serverId: string;
  /** The tool name (e.g. 'echo', 'search_codebase', 'run_command', 'query_db'). */
  readonly toolName: string;
  /** The verified capabilities granted to this tool under this server. */
  readonly capability: ToolCapability;
  /** Optional expected definition hash to detect tampering. */
  readonly expectedSchemaHash?: string;
}

export interface ToolDefinitionSnapshot {
  readonly serverId: string;
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
  readonly schemaHash: string;
  readonly firstSeenAt: number;
  readonly lastSeenAt: number;
}

export interface ToolDefinitionInput {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
  readonly annotations?: Record<string, unknown>;
}

export interface DefinitionTrackingResult {
  readonly mutated: boolean;
  readonly isNew: boolean;
  readonly previousHash?: string;
  readonly currentHash: string;
  readonly snapshot: ToolDefinitionSnapshot;
}

/**
 * Computes a deterministic SHA-256 hash of a tool's definition (name, description, inputSchema).
 */
export function computeToolDefinitionHash(tool: {
  name: string;
  description?: string;
  inputSchema?: unknown;
}): string {
  const normalized = {
    name: tool.name,
    description: tool.description ?? '',
    inputSchema: tool.inputSchema ?? {},
  };
  return createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
}

export class ToolCapabilityRegistry {
  private readonly bindings = new Map<string, TrustedToolBinding>();
  private readonly toolDefinitions = new Map<string, ToolDefinitionSnapshot>();

  constructor(initialBindings: readonly TrustedToolBinding[] = []) {
    for (const binding of initialBindings) {
      this.bindCapability(
        binding.serverId,
        binding.toolName,
        binding.capability,
        binding.expectedSchemaHash,
      );
    }
  }

  /**
   * Binds an approved capability to a trusted server identity and tool name.
   */
  bindCapability(
    serverId: string,
    toolName: string,
    capability: ToolCapability,
    expectedSchemaHash?: string,
  ): void {
    const key = `${serverId}:${toolName}`;
    this.bindings.set(key, {
      serverId,
      toolName,
      capability,
      expectedSchemaHash,
    });
  }

  /**
   * Resolves the effective capability for a tool.
   *
   * Security Rule: NEVER trust a tool's self-description or annotation as proof of capability.
   * If not explicitly bound to a trusted server identity, returns 'UNKNOWN'.
   */
  resolveCapability(
    serverId: string | undefined,
    toolName: string,
    _toolMeta?: ToolDefinitionInput,
  ): ToolCapability {
    // 1. Check exact serverId + toolName binding
    if (serverId) {
      const exactKey = `${serverId}:${toolName}`;
      const exactMatch = this.bindings.get(exactKey);
      if (exactMatch) {
        return exactMatch.capability;
      }
    }

    // 2. Check wildcard serverId '*' + toolName binding
    const wildcardKey = `*:${toolName}`;
    const wildcardMatch = this.bindings.get(wildcardKey);
    if (wildcardMatch) {
      return wildcardMatch.capability;
    }

    // 3. Unverified or untrusted tool -> Default conservative 'UNKNOWN'
    return 'UNKNOWN';
  }

  /**
   * Registers an approved baseline tool definition before discovery.
   * Ensures that when the tool is discovered, it must match this baseline hash.
   */
  registerApprovedBaseline(
    serverId: string,
    tool: ToolDefinitionInput | { name: string; schemaHash: string },
  ): void {
    const key = `${serverId}:${tool.name}`;
    const hash = 'schemaHash' in tool ? tool.schemaHash : computeToolDefinitionHash(tool);
    const now = Date.now();
    const snapshot: ToolDefinitionSnapshot = {
      serverId,
      name: tool.name,
      description: 'description' in tool ? tool.description : undefined,
      inputSchema: 'inputSchema' in tool ? tool.inputSchema : undefined,
      schemaHash: hash,
      firstSeenAt: now,
      lastSeenAt: now,
    };
    this.toolDefinitions.set(key, snapshot);
  }

  /**
   * Approves a legitimate tool update (e.g. upgraded schema or docs) by an authorized operator.
   * Updates the baseline hash so that subsequent discoveries do not flag it as mutated.
   */
  approveToolUpdate(
    serverId: string,
    tool: ToolDefinitionInput,
    _auditMetadata?: { readonly approvedBy?: string; readonly reason?: string },
  ): ToolDefinitionSnapshot {
    const key = `${serverId}:${tool.name}`;
    const hash = computeToolDefinitionHash(tool);
    const existing = this.toolDefinitions.get(key);
    const now = Date.now();

    const snapshot: ToolDefinitionSnapshot = {
      serverId,
      name: tool.name,
      description: tool.description,
      inputSchema: tool.inputSchema,
      schemaHash: hash,
      firstSeenAt: existing?.firstSeenAt ?? now,
      lastSeenAt: now,
    };
    this.toolDefinitions.set(key, snapshot);

    // Update expectedSchemaHash on binding if one exists
    const binding = this.bindings.get(key);
    if (binding) {
      this.bindings.set(key, {
        ...binding,
        expectedSchemaHash: hash,
      });
    }

    return snapshot;
  }

  /**
   * Tracks a tool definition during discovery to detect dynamic tampering or schema mutations.
   *
   * Security Rules:
   *   1. If an approved baseline (or expectedSchemaHash) is configured, the tool MUST match it.
   *   2. A malicious tool changing its description or input schema after initial registration
   *      must be detected and quarantined.
   */
  trackDefinition(
    serverId: string | undefined,
    tool: ToolDefinitionInput,
  ): DefinitionTrackingResult {
    const effectiveServerId = serverId ?? 'default';
    const key = `${effectiveServerId}:${tool.name}`;
    const currentHash = computeToolDefinitionHash(tool);
    const existing = this.toolDefinitions.get(key);
    const now = Date.now();

    // Check if an expected baseline hash was specified in trusted bindings
    const binding =
      (serverId ? this.bindings.get(`${serverId}:${tool.name}`) : undefined) ??
      this.bindings.get(`*:${tool.name}`);

    if (binding?.expectedSchemaHash && currentHash !== binding.expectedSchemaHash) {
      return {
        mutated: true,
        isNew: !existing,
        previousHash: binding.expectedSchemaHash,
        currentHash,
        snapshot: existing ?? {
          serverId: effectiveServerId,
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
          schemaHash: binding.expectedSchemaHash,
          firstSeenAt: now,
          lastSeenAt: now,
        },
      };
    }

    if (!existing) {
      const snapshot: ToolDefinitionSnapshot = {
        serverId: effectiveServerId,
        name: tool.name,
        description: tool.description,
        inputSchema: tool.inputSchema,
        schemaHash: currentHash,
        firstSeenAt: now,
        lastSeenAt: now,
      };
      this.toolDefinitions.set(key, snapshot);
      return { mutated: false, isNew: true, currentHash, snapshot };
    }

    if (existing.schemaHash !== currentHash) {
      // Schema or description changed dynamically!
      const previousHash = existing.schemaHash;
      return {
        mutated: true,
        isNew: false,
        previousHash,
        currentHash,
        snapshot: existing,
      };
    }

    // Unchanged definition, update lastSeenAt
    const updated: ToolDefinitionSnapshot = {
      ...existing,
      lastSeenAt: now,
    };
    this.toolDefinitions.set(key, updated);
    return { mutated: false, isNew: false, currentHash, snapshot: updated };
  }

  /**
   * Resets all recorded tool definitions and bindings.
   */
  reset(): void {
    this.bindings.clear();
    this.toolDefinitions.clear();
  }
}
