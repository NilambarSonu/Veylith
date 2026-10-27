/**
 * Local Authorization and Session Security Manager for Veylith Phase 2C.
 *
 * Implements:
 *   - Per-client session lifecycle management (creation, validation, touch, expiry, destruction)
 *   - Session-scoped authorization policies for permitted tools, resources, and prompts
 *   - Prevention of forged or invalid session identifiers
 *   - Prevention of cross-client session hijacking (identity verification)
 *   - Default-deny / explicit fallback when session authorization is absent
 */

import { randomUUID } from 'node:crypto';
import type { ClientSession } from '@veylith/core';

export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000; // 1 hour

export interface CreateSessionOptions {
  readonly clientIdentity: string;
  readonly serverId: string;
  readonly permittedTools?: readonly string[] | '*';
  readonly permittedResources?: readonly string[] | '*';
  readonly permittedPrompts?: readonly string[] | '*';
  readonly ttlMs?: number;
  readonly metadata?: Record<string, unknown>;
}

export type SessionRejectionReason =
  'not_found' | 'expired' | 'identity_mismatch' | 'invalid_format';

export interface SessionValidationResult {
  readonly valid: boolean;
  readonly session?: ClientSession;
  readonly reason?: SessionRejectionReason;
}

export class ClientSessionManager {
  private readonly sessions = new Map<string, ClientSession>();
  private readonly defaultTtlMs: number;

  constructor(defaultTtlMs: number = DEFAULT_SESSION_TTL_MS) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Establishes a new authenticated/authorized client session.
   */
  createSession(options: CreateSessionOptions): ClientSession {
    if (!options.clientIdentity || options.clientIdentity.trim() === '') {
      throw new Error('clientIdentity is required to create a session');
    }
    if (!options.serverId || options.serverId.trim() === '') {
      throw new Error('serverId is required to create a session');
    }

    const now = Date.now();
    const ttl = options.ttlMs ?? this.defaultTtlMs;
    const sessionId = `vyl-sess-${randomUUID()}`;

    const session: ClientSession = {
      sessionId,
      clientIdentity: options.clientIdentity.trim(),
      serverId: options.serverId.trim(),
      createdAt: now,
      lastAccessedAt: now,
      expiresAt: now + ttl,
      permittedTools: options.permittedTools ?? '*',
      permittedResources: options.permittedResources ?? '*',
      permittedPrompts: options.permittedPrompts ?? '*',
      metadata: options.metadata ? { ...options.metadata } : undefined,
    };

    this.sessions.set(sessionId, session);
    return session;
  }

  /**
   * Validates a session by ID and optionally verifies that the caller identity matches.
   * Updates lastAccessedAt if valid.
   */
  validateSession(
    sessionId: string | undefined,
    expectedClientIdentity?: string,
  ): SessionValidationResult {
    if (!sessionId || typeof sessionId !== 'string' || !sessionId.startsWith('vyl-sess-')) {
      return { valid: false, reason: 'invalid_format' };
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      return { valid: false, reason: 'not_found' };
    }

    const now = Date.now();
    if (now > session.expiresAt) {
      this.sessions.delete(sessionId);
      return { valid: false, reason: 'expired' };
    }

    if (expectedClientIdentity && session.clientIdentity !== expectedClientIdentity) {
      return { valid: false, reason: 'identity_mismatch' };
    }

    // Touch session on active access
    const updated: ClientSession = {
      ...session,
      lastAccessedAt: now,
      expiresAt: now + this.defaultTtlMs,
    };
    this.sessions.set(sessionId, updated);

    return { valid: true, session: updated };
  }

  /**
   * Checks whether a tool invocation is authorized under the active session.
   */
  isToolAuthorized(sessionId: string, toolName: string): boolean {
    const validation = this.validateSession(sessionId);
    if (!validation.valid || !validation.session) return false;

    const { permittedTools } = validation.session;
    if (permittedTools === '*') return true;
    return permittedTools.includes(toolName) || permittedTools.includes('*');
  }

  /**
   * Checks whether a resource read is authorized under the active session.
   */
  isResourceAuthorized(sessionId: string, resourceUri: string): boolean {
    const validation = this.validateSession(sessionId);
    if (!validation.valid || !validation.session) return false;

    const { permittedResources } = validation.session;
    if (permittedResources === '*') return true;
    return permittedResources.some((pattern) => {
      if (pattern === '*' || pattern === resourceUri) return true;
      if (pattern.endsWith('*') && resourceUri.startsWith(pattern.slice(0, -1))) return true;
      return false;
    });
  }

  /**
   * Checks whether a prompt retrieval is authorized under the active session.
   */
  isPromptAuthorized(sessionId: string, promptName: string): boolean {
    const validation = this.validateSession(sessionId);
    if (!validation.valid || !validation.session) return false;

    const { permittedPrompts } = validation.session;
    if (permittedPrompts === '*') return true;
    return permittedPrompts.includes(promptName) || permittedPrompts.includes('*');
  }

  /**
   * Destroys an existing session (explicit client logout or teardown).
   */
  destroySession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Cleans up expired sessions from memory.
   */
  cleanupExpiredSessions(): number {
    const now = Date.now();
    let removed = 0;
    for (const [id, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Returns current count of active sessions.
   */
  getActiveSessionsCount(): number {
    this.cleanupExpiredSessions();
    return this.sessions.size;
  }

  /**
   * Clears all sessions (for testing).
   */
  reset(): void {
    this.sessions.clear();
  }
}
