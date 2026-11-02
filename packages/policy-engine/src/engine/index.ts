/**
 * Veylith Hybrid Security Inspection Engine (Phase 2C).
 *
 * Coordinates:
 *   - Tier 1: Deterministic rules (hard invariants, sub-millisecond, unoverrideable)
 *   - Tier 2: Heuristic risk screener (triages clean vs ambiguous content)
 *   - Tier 3: Meta Muse semantic model (evaluates complex ambiguous prompts)
 *
 * Enforces policy decisions and session authorization across:
 *   1. Tools Discovery (tools/list)
 *   2. Tool Invocations (tools/call) with TOCTOU baseline checks
 *   3. Tool Responses (tools/call returned data)
 *   4. Resources Discovery (resources/list & resources/templates/list)
 *   5. Resource Content (resources/read) with binary & size policy
 *   6. Prompts Discovery (prompts/list)
 *   7. Prompt Messages (prompts/get)
 *
 * All decisions produce cryptographically chained, tamper-evident audit records.
 */

import { randomUUID } from 'node:crypto';
import type {
  SecurityInspectionResult,
  InspectionContext,
  PolicyRule,
  ThreatCategory,
  PolicyAction,
  ResourceMetadataInput,
  ResourceTemplateInput,
  ResourceContentItem,
  PromptMetadataInput,
  PromptMessageItem,
} from '@veylith/core';
import type { MetaAdapter } from '@veylith/meta-adapter';
import { DeterministicRuleSet } from '../rules/deterministic.js';
import { BoundaryInspector } from '../routing/inspector.js';
import { InspectionCache } from '../cache/inspection-cache.js';
import {
  ToolCapabilityRegistry,
  toolMetadataText,
  type TrustedToolBinding,
} from '../capabilities/registry.js';
import { ClientSessionManager } from '../sessions/manager.js';
import { AuditLogChain } from '../audit/chain.js';

export interface SecurityEngineOptions {
  readonly policyVersion?: string;
  readonly failClosed?: boolean;
  readonly useCache?: boolean;
  readonly defaultDecision?: PolicyAction;
  readonly capabilityRegistry?: ToolCapabilityRegistry;
  readonly capabilityBindings?: readonly TrustedToolBinding[];
  readonly sessionManager?: ClientSessionManager;
  readonly auditChain?: AuditLogChain;
  readonly maxResourceContentBytes?: number;
  readonly allowBinaryResources?: boolean;
}

export interface ToolMetadataInput {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema?: unknown;
}

export interface DiscoveryInspectionOutcome {
  readonly cleanTools: readonly ToolMetadataInput[];
  readonly blockedTools: readonly {
    readonly name: string;
    readonly reason: string;
    readonly threatCategory: ThreatCategory;
  }[];
  readonly results: readonly SecurityInspectionResult[];
}

export interface ResponseInspectionOutcome {
  readonly result: SecurityInspectionResult;
  readonly sanitizedContent: readonly { readonly type: string; readonly text?: string }[];
  readonly isRedacted: boolean;
}

export interface ResourceDiscoveryOutcome {
  readonly cleanResources: readonly ResourceMetadataInput[];
  readonly cleanTemplates: readonly ResourceTemplateInput[];
  readonly blockedResources: readonly {
    readonly uri: string;
    readonly name: string;
    readonly reason: string;
    readonly threatCategory: ThreatCategory;
  }[];
  readonly results: readonly SecurityInspectionResult[];
}

export interface ResourceContentOutcome {
  readonly sanitizedItems: readonly ResourceContentItem[];
  readonly isRedacted: boolean;
  readonly isBlocked: boolean;
  readonly blockReason?: string;
  readonly threatCategory: ThreatCategory;
  readonly results: readonly SecurityInspectionResult[];
}

export interface PromptDiscoveryOutcome {
  readonly cleanPrompts: readonly PromptMetadataInput[];
  readonly blockedPrompts: readonly {
    readonly name: string;
    readonly reason: string;
    readonly threatCategory: ThreatCategory;
  }[];
  readonly results: readonly SecurityInspectionResult[];
}

export interface PromptMessagesOutcome {
  readonly sanitizedMessages: readonly PromptMessageItem[];
  readonly isRedacted: boolean;
  readonly isBlocked: boolean;
  readonly blockReason?: string;
  readonly threatCategory: ThreatCategory;
  readonly results: readonly SecurityInspectionResult[];
}

export class SecurityInspectionEngine {
  private readonly deterministicRules = new DeterministicRuleSet();
  public readonly boundary: BoundaryInspector;
  private readonly cache: InspectionCache;
  private readonly policyRules: readonly PolicyRule[];
  private readonly metaAdapter: MetaAdapter;
  private readonly policyVersion: string;
  private readonly failClosed: boolean;
  private readonly defaultDecision: PolicyAction;
  public readonly capabilityRegistry: ToolCapabilityRegistry;
  public readonly sessionManager: ClientSessionManager;
  public readonly auditChain: AuditLogChain;
  private readonly maxResourceContentBytes: number;
  private readonly allowBinaryResources: boolean;

  constructor(
    policyRules: readonly PolicyRule[] = [],
    metaAdapter: MetaAdapter,
    options?: SecurityEngineOptions,
  ) {
    this.policyRules = policyRules;
    this.metaAdapter = metaAdapter;
    this.policyVersion = options?.policyVersion ?? 'v2f.1';
    this.failClosed = options?.failClosed ?? true;
    this.defaultDecision = options?.defaultDecision ?? 'allow';
    this.cache = new InspectionCache(500, 60000);
    this.capabilityRegistry =
      options?.capabilityRegistry ?? new ToolCapabilityRegistry(options?.capabilityBindings ?? []);
    this.sessionManager = options?.sessionManager ?? new ClientSessionManager();
    this.boundary = new BoundaryInspector(
      metaAdapter,
      this.capabilityRegistry,
      this.sessionManager,
      this.policyVersion,
      this.failClosed,
      this.defaultDecision,
    );
    this.auditChain = options?.auditChain ?? new AuditLogChain();
    this.maxResourceContentBytes = options?.maxResourceContentBytes ?? 5 * 1024 * 1024;
    this.allowBinaryResources = options?.allowBinaryResources ?? false;
  }

  getRoutingMetrics() {
    return this.boundary.stats();
  }
  /** Only trusted operator code may pin exact content; upstream hints and labels never approve it. */
  approveTrustedContent(
    serverId: string,
    stage: InspectionContext['stage'],
    target: string,
    content: string,
  ) {
    this.boundary.router.approve(serverId, stage, target, content);
  }
  /**
   * Records an audit event in the tamper-evident hash chain.
   */
  private recordAudit(
    res: SecurityInspectionResult,
    mcpMethod: string,
    targetName: string | undefined,
    ctx?:
      | InspectionContext
      | {
          readonly serverId?: string;
          readonly clientIdentity?: string;
          readonly sessionId?: string;
        },
  ): void {
    const serverId = ctx?.serverId ?? 'unknown-server';
    const clientIdentity = ctx?.clientIdentity;
    const sessionId = ctx?.sessionId;

    this.auditChain.append({
      sessionId,
      serverId,
      clientIdentity,
      mcpMethod,
      targetName,
      stage: res.stage,
      decision: res.action,
      reasonCode: res.ruleId ?? res.threatCategory,
      policyVersion: this.policyVersion,
      modelId: res.modelId,
      latencyMs: res.evaluationDurationMs,
      routing: res.routing ?? {
        decision: res.action === 'block' ? 'deterministically_blocked' : 'verified_safe_fast_path',
        reason: 'authorization-capability-or-explicit-policy',
        origin: res.stage === 'call_arguments' ? 'client' : 'upstream',
        capability: 'UNKNOWN',
        inputBytes: 0,
        contextIncluded: false,
      },
      tokenUsage: res.tokenUsage,
    });
  }

  /**
   * 1. Inspect tool metadata during tools/list discovery.
   * Identifies tool-description poisoning, dynamic schema mutations, and static blocks.
   */
  async inspectDiscovery(
    tools: readonly ToolMetadataInput[],
    clientOrContext?:
      | string
      | {
          readonly serverId?: string;
          readonly clientIdentity?: string;
          readonly sessionId?: string;
        },
  ): Promise<DiscoveryInspectionOutcome> {
    const routingRequestId = randomUUID();
    const serverId = typeof clientOrContext === 'object' ? clientOrContext.serverId : undefined;
    const clientIdentity =
      typeof clientOrContext === 'string' ? clientOrContext : clientOrContext?.clientIdentity;
    const sessionId = typeof clientOrContext === 'object' ? clientOrContext.sessionId : undefined;
    const cleanTools: ToolMetadataInput[] = [];
    const blockedTools: { name: string; reason: string; threatCategory: ThreatCategory }[] = [];
    const results: SecurityInspectionResult[] = [];

    // Session validation if sessionId provided
    if (sessionId) {
      const sessVal = this.sessionManager.validateSession(sessionId, clientIdentity, serverId);
      if (!sessVal.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${sessionId}' is invalid or expired (reason: ${sessVal.reason})`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'tools/list', undefined, { serverId, clientIdentity, sessionId });
        return {
          cleanTools: [],
          blockedTools: tools.map((t) => ({
            name: t.name,
            reason: res.explanation,
            threatCategory: 'unauthorized_access',
          })),
          results: [res],
        };
      }
    }

    for (const tool of tools) {
      // Session tool authorization check
      if (sessionId && !this.sessionManager.isToolAuthorized(sessionId, tool.name)) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_authorization', snippet: tool.name, location: 'toolName' }],
          explanation: `Tool '${tool.name}' is not permitted under session '${sessionId}'`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: 'unauthorized_access',
        });
        this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      // Check if tool name is explicitly blocked by configured deterministic rules
      const staticRule = this.policyRules.find(
        (r) =>
          r.enabled &&
          (r.method === '*' || r.method === 'tools/list') &&
          (r.toolName === tool.name || r.toolName === '*') &&
          r.decision === 'block',
      );

      if (staticRule) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'none',
          evidence: [{ type: 'static_rule', snippet: tool.name, location: 'toolName' }],
          explanation: `Tool '${tool.name}' blocked by static policy rule '${staticRule.id}'`,
          ruleId: staticRule.id,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({ name: tool.name, reason: res.explanation, threatCategory: 'none' });
        this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      // Check for dynamic definition mutations (schema/description tampering after registration)
      const trackResult = this.capabilityRegistry.trackDefinition(serverId, tool);
      if (trackResult.mutated) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'discovery',
          action: 'block',
          threatCategory: 'tool_poisoning',
          evidence: [
            {
              type: 'definition_mutation',
              snippet: `Hash changed from ${trackResult.previousHash?.slice(0, 12)} to ${trackResult.currentHash.slice(0, 12)}`,
              location: 'tool_metadata',
            },
          ],
          explanation: trackResult.capacityExceeded
            ? 'Tool definition tracking capacity reached; new tool quarantined'
            : `Tool definition mutated: Description or schema for tool '${tool.name}' was modified after initial registration. Quarantined to prevent dynamic prompt injection or unauthorized capability expansion.`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: 'tool_poisoning',
        });
        this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      // Tier 1 & 2: Screen description and schema
      const inspectTarget = toolMetadataText(tool);
      if (serverId && this.capabilityRegistry.isPinnedDefinition(serverId, tool))
        this.approveTrustedContent(serverId, 'discovery', tool.name, inspectTarget);
      const screenVerdict = this.boundary.screen(inspectTarget, 'discovery', tool.name, {
        serverId,
        clientIdentity,
        sessionId,
      });

      if (screenVerdict.type === 'hard_violation') {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          routing: screenVerdict.routing,
          stage: 'discovery',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: screenVerdict.match.location || 'description',
            },
          ],
          explanation: `Tool description poisoning detected: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: 0.2,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: res.threatCategory,
        });
        this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      if (screenVerdict.type === 'clean') {
        // Fast path: clean
        cleanTools.push(tool);
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          routing: screenVerdict.routing,
          stage: 'discovery',
          action: 'allow',
          threatCategory: 'none',
          evidence: [],
          explanation: 'Tool metadata verified clean by deterministic screener',
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: false,
        };
        results.push(res);
        this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      // Ambiguous -> Tier 3: Meta Muse Semantic Inspection
      const cacheKey = this.cache.generateKey({
        payload: screenVerdict.payload,
        stage: 'discovery',
        policyVersion: this.policyVersion,
        modelVersion: `${this.metaAdapter.mode}:${this.metaAdapter.model}`,
        baselineRevision: this.capabilityRegistry.baselineRevision,
        clientId: clientIdentity,
        serverId,
        sessionId,
        toolName: tool.name,
      });
      const cached = this.cache.get(cacheKey);

      if (cached) {
        this.boundary.cacheHit();
        results.push(cached);
        if (cached.action === 'block') {
          blockedTools.push({
            name: tool.name,
            reason: cached.explanation,
            threatCategory: cached.threatCategory,
          });
        } else {
          cleanTools.push(tool);
        }
        this.recordAudit(cached, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });
        continue;
      }

      const modelResult = await this.boundary.infer(
        screenVerdict.payload,
        'discovery',
        screenVerdict.routing,
        routingRequestId,
        {
          toolName: tool.name,
        },
      );

      let finalAction: PolicyAction = modelResult.flagged
        ? modelResult.action
        : this.defaultDecision;
      let finalExplanation = modelResult.explanation;

      // Fail-closed risk-based fallback: High-risk unverified operations MUST NOT pass when AI provider fails
      if (
        modelResult.action === 'review' &&
        screenVerdict.type === 'ambiguous' &&
        screenVerdict.riskLevel === 'high'
      ) {
        finalAction = 'block';
        finalExplanation = `High-risk tool discovery quarantined: Security classifier unavailable while metadata exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
      }

      const res: SecurityInspectionResult = {
        id: randomUUID(),
        routing: this.boundary.effectiveRoute(screenVerdict.routing, modelResult),
        stage: 'discovery',
        action: finalAction,
        threatCategory:
          finalAction === 'block' && modelResult.threatCategory === 'none'
            ? 'tool_poisoning'
            : modelResult.threatCategory,
        evidence: modelResult.evidence.map((ev) => ({
          type: 'semantic_inference',
          snippet: ev,
          location: 'tool_metadata',
        })),
        explanation: finalExplanation,
        modelId: modelResult.mode === 'disabled' ? undefined : this.metaAdapter.model,
        evaluationDurationMs: modelResult.durationMs,
        tokenUsage: modelResult.tokenUsage,
        origin:
          modelResult.mode === 'mock'
            ? 'mock'
            : modelResult.mode === 'disabled'
              ? 'deterministic'
              : 'live',
        confidence: modelResult.confidence,
        isConfirmedViolation: modelResult.flagged && modelResult.action === 'block',
      };

      if (modelResult.action !== 'review') this.cache.set(cacheKey, res);
      results.push(res);
      this.recordAudit(res, 'tools/list', tool.name, { serverId, clientIdentity, sessionId });

      if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
        blockedTools.push({
          name: tool.name,
          reason: res.explanation,
          threatCategory: res.threatCategory,
        });
      } else {
        cleanTools.push(tool);
      }
    }

    return { cleanTools, blockedTools, results };
  }

  /**
   * 2. Inspect invocation arguments during tools/call.
   * Includes session validation and TOCTOU consistency verification.
   */
  async inspectArguments(
    ctx: InspectionContext,
    toolName: string,
    args: Record<string, unknown>,
    currentDefinition?: ToolMetadataInput,
  ): Promise<SecurityInspectionResult> {
    const start = performance.now();

    // 1. Session validation (if sessionId is present)
    if (ctx.sessionId) {
      const sessionCheck = this.sessionManager.validateSession(
        ctx.sessionId,
        ctx.clientIdentity,
        ctx.serverId,
      );
      if (!sessionCheck.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'call_arguments',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: ctx.sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${ctx.sessionId}' is invalid or expired (reason: ${sessionCheck.reason})`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'tools/call', toolName, ctx);
        return res;
      }

      // Check tool permission in session
      if (!this.sessionManager.isToolAuthorized(ctx.sessionId, toolName, ctx.serverId)) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'call_arguments',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_authorization', snippet: toolName, location: 'toolName' }],
          explanation: `Unauthorized tool: Tool '${toolName}' is not permitted under session '${ctx.sessionId}'`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'tools/call', toolName, ctx);
        return res;
      }
    }

    // 2. TOCTOU baseline check: verify tool metadata matches approved baseline
    if (ctx.serverId && currentDefinition) {
      const toctouCheck = this.capabilityRegistry.verifyInvocationConsistency(
        ctx.serverId,
        toolName,
        currentDefinition,
      );
      if (!toctouCheck.consistent) {
        const expectedHash = toctouCheck.expectedHash ?? 'none';
        const currentHash = toctouCheck.currentHash ?? 'unknown';
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'call_arguments',
          action: 'block',
          threatCategory: 'tool_poisoning',
          evidence: [
            {
              type: 'definition_mutation',
              snippet: `Current hash ${currentHash.slice(0, 12)} does not match approved baseline ${expectedHash.slice(0, 12)}`,
              location: 'tool_definition',
            },
          ],
          explanation: `TOCTOU violation detected: Tool '${toolName}' definition changed between discovery and invocation. Expected baseline hash ${expectedHash.slice(0, 12)}, observed ${currentHash.slice(0, 12)}. Quarantined to prevent capability escalation.`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'tools/call', toolName, ctx);
        return res;
      }
    }

    // Check static policy rules (e.g. BLOCKED_TOOLS)
    const staticRule = this.policyRules.find(
      (r) => r.enabled && (r.toolName === toolName || r.toolName === '*') && r.decision === 'block',
    );

    if (staticRule) {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'call_arguments',
        action: 'block',
        threatCategory: 'none',
        evidence: [{ type: 'static_rule', snippet: toolName, location: 'toolName' }],
        explanation: `Veylith policy blocked this call: Matched rule '${staticRule.id}': ${staticRule.description}`,
        ruleId: staticRule.id,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };
      this.recordAudit(res, 'tools/call', toolName, ctx);
      return res;
    }

    // Resolve tool capability strictly from trusted registry bound to serverId
    const capability = this.capabilityRegistry.resolveCapability(ctx.serverId, toolName);

    // Tier 1 & 2: Screen arguments (capability-aware)
    const screenVerdict = this.boundary.screen(args, 'call_arguments', toolName, ctx, capability);

    if (screenVerdict.type === 'hard_violation') {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
        routing: screenVerdict.routing,
        stage: 'call_arguments',
        action: 'block',
        threatCategory: screenVerdict.match.threatCategory,
        evidence: [
          {
            type: 'deterministic_rule',
            matchedPattern: screenVerdict.match.matchedPattern,
            snippet: screenVerdict.match.snippet,
            location: screenVerdict.match.location,
          },
        ],
        explanation: `Dangerous arguments blocked: ${screenVerdict.match.description}`,
        ruleId: screenVerdict.match.ruleId,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };
      this.recordAudit(res, 'tools/call', toolName, ctx);
      return res;
    }

    if (screenVerdict.type === 'clean') {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
        routing: screenVerdict.routing,
        stage: 'call_arguments',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Arguments screened clean by deterministic rules',
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
      this.recordAudit(res, 'tools/call', toolName, ctx);
      return res;
    }

    // Tier 3: Ambiguous arguments -> Semantic model check
    const serializedArgs = screenVerdict.payload;
    const cacheKey = this.cache.generateKey({
      payload: serializedArgs,
      stage: 'call_arguments',
      policyVersion: this.policyVersion,
      modelVersion: `${this.metaAdapter.mode}:${this.metaAdapter.model}`,
      baselineRevision: this.capabilityRegistry.baselineRevision,
      clientId: ctx.clientIdentity,
      serverId: ctx.serverId,
      sessionId: ctx.sessionId,
      toolName,
    });
    const cached = this.cache.get(cacheKey);
    if (cached) {
      this.boundary.cacheHit();
      this.recordAudit(cached, 'tools/call', toolName, ctx);
      return cached;
    }

    const modelResult = await this.boundary.infer(
      serializedArgs,
      'call_arguments',
      screenVerdict.routing,
      ctx.requestId,
      {
        toolName,
      },
    );

    let finalAction: PolicyAction = modelResult.flagged ? modelResult.action : this.defaultDecision;
    let finalExplanation = modelResult.explanation;

    // Fail-closed risk-based fallback: High-risk unverified operations MUST NOT pass when AI provider fails
    if (
      modelResult.action === 'review' &&
      screenVerdict.type === 'ambiguous' &&
      screenVerdict.riskLevel === 'high'
    ) {
      finalAction = 'block';
      finalExplanation = `High-risk arguments quarantined: Security classifier unavailable while arguments exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
    }

    const res: SecurityInspectionResult = {
      id: randomUUID(),
      routing: this.boundary.effectiveRoute(screenVerdict.routing, modelResult),
      stage: 'call_arguments',
      action: finalAction,
      threatCategory:
        finalAction === 'block' && modelResult.threatCategory === 'none'
          ? 'suspicious_arguments'
          : modelResult.threatCategory,
      evidence: modelResult.evidence.map((ev) => ({
        type: 'semantic_inference',
        snippet: ev,
        location: 'args',
      })),
      explanation: finalExplanation,
      modelId: modelResult.mode === 'disabled' ? undefined : this.metaAdapter.model,
      evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
      tokenUsage: modelResult.tokenUsage,
      origin:
        modelResult.mode === 'mock'
          ? 'mock'
          : modelResult.mode === 'disabled'
            ? 'deterministic'
            : 'live',
      confidence: modelResult.confidence,
      isConfirmedViolation: modelResult.flagged && modelResult.action === 'block',
    };

    if (modelResult.action !== 'review') this.cache.set(cacheKey, res);
    this.recordAudit(res, 'tools/call', toolName, ctx);
    return res;
  }

  /**
   * 3. Inspect tool response before returning downstream.
   * Intercepts indirect prompt injection in tool outputs and redacts if dangerous.
   */
  async inspectResponse(
    ctx: InspectionContext,
    toolName: string,
    content: readonly { readonly type: string; readonly text?: string }[],
  ): Promise<ResponseInspectionOutcome> {
    const pieces = content
      .filter((c) => c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text!);
    const result = await this.boundary.classify(
      ctx,
      toolName,
      pieces,
      content.every((c) => c.type === 'text' && typeof c.text === 'string'),
    );
    this.recordAudit(result, 'tools/call', toolName, ctx);
    const isRedacted = result.action === 'block' || (result.action === 'review' && this.failClosed);
    return {
      result,
      isRedacted,
      sanitizedContent: isRedacted
        ? [
            {
              type: 'text',
              text: `[Veylith Security Notice]: Tool response from '${toolName}' quarantined. Reason: ${result.explanation}`,
            },
          ]
        : content,
    };
  }

  /**
   * 4. Inspect resource discovery (resources/list and resources/templates/list).
   * Checks resource metadata, injection in descriptions, and session permissions.
   */
  async inspectResourceDiscovery(
    resources: readonly ResourceMetadataInput[],
    templates: readonly ResourceTemplateInput[] = [],
    ctx?: InspectionContext,
  ): Promise<ResourceDiscoveryOutcome> {
    const cleanResources: ResourceMetadataInput[] = [];
    const cleanTemplates: ResourceTemplateInput[] = [];
    const blockedResources: {
      uri: string;
      name: string;
      reason: string;
      threatCategory: ThreatCategory;
    }[] = [];
    const results: SecurityInspectionResult[] = [];

    // Session validation if sessionId provided
    if (ctx?.sessionId) {
      const sessVal = this.sessionManager.validateSession(
        ctx.sessionId,
        ctx.clientIdentity,
        ctx.serverId,
      );
      if (!sessVal.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: ctx.sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${ctx.sessionId}' is invalid or expired (reason: ${sessVal.reason})`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'resources/list', undefined, ctx);
        return {
          cleanResources: [],
          cleanTemplates: [],
          blockedResources: resources.map((r) => ({
            uri: r.uri,
            name: r.name,
            reason: res.explanation,
            threatCategory: 'unauthorized_access',
          })),
          results: [res],
        };
      }
    }

    // Inspect individual resources
    for (const res of resources) {
      if (ctx?.sessionId && !this.sessionManager.isResourceAuthorized(ctx.sessionId, res.uri)) {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_authorization', snippet: res.uri, location: 'uri' }],
          explanation: `Resource '${res.uri}' is not permitted under session '${ctx.sessionId}'`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(result);
        blockedResources.push({
          uri: res.uri,
          name: res.name,
          reason: result.explanation,
          threatCategory: 'unauthorized_access',
        });
        this.recordAudit(result, 'resources/list', res.uri, ctx);
        continue;
      }

      const inspectTarget = `${res.name} ${res.description ?? ''} ${res.uri}`;
      const screenVerdict = this.boundary.screen(inspectTarget, 'resource_discovery', res.uri, ctx);

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
          routing: screenVerdict.routing,
          stage: 'resource_discovery',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: 'resource_metadata',
            },
          ],
          explanation: `Resource metadata poisoning detected: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(result);
        blockedResources.push({
          uri: res.uri,
          name: res.name,
          reason: result.explanation,
          threatCategory: result.threatCategory,
        });
        this.recordAudit(result, 'resources/list', res.uri, ctx);
        continue;
      }

      if (screenVerdict.type === 'ambiguous') {
        const review = await this.boundary.classify(
          {
            requestId: randomUUID(),
            stage: 'resource_discovery',
            method: 'resources/list',
            timestamp: new Date().toISOString(),
            ...ctx,
          },
          res.uri,
          [inspectTarget],
          true,
          screenVerdict,
        );
        results.push(review);
        this.recordAudit(review, 'resources/list', res.uri, ctx);
        if (review.action === 'block' || (review.action === 'review' && this.failClosed)) {
          blockedResources.push({
            uri: res.uri,
            name: res.name,
            reason: review.explanation,
            threatCategory: review.threatCategory,
          });
          continue;
        }
        cleanResources.push(res);
        continue;
      }
      cleanResources.push(res);
      const allowResult: SecurityInspectionResult = {
        id: randomUUID(),
        routing: screenVerdict.routing,
        stage: 'resource_discovery',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Resource metadata clean',
        evaluationDurationMs: 0.1,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
      results.push(allowResult);
      this.recordAudit(allowResult, 'resources/list', res.uri, ctx);
    }

    // Inspect templates
    for (const tpl of templates) {
      const inspectTarget = `${tpl.name} ${tpl.description ?? ''} ${tpl.uriTemplate}`;
      const screenVerdict = this.boundary.screen(
        inspectTarget,
        'resource_discovery',
        tpl.uriTemplate,
        ctx,
      );

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
          routing: screenVerdict.routing,
          stage: 'resource_discovery',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: 'template_metadata',
            },
          ],
          explanation: `Resource template poisoning detected: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(result);
        this.recordAudit(result, 'resources/templates/list', tpl.uriTemplate, ctx);
        continue;
      }

      if (screenVerdict.type === 'ambiguous') {
        const review = await this.boundary.classify(
          {
            requestId: randomUUID(),
            stage: 'resource_discovery',
            method: 'resources/list',
            timestamp: new Date().toISOString(),
            ...ctx,
          },
          tpl.uriTemplate,
          [inspectTarget],
          true,
          screenVerdict,
        );
        results.push(review);
        this.recordAudit(review, 'resources/list', tpl.uriTemplate, ctx);
        if (review.action === 'block' || (review.action === 'review' && this.failClosed)) {
          continue;
        }
        cleanTemplates.push(tpl);
        continue;
      }
      cleanTemplates.push(tpl);
    }

    return { cleanResources, cleanTemplates, blockedResources, results };
  }

  /**
   * 5. Inspect resource content during resources/read.
   * Enforces content-size exhaustion limits, binary handling policy, and prompt injection detection.
   */
  async inspectResourceContent(
    ctx: InspectionContext,
    uri: string,
    items: readonly ResourceContentItem[],
  ): Promise<ResourceContentOutcome> {
    const start = performance.now();

    // Session validation
    if (ctx.sessionId) {
      const sessionCheck = this.sessionManager.validateSession(
        ctx.sessionId,
        ctx.clientIdentity,
        ctx.serverId,
      );
      if (!sessionCheck.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_content',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: ctx.sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${ctx.sessionId}' is invalid or expired (reason: ${sessionCheck.reason})`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'resources/read', uri, ctx);
        return {
          sanitizedItems: [],
          isRedacted: false,
          isBlocked: true,
          blockReason: res.explanation,
          threatCategory: 'unauthorized_access',
          results: [res],
        };
      }

      if (!this.sessionManager.isResourceAuthorized(ctx.sessionId, uri, ctx.serverId)) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_content',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_authorization', snippet: uri, location: 'uri' }],
          explanation: `Unauthorized resource: Resource '${uri}' is not permitted under session '${ctx.sessionId}'`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'resources/read', uri, ctx);
        return {
          sanitizedItems: [],
          isRedacted: false,
          isBlocked: true,
          blockReason: res.explanation,
          threatCategory: 'unauthorized_access',
          results: [res],
        };
      }
    }

    // Total content size check to prevent output exhaustion / DoS
    let totalBytes = 0;
    for (const item of items) {
      if (typeof item.text === 'string') {
        totalBytes += Buffer.byteLength(item.text, 'utf8');
      } else if (typeof item.blob === 'string') {
        totalBytes += Math.round((item.blob.length * 3) / 4); // Base64 approximate byte length
      }
    }

    if (totalBytes > this.maxResourceContentBytes) {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'resource_content',
        action: 'block',
        threatCategory: 'resource_poisoning',
        evidence: [
          {
            type: 'size_limit_exceeded',
            snippet: `${totalBytes} bytes > ${this.maxResourceContentBytes} bytes maximum limit`,
            location: 'resource_content',
          },
        ],
        explanation: `Resource content size limit exceeded (${totalBytes} bytes exceeds ${this.maxResourceContentBytes} bytes maximum). Request blocked to prevent memory exhaustion.`,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };
      this.recordAudit(res, 'resources/read', uri, ctx);
      return {
        sanitizedItems: [],
        isRedacted: false,
        isBlocked: true,
        blockReason: res.explanation,
        threatCategory: 'resource_poisoning',
        results: [res],
      };
    }

    if (items.some((item) => item.blob !== undefined) && !this.allowBinaryResources) {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'resource_content',
        action: 'block',
        threatCategory: 'uninspected_binary',
        evidence: [],
        explanation:
          'Uninspected binary payload rejected: explicit binary inspection policy required',
        evaluationDurationMs: performance.now() - start,
        origin: 'deterministic',
        isConfirmedViolation: true,
        routing: {
          decision: 'unknown_or_uninspectable',
          reason: 'uninspected-binary',
          origin: 'upstream',
          capability: 'UNKNOWN',
          inputBytes: 0,
          contextIncluded: false,
        },
      };
      this.recordAudit(res, 'resources/read', uri, ctx);
      return {
        sanitizedItems: [],
        isRedacted: false,
        isBlocked: true,
        blockReason: res.explanation,
        threatCategory: 'uninspected_binary',
        results: [res],
      };
    }
    const textItems = items.filter((item) => item.blob === undefined);
    const pieces = textItems.map((item) => item.text ?? '');
    if (!textItems.length) {
      const routed = this.boundary.screen('', ctx.stage, uri, ctx, undefined, [], false);
      const result: SecurityInspectionResult = {
        id: randomUUID(),
        stage: ctx.stage,
        action: 'allow',
        threatCategory: 'uninspected_binary',
        origin: 'deterministic',
        isConfirmedViolation: false,
        evidence: [],
        explanation: 'Explicit binary allow policy: content remains uninspectable',
        evaluationDurationMs: performance.now() - start,
        routing: { ...routed.routing, reason: 'explicit-uninspected-binary-opt-out' },
      };
      this.recordAudit(result, 'resources/read', uri, ctx);
      return {
        sanitizedItems: items,
        isRedacted: false,
        isBlocked: false,
        threatCategory: 'none',
        results: [result],
      };
    }
    const result = await this.boundary.classify(
      ctx,
      uri,
      pieces,
      textItems.every(
        (item) =>
          typeof item.text === 'string' &&
          (!item.mimeType ||
            item.mimeType.startsWith('text/') ||
            item.mimeType === 'application/json'),
      ),
    );
    this.recordAudit(result, 'resources/read', uri, ctx);
    const isRedacted = result.action === 'block' || (result.action === 'review' && this.failClosed);
    return {
      sanitizedItems: isRedacted
        ? items.map((item) =>
            item.blob !== undefined
              ? item
              : {
                  ...item,
                  text: `[Veylith Security Notice]: Resource content from '${uri}' quarantined. Reason: ${result.explanation}`,
                },
          )
        : items,
      isRedacted,
      isBlocked: false,
      threatCategory: isRedacted ? 'resource_poisoning' : 'none',
      results: [result],
    };
  }

  /**
   * 6. Inspect prompts discovery (prompts/list).
   * Checks prompt metadata, template descriptions, and session permissions.
   */
  async inspectPromptDiscovery(
    prompts: readonly PromptMetadataInput[],
    ctx?: InspectionContext,
  ): Promise<PromptDiscoveryOutcome> {
    const cleanPrompts: PromptMetadataInput[] = [];
    const blockedPrompts: { name: string; reason: string; threatCategory: ThreatCategory }[] = [];
    const results: SecurityInspectionResult[] = [];

    // Session validation if sessionId provided
    if (ctx?.sessionId) {
      const sessVal = this.sessionManager.validateSession(
        ctx.sessionId,
        ctx.clientIdentity,
        ctx.serverId,
      );
      if (!sessVal.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: ctx.sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${ctx.sessionId}' is invalid or expired (reason: ${sessVal.reason})`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'prompts/list', undefined, ctx);
        return {
          cleanPrompts: [],
          blockedPrompts: prompts.map((p) => ({
            name: p.name,
            reason: res.explanation,
            threatCategory: 'unauthorized_access',
          })),
          results: [res],
        };
      }
    }

    for (const prompt of prompts) {
      if (ctx?.sessionId && !this.sessionManager.isPromptAuthorized(ctx.sessionId, prompt.name)) {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_discovery',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [
            { type: 'session_authorization', snippet: prompt.name, location: 'promptName' },
          ],
          explanation: `Prompt '${prompt.name}' is not permitted under session '${ctx.sessionId}'`,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(result);
        blockedPrompts.push({
          name: prompt.name,
          reason: result.explanation,
          threatCategory: 'unauthorized_access',
        });
        this.recordAudit(result, 'prompts/list', prompt.name, ctx);
        continue;
      }

      const inspectTarget = `${prompt.name} ${prompt.description ?? ''} ${JSON.stringify(prompt.arguments ?? [])}`;
      const screenVerdict = this.boundary.screen(
        inspectTarget,
        'prompt_discovery',
        prompt.name,
        ctx,
      );

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
          routing: screenVerdict.routing,
          stage: 'prompt_discovery',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: 'prompt_metadata',
            },
          ],
          explanation: `Prompt metadata poisoning detected: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: 0.1,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(result);
        blockedPrompts.push({
          name: prompt.name,
          reason: result.explanation,
          threatCategory: result.threatCategory,
        });
        this.recordAudit(result, 'prompts/list', prompt.name, ctx);
        continue;
      }

      if (screenVerdict.type === 'ambiguous') {
        const review = await this.boundary.classify(
          {
            requestId: randomUUID(),
            stage: 'prompt_discovery',
            method: 'prompts/list',
            timestamp: new Date().toISOString(),
            ...ctx,
          },
          prompt.name,
          [inspectTarget],
          true,
          screenVerdict,
        );
        results.push(review);
        this.recordAudit(review, 'prompts/list', prompt.name, ctx);
        if (review.action === 'block' || (review.action === 'review' && this.failClosed)) {
          blockedPrompts.push({
            name: prompt.name,
            reason: review.explanation,
            threatCategory: review.threatCategory,
          });
          continue;
        }
        cleanPrompts.push(prompt);
        continue;
      }
      cleanPrompts.push(prompt);
      const allowResult: SecurityInspectionResult = {
        id: randomUUID(),
        routing: screenVerdict.routing,
        stage: 'prompt_discovery',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Prompt metadata clean',
        evaluationDurationMs: 0.1,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
      results.push(allowResult);
      this.recordAudit(allowResult, 'prompts/list', prompt.name, ctx);
    }

    return { cleanPrompts, blockedPrompts, results };
  }

  /**
   * 7. Inspect prompt messages during prompts/get.
   * Intercepts poisoned prompt templates attempting to impersonate privileged system instructions.
   */
  async inspectPromptMessages(
    ctx: InspectionContext,
    promptName: string,
    messages: readonly PromptMessageItem[],
    _args?: Record<string, unknown>,
  ): Promise<PromptMessagesOutcome> {
    const start = performance.now();

    // Session validation
    if (ctx.sessionId) {
      const sessionCheck = this.sessionManager.validateSession(
        ctx.sessionId,
        ctx.clientIdentity,
        ctx.serverId,
      );
      if (!sessionCheck.valid) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_messages',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [{ type: 'session_validation', snippet: ctx.sessionId, location: 'sessionId' }],
          explanation: `Unauthorized session: Session '${ctx.sessionId}' is invalid or expired (reason: ${sessionCheck.reason})`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'prompts/get', promptName, ctx);
        return {
          sanitizedMessages: [],
          isRedacted: false,
          isBlocked: true,
          blockReason: res.explanation,
          threatCategory: 'unauthorized_access',
          results: [res],
        };
      }

      if (!this.sessionManager.isPromptAuthorized(ctx.sessionId, promptName, ctx.serverId)) {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_messages',
          action: 'block',
          threatCategory: 'unauthorized_access',
          evidence: [
            { type: 'session_authorization', snippet: promptName, location: 'promptName' },
          ],
          explanation: `Unauthorized prompt: Prompt '${promptName}' is not permitted under session '${ctx.sessionId}'`,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        this.recordAudit(res, 'prompts/get', promptName, ctx);
        return {
          sanitizedMessages: [],
          isRedacted: false,
          isBlocked: true,
          blockReason: res.explanation,
          threatCategory: 'unauthorized_access',
          results: [res],
        };
      }
    }

    const pieces = messages.map((msg) => msg.content.text ?? '');
    const result = await this.boundary.classify(
      ctx,
      promptName,
      pieces,
      messages.every((msg) => msg.content.type === 'text' && typeof msg.content.text === 'string'),
    );
    this.recordAudit(result, 'prompts/get', promptName, ctx);
    const isRedacted = result.action === 'block' || (result.action === 'review' && this.failClosed);
    return {
      sanitizedMessages: isRedacted
        ? messages.map((msg) => ({
            role: msg.role,
            content: {
              type: 'text',
              text: `[Veylith Security Notice]: Prompt '${promptName}' quarantined. Reason: ${result.explanation}`,
            },
          }))
        : messages,
      isRedacted,
      isBlocked: false,
      threatCategory: isRedacted ? 'prompt_poisoning' : 'none',
      results: [result],
    };
  }
}
