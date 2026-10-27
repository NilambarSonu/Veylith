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
import { HeuristicRiskScreener } from '../screener/heuristic.js';
import { InspectionCache } from '../cache/inspection-cache.js';
import { ToolCapabilityRegistry, type TrustedToolBinding } from '../capabilities/registry.js';
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
  private readonly screener = new HeuristicRiskScreener();
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
    this.policyVersion = options?.policyVersion ?? 'v1.0.0';
    this.failClosed = options?.failClosed ?? false;
    this.defaultDecision = options?.defaultDecision ?? 'allow';
    this.cache = new InspectionCache(500, 60000);
    this.capabilityRegistry =
      options?.capabilityRegistry ?? new ToolCapabilityRegistry(options?.capabilityBindings ?? []);
    this.sessionManager = options?.sessionManager ?? new ClientSessionManager();
    this.auditChain = options?.auditChain ?? new AuditLogChain();
    this.maxResourceContentBytes = options?.maxResourceContentBytes ?? 5 * 1024 * 1024;
    this.allowBinaryResources = options?.allowBinaryResources ?? false;
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
          explanation: `Tool definition mutated: Description or schema for tool '${tool.name}' was modified after initial registration. Quarantined to prevent dynamic prompt injection or unauthorized capability expansion.`,
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
      const inspectTarget = `${tool.name} ${tool.description ?? ''} ${JSON.stringify(tool.inputSchema ?? {})}`;
      const screenVerdict = this.screener.screen(inspectTarget, 'discovery');

      if (screenVerdict.type === 'hard_violation') {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
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
        payload: inspectTarget,
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

      const modelResult = await this.metaAdapter.inspect(inspectTarget, 'discovery', {
        toolName: tool.name,
      });

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
        modelId: this.metaAdapter.model,
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

      this.cache.set(cacheKey, res);
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
    const screenVerdict = this.screener.screen(args, {
      stage: 'call_arguments',
      capability,
      toolName,
      serverId: ctx.serverId,
    });

    if (screenVerdict.type === 'hard_violation') {
      const res: SecurityInspectionResult = {
        id: randomUUID(),
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
    const serializedArgs = JSON.stringify(args);
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
      this.recordAudit(cached, 'tools/call', toolName, ctx);
      return cached;
    }

    const modelResult = await this.metaAdapter.inspect(serializedArgs, 'call_arguments', {
      toolName,
    });

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
      modelId: this.metaAdapter.model,
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

    this.cache.set(cacheKey, res);
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
    const start = performance.now();

    const textPayload = content
      .filter((c) => c.type === 'text' && typeof c.text === 'string')
      .map((c) => c.text!)
      .join('\n');

    // Tier 1 & 2: Screen response
    const screenVerdict = this.screener.screen(textPayload, 'call_response');

    if (screenVerdict.type === 'hard_violation') {
      const result: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'call_response',
        action: 'block',
        threatCategory: screenVerdict.match.threatCategory,
        evidence: [
          {
            type: 'deterministic_rule',
            matchedPattern: screenVerdict.match.matchedPattern,
            snippet: screenVerdict.match.snippet,
            location: screenVerdict.match.location || 'response_body',
          },
        ],
        explanation: `Malicious response intercepted: ${screenVerdict.match.description}`,
        ruleId: screenVerdict.match.ruleId,
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: true,
      };

      this.recordAudit(result, 'tools/call', toolName, ctx);

      const sanitizedContent = [
        {
          type: 'text',
          text: `[Veylith Security Notice]: Tool response from '${toolName}' contained potential prompt injection instructions and was redacted to protect the agent reasoning loop. Reason: ${screenVerdict.match.description}`,
        },
      ];

      return { result, sanitizedContent, isRedacted: true };
    }

    if (screenVerdict.type === 'clean') {
      const result: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'call_response',
        action: 'allow',
        threatCategory: 'none',
        evidence: [],
        explanation: 'Response content screened clean by deterministic rules',
        evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
        origin: 'deterministic',
        isConfirmedViolation: false,
      };
      this.recordAudit(result, 'tools/call', toolName, ctx);
      return { result, sanitizedContent: content, isRedacted: false };
    }

    // Tier 3: Ambiguous response -> Semantic model check
    const cacheKey = this.cache.generateKey({
      payload: textPayload,
      stage: 'call_response',
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
      this.recordAudit(cached, 'tools/call', toolName, ctx);
      if (cached.action === 'block') {
        return {
          result: cached,
          sanitizedContent: [
            {
              type: 'text',
              text: `[Veylith Security Notice]: Tool response from '${toolName}' contained potential prompt injection instructions and was redacted. Reason: ${cached.explanation}`,
            },
          ],
          isRedacted: true,
        };
      }
      return { result: cached, sanitizedContent: content, isRedacted: false };
    }

    const modelResult = await this.metaAdapter.inspect(textPayload, 'call_response', {
      toolName,
    });

    let finalAction: PolicyAction = modelResult.flagged ? modelResult.action : this.defaultDecision;
    let finalExplanation = modelResult.explanation;

    // Fail-closed risk-based fallback: High-risk unverified operations MUST NOT pass when AI provider fails
    if (
      modelResult.action === 'review' &&
      screenVerdict.type === 'ambiguous' &&
      screenVerdict.riskLevel === 'high'
    ) {
      finalAction = 'block';
      finalExplanation = `High-risk response quarantined: Security classifier unavailable while response exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
    }

    const result: SecurityInspectionResult = {
      id: randomUUID(),
      stage: 'call_response',
      action: finalAction,
      threatCategory:
        finalAction === 'block' && modelResult.threatCategory === 'none'
          ? 'malicious_response'
          : modelResult.threatCategory,
      evidence: modelResult.evidence.map((ev) => ({
        type: 'semantic_inference',
        snippet: ev,
        location: 'response_body',
      })),
      explanation: finalExplanation,
      modelId: this.metaAdapter.model,
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

    this.cache.set(cacheKey, result);
    this.recordAudit(result, 'tools/call', toolName, ctx);

    if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
      return {
        result,
        sanitizedContent: [
          {
            type: 'text',
            text: `[Veylith Security Notice]: Tool response from '${toolName}' was intercepted and redacted. Reason: ${finalExplanation}`,
          },
        ],
        isRedacted: true,
      };
    }

    return { result, sanitizedContent: content, isRedacted: false };
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
      const screenVerdict = this.screener.screen(inspectTarget, 'resource_discovery');

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
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

      cleanResources.push(res);
      const allowResult: SecurityInspectionResult = {
        id: randomUUID(),
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
      const screenVerdict = this.screener.screen(inspectTarget, 'resource_discovery');

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
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
    const results: SecurityInspectionResult[] = [];

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

    const sanitizedItems: ResourceContentItem[] = [];
    let isRedacted = false;

    for (const item of items) {
      // Binary content policy: explicit policy-based handling
      if (item.blob !== undefined) {
        if (!this.allowBinaryResources) {
          const res: SecurityInspectionResult = {
            id: randomUUID(),
            stage: 'resource_content',
            action: 'block',
            threatCategory: 'uninspected_binary',
            evidence: [
              {
                type: 'uninspected_binary',
                snippet: `MIME type: ${item.mimeType ?? 'application/octet-stream'}`,
                location: 'blob',
              },
            ],
            explanation: `Uninspected binary payload rejected: Gateway policy disallows uninspected binary resource contents ('${uri}'). Explicit binary inspection policy required.`,
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
            threatCategory: 'uninspected_binary',
            results: [res],
          };
        } else {
          // Explicitly permitted binary payload
          sanitizedItems.push(item);
          continue;
        }
      }

      // Text content inspection
      const textContent = item.text ?? '';
      const screenVerdict = this.screener.screen(textContent, 'resource_content');

      if (screenVerdict.type === 'hard_violation') {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_content',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: 'resource_text',
            },
          ],
          explanation: `Malicious resource content intercepted: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        this.recordAudit(res, 'resources/read', uri, ctx);

        // Redact resource text
        sanitizedItems.push({
          ...item,
          text: `[Veylith Security Notice]: Resource content from '${uri}' contained active prompt injection instructions and was redacted to protect the agent reasoning loop. Reason: ${screenVerdict.match.description}`,
        });
        isRedacted = true;
        continue;
      }

      if (screenVerdict.type === 'clean') {
        sanitizedItems.push(item);
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'resource_content',
          action: 'allow',
          threatCategory: 'none',
          evidence: [],
          explanation: 'Resource content verified clean',
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: false,
        };
        results.push(res);
        this.recordAudit(res, 'resources/read', uri, ctx);
        continue;
      }

      // Ambiguous content -> Semantic model check
      const cacheKey = this.cache.generateKey({
        payload: textContent,
        stage: 'resource_content',
        policyVersion: this.policyVersion,
        modelVersion: `${this.metaAdapter.mode}:${this.metaAdapter.model}`,
        baselineRevision: this.capabilityRegistry.baselineRevision,
        clientId: ctx.clientIdentity,
        serverId: ctx.serverId,
        sessionId: ctx.sessionId,
        toolName: uri,
      });
      const cached = this.cache.get(cacheKey);

      if (cached) {
        results.push(cached);
        this.recordAudit(cached, 'resources/read', uri, ctx);
        if (cached.action === 'block') {
          sanitizedItems.push({
            ...item,
            text: `[Veylith Security Notice]: Resource content from '${uri}' was quarantined. Reason: ${cached.explanation}`,
          });
          isRedacted = true;
        } else {
          sanitizedItems.push(item);
        }
        continue;
      }

      const modelResult = await this.metaAdapter.inspect(textContent, 'call_response', {
        resourceUri: uri,
      });

      let finalAction: PolicyAction = modelResult.flagged
        ? modelResult.action
        : this.defaultDecision;
      let finalExplanation = modelResult.explanation;

      if (
        modelResult.action === 'review' &&
        screenVerdict.type === 'ambiguous' &&
        screenVerdict.riskLevel === 'high'
      ) {
        finalAction = 'block';
        finalExplanation = `High-risk resource quarantined: Security classifier unavailable while content exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
      }

      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'resource_content',
        action: finalAction,
        threatCategory:
          finalAction === 'block' && modelResult.threatCategory === 'none'
            ? 'resource_poisoning'
            : modelResult.threatCategory,
        evidence: modelResult.evidence.map((ev) => ({
          type: 'semantic_inference',
          snippet: ev,
          location: 'resource_text',
        })),
        explanation: finalExplanation,
        modelId: this.metaAdapter.model,
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

      this.cache.set(cacheKey, res);
      results.push(res);
      this.recordAudit(res, 'resources/read', uri, ctx);

      if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
        sanitizedItems.push({
          ...item,
          text: `[Veylith Security Notice]: Resource content from '${uri}' was quarantined. Reason: ${finalExplanation}`,
        });
        isRedacted = true;
      } else {
        sanitizedItems.push(item);
      }
    }

    return {
      sanitizedItems,
      isRedacted,
      isBlocked: false,
      threatCategory: isRedacted ? 'resource_poisoning' : 'none',
      results,
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
      const screenVerdict = this.screener.screen(inspectTarget, 'prompt_discovery');

      if (screenVerdict.type === 'hard_violation') {
        const result: SecurityInspectionResult = {
          id: randomUUID(),
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

      cleanPrompts.push(prompt);
      const allowResult: SecurityInspectionResult = {
        id: randomUUID(),
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
    const results: SecurityInspectionResult[] = [];

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

    const sanitizedMessages: PromptMessageItem[] = [];
    let isRedacted = false;

    for (const msg of messages) {
      const contentText =
        typeof msg.content.text === 'string' ? msg.content.text : JSON.stringify(msg.content);

      // Tier 1 & 2: Screen prompt messages
      const screenVerdict = this.screener.screen(contentText, 'prompt_messages');

      if (screenVerdict.type === 'hard_violation') {
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_messages',
          action: 'block',
          threatCategory: screenVerdict.match.threatCategory,
          evidence: [
            {
              type: 'deterministic_rule',
              matchedPattern: screenVerdict.match.matchedPattern,
              snippet: screenVerdict.match.snippet,
              location: 'prompt_message',
            },
          ],
          explanation: `Poisoned prompt template intercepted: ${screenVerdict.match.description}`,
          ruleId: screenVerdict.match.ruleId,
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: true,
        };
        results.push(res);
        this.recordAudit(res, 'prompts/get', promptName, ctx);

        sanitizedMessages.push({
          role: msg.role,
          content: {
            type: 'text',
            text: `[Veylith Security Notice]: Prompt template '${promptName}' contained instruction hijacking or policy override attempts and was redacted. Reason: ${screenVerdict.match.description}`,
          },
        });
        isRedacted = true;
        continue;
      }

      if (screenVerdict.type === 'clean') {
        sanitizedMessages.push(msg);
        const res: SecurityInspectionResult = {
          id: randomUUID(),
          stage: 'prompt_messages',
          action: 'allow',
          threatCategory: 'none',
          evidence: [],
          explanation: 'Prompt message verified clean',
          evaluationDurationMs: Math.round((performance.now() - start) * 100) / 100,
          origin: 'deterministic',
          isConfirmedViolation: false,
        };
        results.push(res);
        this.recordAudit(res, 'prompts/get', promptName, ctx);
        continue;
      }

      // Ambiguous prompt template -> Semantic model check
      const cacheKey = this.cache.generateKey({
        payload: contentText,
        stage: 'prompt_messages',
        policyVersion: this.policyVersion,
        modelVersion: `${this.metaAdapter.mode}:${this.metaAdapter.model}`,
        baselineRevision: this.capabilityRegistry.baselineRevision,
        clientId: ctx.clientIdentity,
        serverId: ctx.serverId,
        sessionId: ctx.sessionId,
        toolName: promptName,
      });
      const cached = this.cache.get(cacheKey);

      if (cached) {
        results.push(cached);
        this.recordAudit(cached, 'prompts/get', promptName, ctx);
        if (cached.action === 'block') {
          sanitizedMessages.push({
            role: msg.role,
            content: {
              type: 'text',
              text: `[Veylith Security Notice]: Prompt template '${promptName}' was quarantined. Reason: ${cached.explanation}`,
            },
          });
          isRedacted = true;
        } else {
          sanitizedMessages.push(msg);
        }
        continue;
      }

      const modelResult = await this.metaAdapter.inspect(contentText, 'call_response', {
        promptName,
      });

      let finalAction: PolicyAction = modelResult.flagged
        ? modelResult.action
        : this.defaultDecision;
      let finalExplanation = modelResult.explanation;

      if (
        modelResult.action === 'review' &&
        screenVerdict.type === 'ambiguous' &&
        screenVerdict.riskLevel === 'high'
      ) {
        finalAction = 'block';
        finalExplanation = `High-risk prompt template quarantined: Security classifier unavailable while template exhibited high-risk signals (${screenVerdict.suspiciousSignals.join(', ')})`;
      }

      const res: SecurityInspectionResult = {
        id: randomUUID(),
        stage: 'prompt_messages',
        action: finalAction,
        threatCategory:
          finalAction === 'block' && modelResult.threatCategory === 'none'
            ? 'prompt_poisoning'
            : modelResult.threatCategory,
        evidence: modelResult.evidence.map((ev) => ({
          type: 'semantic_inference',
          snippet: ev,
          location: 'prompt_message',
        })),
        explanation: finalExplanation,
        modelId: this.metaAdapter.model,
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

      this.cache.set(cacheKey, res);
      results.push(res);
      this.recordAudit(res, 'prompts/get', promptName, ctx);

      if (finalAction === 'block' || (finalAction === 'review' && this.failClosed)) {
        sanitizedMessages.push({
          role: msg.role,
          content: {
            type: 'text',
            text: `[Veylith Security Notice]: Prompt template '${promptName}' was quarantined. Reason: ${finalExplanation}`,
          },
        });
        isRedacted = true;
      } else {
        sanitizedMessages.push(msg);
      }
    }

    return {
      sanitizedMessages,
      isRedacted,
      isBlocked: false,
      threatCategory: isRedacted ? 'prompt_poisoning' : 'none',
      results,
    };
  }
}
