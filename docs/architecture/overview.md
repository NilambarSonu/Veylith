# Veylith Architecture Overview

## Introduction

**Veylith** is an AI-native security gateway positioned between Model Context Protocol (MCP) clients (autonomous agents, LLM runtimes, agent orchestrators) and upstream MCP servers (tools, resources, prompt providers).

During **Phase 1**, Veylith evolves from a transport bridge into a **hybrid deterministic + AI-assisted security inspection engine**, powered by Meta Muse (`muse-spark-1.3`).

---

## Architectural Topology

```mermaid
flowchart TD
    Client["MCP Client\n(Claude / Cursor / Agent)"]
    Gateway["Veylith Gateway\n(Security Perimeter :8787)"]
    Upstream["Upstream MCP Server\n(Target Tools :8788)"]

    subgraph InspectionEngine ["Security Inspection Engine"]
        Tier1["Tier 1: Deterministic Rules\n(Hard Invariants <0.1ms)"]
        Tier2["Tier 2: Heuristic Screener\n(Triage Clean vs Ambiguous)"]
        Tier3["Tier 3: Meta Muse Semantic Adapter\n(muse-spark-1.3 / Mock / Live)"]
        Cache["Inspection Cache\n(LRU / TTL SHA-256)"]
    end

    Client -->|Streamable HTTP| Gateway
    Gateway --> Tier1
    Tier1 -->|Ambiguous| Tier2
    Tier2 -->|Suspicious Signal| Tier3
    Tier3 <--> Cache
    Gateway -->|Forward Allowed Calls| Upstream
    Upstream -->|Tool Output| Gateway
    Gateway -->|Sanitized Response| Client
```

---

## The Three Inspection Stages

Veylith provides complete defense-in-depth across three distinct operational stages of the MCP protocol lifecycle:

```mermaid
sequenceDiagram
    autonumber
    actor Agent as MCP Client
    participant GW as Veylith Gateway
    participant Engine as Security Engine
    participant Server as Upstream Server

    Note over GW,Server: Stage 1: Discovery Inspection
    Agent->>GW: tools/list
    GW->>Server: tools/list
    Server-->>GW: [Raw Tool Metadata & Schemas]
    GW->>Engine: inspectDiscovery(tools)
    Engine-->>GW: cleanTools (poisoned tools filtered)
    GW-->>Agent: [Clean Tools List]

    Note over Agent,GW: Stage 2: Argument Inspection
    Agent->>GW: tools/call (name, args)
    GW->>Engine: inspectArguments(ctx, toolName, args)
    alt Hard Block or Semantic Violation
        Engine-->>GW: Action: BLOCK
        GW-->>Agent: isError: true, "Veylith policy blocked this call..."
    else Allowed
        Engine-->>GW: Action: ALLOW
        GW->>Server: tools/call (name, args)
        Server-->>GW: [Raw Tool Output Content]

        Note over GW,Engine: Stage 3: Response Inspection
        GW->>Engine: inspectResponse(ctx, toolName, content)
        alt Injected Prompt Instructions Detected
            Engine-->>GW: Action: BLOCK (Sanitized Notice)
            GW-->>Agent: isError: true, "[Veylith Security Notice]: Redacted..."
        else Clean Output
            Engine-->>GW: Action: ALLOW (Original Output)
            GW-->>Agent: [Raw Content]
        end
    end
```

---

## Tiered Performance Strategy

To balance low latency with deep semantic analysis, Veylith uses a 3-tier processing pipeline:

| Tier       | Component                    | Latency                                   | Scope & Role                                                                                                                                                                                                                                       |
| :--------- | :--------------------------- | :---------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Tier 1** | **Deterministic Rules**      | `<0.05 ms`                                | Evaluates hard security invariants (destructive shell commands like `rm -rf`, destructive SQL `DROP TABLE`, path traversal `../../etc/shadow`, known credential regexes, explicit tool deny-lists). **Hard blocks can never be overridden by AI.** |
| **Tier 2** | **Heuristic Screener**       | `<0.1 ms`                                 | Triages payloads into `clean` (fast-path allow, skipping LLM), `hard_violation` (fast-path block), or `ambiguous` (contains suspicious keywords or patterns).                                                                                      |
| **Tier 3** | **Meta Muse Semantic Model** | `~10–15 ms` (mock) / `~300–600 ms` (live) | Evaluates ambiguous cases using Meta Muse (`muse-spark-1.3`). Features XML delimiter trust separation and strict Zod output validation.                                                                                                            |

---

## Core Components

### 1. `apps/gateway` (MCP Bridge Gateway)

- Implements Streamable HTTP MCP server interface for downstream clients.
- Connects as an MCP client to upstream servers using `@modelcontextprotocol/client`.
- Integrates `SecurityInspectionEngine` across discovery, call arguments, and tool outputs.
- Redacts sensitive credentials in audit logs.

### 2. `packages/core` (Domain Foundation)

- Protocol-agnostic domain layer.
- `InspectionStage`: `'discovery' | 'call_arguments' | 'call_response'`.
- `ThreatCategory`: `'tool_poisoning' | 'suspicious_arguments' | 'malicious_response' | 'credential_leak' | 'destructive_command' | 'none'`.
- `PolicyAction`: `'allow' | 'block' | 'review'`.
- `SecurityInspectionResult`: Structured audit verdict with rule ID, model ID, origin, confidence, and sanitized evidence.

### 3. `packages/policy-engine` (Hybrid Engine)

- `DeterministicRuleSet`: In-memory pattern scanner covering destructive execution, exfiltration URLs, and directive overrides.
- `HeuristicRiskScreener`: Fast regex/keyword screener triaging requests.
- `InspectionCache`: Bounded in-memory LRU/TTL cache keyed by `SHA-256(payload) + stage + policyVersion + modelVersion`.
- `SecurityInspectionEngine`: Master coordinator orchestrating all three tiers.

### 4. `packages/meta-adapter` (Meta Muse Integration)

- `MetaMuseSecurityAdapter`: Handles `mock` (offline deterministic simulation), `live` (Meta Model API `POST /responses` to `https://api.meta.ai/v1`), and `disabled` modes.
- `UsageTracker`: Application-level budget cap enforcing maximum requests per run and daily USD budget caps with token accounting.
- **Trust Separation**: Untrusted input is strictly encapsulated within `<untrusted_content>` tags, instructing the model to treat the content purely as passive data.

---

## Trade-offs and Invariants

1. **Deterministic Precedence**: AI inference is strictly consultative; it cannot unblock a payload flagged by a Tier 1 deterministic invariant.
2. **Fail-Closed vs Fail-Open**: In development mode, ambiguous unblocked interactions default to `allow` (fail-open) for developer velocity. In production profiles, `failClosed: true` flags any model outage or `review` verdict as a block.
3. **Local Privacy**: Model inspection is strictly performed from the backend gateway; API keys are never delivered to clients or browser runtimes.
