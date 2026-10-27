# Veylith Architectural Security Audit: Tool Capabilities vs. Substring False Positives

**Author:** Principal MCP Protocol Engineer & AI Infrastructure Security Architect  
**Scope:** Policy Engine Deterministic Rule Evaluation (`packages/policy-engine/src/rules/deterministic.ts`)  
**Status:** Completed Architectural Audit for Phase 2B / Blueprint for Phase 2C

---

## 1. Problem Statement & Audit Objective

In Phase 0, Phase 1, and Phase 2A, Veylith implemented Tier 1 deterministic security invariants using regular expression pattern matching on incoming tool call arguments (`call_arguments`).

During Phase 2B client integration testing, `echo` with argument `{ message: 'rm -rf /' }` was evaluated and blocked with:

```json
{
  "content": [
    {
      "type": "text",
      "text": "Veylith policy blocked this call: Dangerous arguments blocked: Destructive filesystem deletion (rm -rf / or *)"
    }
  ],
  "isError": true
}
```

### The Security Question

_Is blocking `rm -rf /` inside a harmless `echo` message an inappropriate false positive?_

### The Verdict

**YES.** Blocking `rm -rf /` within an `echo` tool invocation is an inappropriate false positive in production.  
Security enforcement must account for **tool capabilities, side-effect potentials, and execution context**, rather than naively treating every string occurrence of a dangerous command as an active exploit.

---

## 2. Root Cause Analysis: Confusing Code with Data

The vulnerability in naive pattern-based gateways is the classic security failure: **confusing code with data**.

1. **Tool Semantics Matter:**
   - An `echo` tool merely reflects an input string back into the conversation or terminal. It has zero filesystem access, zero shell execution capabilities, and zero system mutation potential.
   - A code search tool (`grep_search`, `search_repository`) or documentation viewer (`view_file`, `fetch_docs`) frequently processes strings like `rm -rf /`, `DROP TABLE users;`, or `chmod 777 /` as **legitimate search queries or code review artifacts**.
   - Blocking these strings on read-only tools causes immediate disruption to legitimate developer workflows without providing any security benefit.

2. **When Destructive Patterns Are Genuine Threats:**
   - The string `rm -rf /` is ONLY a catastrophic threat when passed to a tool that possesses **operating system shell execution capabilities** (such as `bash`, `execute_command`, `terminal_exec`, or `run_script`) or **filesystem mutation capabilities** (such as a recursive file deletion tool).
   - In that context, the argument is interpreted as executable shell code by an underlying interpreter.

3. **Historical Context in Veylith Test Suites:**
   - In Phase 0, Phase 1, and the initial Phase 2B test harness, `echo` was used as a safe, harmless vehicle to demonstrate that argument interception logic works end-to-end without requiring a destructive shell tool in the test suite.
   - While effective for verifying that the interception pipeline triggers, relying on global substring matching in production creates severe usability friction.

---

## 3. Tool Capability & Authorization Context Architecture (Phase 2C Blueprint)

To eliminate false positives while strictly upholding security invariants, Veylith will transition in Phase 2C to a **Capability-Aware Security Model**:

```
                       Inbound Tool Call (name, args)
                                     |
                                     v
                   +----------------------------------+
                   | Tool Capability Classifier       |
                   | (Discovered from Schema & Config)|
                   +----------------------------------+
                                     |
           +-------------------------+-------------------------+
           |                                                   |
           v                                                   v
   [HIGH RISK CAPABILITY]                             [READ-ONLY / PURE TOOL]
   - SHELL_EXECUTION                                  - TEXT_TRANSFORM (e.g. echo)
   - FS_MUTATION                                      - CODE_SEARCH
   - SQL_EXECUTION                                    - DATA_CALCULATION (e.g. add)
   - NETWORK_OUTBOUND                                          |
           |                                                   v
           v                                          Bypass Execution Invariants
   Enforce Hard Invariants:                           (e.g., 'rm -rf /' allowed)
   - 'rm -rf /' blocked on SHELL/FS                            |
   - 'DROP TABLE' blocked on SQL                               v
   - Exfiltration endpoints blocked on NET            Inspect Only for Prompt Injections
```

### 3.1 Tool Capability Taxonomy

Veylith categorizes upstream tools into five capability profiles:

| Capability Profile | Example Tools                               | Applicable Tier 1 Invariants                                               |
| :----------------- | :------------------------------------------ | :------------------------------------------------------------------------- |
| **`SHELL_EXEC`**   | `bash`, `run_terminal`, `exec_command`      | `rm -rf /`, fork bombs, `shutdown`, `chmod 777`                            |
| **`FS_MUTATION`**  | `delete_file`, `write_file`, `move_file`    | Path traversal (`../../etc/passwd`), destructive deletes                   |
| **`SQL_EXEC`**     | `query_db`, `execute_sql`, `postgres_query` | `DROP TABLE`, `TRUNCATE`, unbounded `DELETE FROM`                          |
| **`NETWORK_OUT`**  | `curl`, `fetch_url`, `send_webhook`         | Known exfiltration endpoints (`webhook.site`), SSRF to private IPs         |
| **`PURE_OR_READ`** | `echo`, `add`, `search_code`, `read_file`   | **Exempt from execution invariants**; inspected only for prompt injections |

### 3.2 Discovery Capability Tagging

During Stage 1 (`tools/list` discovery inspection):

1. Veylith analyzes tool names, descriptions, and input schemas to classify the tool's capability profile.
2. Capability classifications are stored in the session state alongside the tool registration.
3. During Stage 2 (`tools/call` argument inspection), deterministic rules check:
   ```ts
   if (rule.requiredCapability && !toolCapabilities.has(rule.requiredCapability)) {
     // Skip execution-specific rule: tool cannot execute this payload
     continue;
   }
   ```

---

## 4. Current Test Suite Stability & Phase 2B Alignment

In Phase 2B:

- Existing tests in `tests/integration/gateway.test.ts` (Phase 1 legacy tests) expect `echo` with `rm -rf /` to be blocked as a verification of the generic regex scanner.
- In `scripts/demo-real-client.ts`, Workflow B has been updated to explicitly demonstrate:
  1. **Configured Tool Blocklist (`restricted_demo_tool`)**: Verifies policy blocking based on tool authorization identity.
  2. **Hard Invariant Blocking (`rm -rf /`)**: Verifies argument pattern matching.
- **Phase 2C Action Item**: When Phase 2C introduces capability-aware tool profiles, `echo` will be classified as `PURE_OR_READ`, and a mock execution tool (`mock_shell_exec`) will be introduced to demonstrate shell invariant enforcement without creating false positives on harmless text tools.
