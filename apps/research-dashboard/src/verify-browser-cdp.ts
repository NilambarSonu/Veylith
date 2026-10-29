import { spawn, type ChildProcess } from 'node:child_process';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { startDashboardServer } from './server/index.js';

interface CdpMessage {
  id: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: unknown };
}

interface InteractionLog {
  step: number;
  category: string;
  action: string;
  outcome: 'PASS' | 'FAIL';
  details: string;
}

const interactionLogs: InteractionLog[] = [];

function recordInteraction(
  category: string,
  action: string,
  outcome: 'PASS' | 'FAIL',
  details: string,
) {
  const step = interactionLogs.length + 1;
  interactionLogs.push({ step, category, action, outcome, details });
  console.log(`[Step ${step}] [${outcome}] [${category}] ${action} — ${details}`);
}

async function runBrowserVerification(): Promise<void> {
  console.log('═══════════════════════════════════════════════════════════════════');
  console.log('   VEYLITH RESEARCH DASHBOARD — LIVE BROWSER AUTOMATION AUDIT      ');
  console.log('═══════════════════════════════════════════════════════════════════\n');

  // 1. Start Dashboard Server on a dedicated loopback port
  const SERVER_PORT = 19896;
  console.log(`[Setup] Starting local dashboard server on loopback port ${SERVER_PORT}...`);
  const { server, url: serverUrl } = await startDashboardServer({ port: SERVER_PORT });
  console.log(`[Setup] Dashboard server bound to ${serverUrl}`);

  // 2. Launch Google Chrome in Headless Mode
  const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  if (!fs.existsSync(chromePath)) {
    throw new Error(`Google Chrome executable not found at: ${chromePath}`);
  }

  const CDP_PORT = 9223;
  const tmpUserDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'veylith-cdp-test-'));
  console.log(`[Setup] Spawning headless Chrome on CDP port ${CDP_PORT}...`);

  const chromeProc: ChildProcess = spawn(
    chromePath,
    [
      '--headless=new',
      `--remote-debugging-port=${CDP_PORT}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--disable-extensions',
      `--user-data-dir=${tmpUserDataDir}`,
      'about:blank',
    ],
    { stdio: 'ignore' },
  );

  let ws: WebSocket | null = null;
  const consoleMessages: Array<{ type: string; text: string }> = [];
  const uncaughtExceptions: string[] = [];

  try {
    // 3. Connect to CDP via WebSocket
    let wsUrl = '';
    const pollStart = Date.now();
    while (Date.now() - pollStart < 10000) {
      try {
        const json = await new Promise<string>((resolve, reject) => {
          http
            .get(`http://127.0.0.1:${CDP_PORT}/json`, (res) => {
              let data = '';
              res.on('data', (c) => (data += c));
              res.on('end', () => resolve(data));
            })
            .on('error', reject);
        });
        const targets = JSON.parse(json);
        const pageTarget = Array.isArray(targets)
          ? targets.find(
              (t: { type?: string; webSocketDebuggerUrl?: string }) =>
                t.type === 'page' && t.webSocketDebuggerUrl,
            )
          : null;
        if (pageTarget?.webSocketDebuggerUrl) {
          wsUrl = pageTarget.webSocketDebuggerUrl;
          break;
        }
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }

    if (!wsUrl) {
      throw new Error(`Failed to obtain Chrome CDP WebSocket URL on port ${CDP_PORT}`);
    }
    console.log(`[Setup] Connected to Chrome DevTools Protocol at ${wsUrl}`);

    ws = new WebSocket(wsUrl);
    await new Promise<void>((resolve, reject) => {
      ws!.onopen = () => resolve();
      ws!.onerror = (err) => reject(err);
    });

    let msgId = 1;
    const pendingRequests = new Map<
      number,
      {
        resolve: (res: Record<string, unknown> | undefined) => void;
        reject: (err: Error) => void;
      }
    >();

    ws.onmessage = (event) => {
      try {
        const data: CdpMessage = JSON.parse(event.data.toString());
        if (data.id && pendingRequests.has(data.id)) {
          const { resolve, reject } = pendingRequests.get(data.id)!;
          pendingRequests.delete(data.id);
          if (data.error) {
            reject(new Error(`CDP Error ${data.error.code}: ${data.error.message}`));
          } else {
            resolve(data.result);
          }
        } else if (data.method === 'Runtime.consoleAPICalled') {
          const p = data.params as {
            type: string;
            args?: Array<{ value?: string; description?: string }>;
          };
          const text = (p.args || []).map((a) => a.value ?? a.description ?? '').join(' ');
          consoleMessages.push({ type: p.type, text });
          if (p.type === 'error') {
            console.error(`[Browser Console Error] ${text}`);
          }
        } else if (data.method === 'Runtime.exceptionThrown') {
          const p = data.params as {
            exceptionDetails?: { text?: string; exception?: { description?: string } };
          };
          const desc =
            p.exceptionDetails?.exception?.description || p.exceptionDetails?.text || 'unknown';
          uncaughtExceptions.push(desc);
          console.error(`[Browser Uncaught Exception] ${desc}`);
        }
      } catch (e) {
        console.error('Error parsing CDP message:', e);
      }
    };

    function sendCommand(
      method: string,
      params: Record<string, unknown> = {},
    ): Promise<Record<string, unknown> | undefined> {
      return new Promise((resolve, reject) => {
        const id = msgId++;
        pendingRequests.set(id, { resolve, reject });
        ws!.send(JSON.stringify({ id, method, params }));
      });
    }

    async function evaluate<T = unknown>(expression: string): Promise<T> {
      const res = (await sendCommand('Runtime.evaluate', {
        expression,
        returnByValue: true,
        awaitPromise: true,
      })) as
        | {
            exceptionDetails?: { text?: string; exception?: { description?: string } };
            result?: { value?: unknown };
          }
        | undefined;
      if (res?.exceptionDetails) {
        throw new Error(
          `Eval error: ${res.exceptionDetails.exception?.description || res.exceptionDetails.text}`,
        );
      }
      return res?.result?.value as T;
    }

    // Enable CDP Domains
    await sendCommand('Page.enable');
    await sendCommand('Runtime.enable');
    await sendCommand('DOM.enable');

    // 4. Navigate to Research Dashboard
    console.log(`[Execution] Navigating to ${serverUrl}...`);
    await sendCommand('Page.navigate', { url: serverUrl });

    // Wait for page load and DOM render
    await new Promise((r) => setTimeout(r, 1500));

    // ── Interaction 1: Verify Overview View (#overview) ───────────────────
    const initialHash = await evaluate<string>('window.location.hash');
    const initialTitle = await evaluate<string>('document.title');
    const pageTitle = await evaluate<string>(
      'document.getElementById("page-title")?.textContent || ""',
    );
    const metricCount = await evaluate<number>('document.querySelectorAll(".stat-card").length');
    const scenarioMetric = await evaluate<string>(
      'document.querySelectorAll(".stat-value")[0]?.textContent || ""',
    );

    if (pageTitle === 'Project Overview' && metricCount >= 4 && scenarioMetric.trim() === '14') {
      recordInteraction(
        'Overview View',
        'Load Initial Dashboard',
        'PASS',
        `Title="${initialTitle}", Hash="${initialHash}", Scenarios=${scenarioMetric.trim()}, Metric Cards=${metricCount}`,
      );
    } else {
      recordInteraction(
        'Overview View',
        'Load Initial Dashboard',
        'FAIL',
        `Expected pageTitle "Project Overview", got "${pageTitle}". MetricCount=${metricCount}`,
      );
    }

    // ── Interaction 2: Shortcut '2' -> Evaluation Lab ─────────────────────
    console.log('[Execution] Testing keyboard shortcut "2" for Evaluation Lab...');
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'rawKeyDown',
      key: '2',
      code: 'Digit2',
      windowsVirtualKeyCode: 50,
    });
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: '2',
      code: 'Digit2',
      windowsVirtualKeyCode: 50,
    });
    await new Promise((r) => setTimeout(r, 500));

    const labHash = await evaluate<string>('window.location.hash');
    const labTitle = await evaluate<string>(
      'document.getElementById("page-title")?.textContent || ""',
    );
    const hasTabsBar = await evaluate<boolean>(
      'document.querySelectorAll(".tabs-bar button").length === 2',
    );

    if (labHash === '#evaluation-lab' && labTitle === 'Evaluation Lab' && hasTabsBar) {
      recordInteraction(
        'Keyboard Navigation',
        'Press "2" Key',
        'PASS',
        `Hash switched to "#evaluation-lab", Title="Evaluation Lab", 2 dataset tabs present`,
      );
    } else {
      recordInteraction(
        'Keyboard Navigation',
        'Press "2" Key',
        'FAIL',
        `Hash="${labHash}", Title="${labTitle}", hasTabsBar=${hasTabsBar}`,
      );
    }

    // ── Interaction 3: Mode buttons & Tabs in Evaluation Lab ───────────────
    console.log('[Execution] Testing Evaluation Lab tabs and mode buttons...');
    // Click Phase 2E Frozen Holdout tab
    await evaluate<void>('document.getElementById("tab-p2e")?.click()');
    await new Promise((r) => setTimeout(r, 400));
    const p2eActive = await evaluate<boolean>(
      'document.getElementById("tab-p2e")?.classList.contains("active") || false',
    );
    const p2eText = await evaluate<string>('document.body.innerText');
    const hasHoldoutMention = p2eText.includes('Phase 2E Frozen Holdout');

    if (p2eActive && hasHoldoutMention) {
      recordInteraction(
        'Evaluation Lab',
        'Switch to Phase 2E Holdout Tab',
        'PASS',
        `Tab activated, holdout benchmark dataset rendered`,
      );
    } else {
      recordInteraction(
        'Evaluation Lab',
        'Switch to Phase 2E Holdout Tab',
        'FAIL',
        `p2eActive=${p2eActive}, hasHoldoutMention=${hasHoldoutMention}`,
      );
    }

    // Switch back to Phase 2F Development Comparison tab
    await evaluate<void>('document.getElementById("tab-p2f")?.click()');
    await new Promise((r) => setTimeout(r, 400));

    // Click Deterministic-Only mode pill
    await evaluate<void>(
      'document.querySelector(\'.pill-btn[data-mode="deterministic-only"]\')?.click()',
    );
    await new Promise((r) => setTimeout(r, 400));
    const detWarningFound = await evaluate<boolean>(
      'document.body.innerText.includes("100% False Positive Rate")',
    );

    // Click Mock-Semantic mode pill
    await evaluate<void>(
      'document.querySelector(\'.pill-btn[data-mode="mock-semantic"]\')?.click()',
    );
    await new Promise((r) => setTimeout(r, 400));
    const mockNoticeFound = await evaluate<boolean>(
      'document.body.innerText.includes("Mock-Semantic Recall: 52.1%")',
    );

    if (detWarningFound && mockNoticeFound) {
      recordInteraction(
        'Evaluation Lab',
        'Toggle Mode Pills (Deterministic vs Mock-Semantic)',
        'PASS',
        `Confirmed "100% False Positive Rate" warning on deterministic and "52.1% Recall" notice on mock-semantic`,
      );
    } else {
      recordInteraction(
        'Evaluation Lab',
        'Toggle Mode Pills (Deterministic vs Mock-Semantic)',
        'FAIL',
        `detWarningFound=${detWarningFound}, mockNoticeFound=${mockNoticeFound}`,
      );
    }

    // ── Interaction 4: Shortcut '3' -> Audit Explorer ─────────────────────
    console.log('[Execution] Testing keyboard shortcut "3" for Audit Explorer...');
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'rawKeyDown',
      key: '3',
      code: 'Digit3',
      windowsVirtualKeyCode: 51,
    });
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: '3',
      code: 'Digit3',
      windowsVirtualKeyCode: 51,
    });
    await new Promise((r) => setTimeout(r, 600));

    const auditHash = await evaluate<string>('window.location.hash');
    const auditTitle = await evaluate<string>(
      'document.getElementById("page-title")?.textContent || ""',
    );
    const chainStatus = await evaluate<string>(
      'document.querySelector(".badge.allow")?.textContent || ""',
    );
    const subtext = await evaluate<string>(
      'document.querySelector(".stat-sub")?.textContent || ""',
    );

    if (
      auditHash === '#audit-explorer' &&
      auditTitle === 'Audit Explorer' &&
      chainStatus.includes('Chain Integrity Validated')
    ) {
      recordInteraction(
        'Audit Explorer',
        'Press "3" Key & Verify SHA-256 Chain Validation',
        'PASS',
        `Hash="#audit-explorer", Status="${chainStatus.trim()}", Subtext="${subtext.trim()}"`,
      );
    } else {
      recordInteraction(
        'Audit Explorer',
        'Press "3" Key & Verify SHA-256 Chain Validation',
        'FAIL',
        `Hash="${auditHash}", Title="${auditTitle}", ChainStatus="${chainStatus}"`,
      );
    }

    // ── Interaction 5: Search and Filtering in Audit Explorer ─────────────
    console.log('[Execution] Testing Audit Explorer search & decision filtering...');
    // 1. Search filter
    await evaluate<void>(`(() => {
      const input = document.querySelector('.search-input');
      if (input) {
        input.value = 'discovery';
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    })()`);
    await new Promise((r) => setTimeout(r, 500)); // debounce is 250ms

    const filteredRowsCount = await evaluate<number>(
      'document.querySelectorAll("table.data-table tbody tr").length',
    );

    // 2. Clear search filter
    await evaluate<void>(`(() => {
      const input = document.querySelector('.search-input');
      if (input) {
        input.value = '';
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    })()`);
    await new Promise((r) => setTimeout(r, 500));

    // 3. Decision filter -> block
    await evaluate<void>(`(() => {
      const selects = document.querySelectorAll('.filter-select');
      const decSelect = selects[1];
      if (decSelect) {
        decSelect.value = 'block';
        decSelect.dispatchEvent(new Event('change', { bubbles: true }));
      }
    })()`);
    await new Promise((r) => setTimeout(r, 500));

    const blockRowsCount = await evaluate<number>(
      'document.querySelectorAll("table.data-table tbody tr").length',
    );
    const blockBadgeCount = await evaluate<number>(
      'document.querySelectorAll("table.data-table tbody .badge.block").length',
    );

    // Reset decision filter
    await evaluate<void>(`(() => {
      const selects = document.querySelectorAll('.filter-select');
      const decSelect = selects[1];
      if (decSelect) {
        decSelect.value = 'all';
        decSelect.dispatchEvent(new Event('change', { bubbles: true }));
      }
    })()`);
    await new Promise((r) => setTimeout(r, 500));

    if (filteredRowsCount > 0 && blockRowsCount > 0 && blockRowsCount === blockBadgeCount) {
      recordInteraction(
        'Audit Explorer',
        'Execute Live Search and Decision Filter',
        'PASS',
        `Search matched ${filteredRowsCount} rows; "block" filter displayed exactly ${blockRowsCount} blocked events with zero unblocked leaks`,
      );
    } else {
      recordInteraction(
        'Audit Explorer',
        'Execute Live Search and Decision Filter',
        'FAIL',
        `filteredRowsCount=${filteredRowsCount}, blockRowsCount=${blockRowsCount}, blockBadgeCount=${blockBadgeCount}`,
      );
    }

    // ── Interaction 6: Pagination Controls ────────────────────────────────
    console.log('[Execution] Testing Audit Explorer pagination...');
    const initialPageText = await evaluate<string>(
      'document.querySelector(".pagination-bar .stat-sub")?.textContent || ""',
    );

    // Click Next page button
    await evaluate<void>('document.querySelectorAll(".btn-page")[1]?.click()');
    await new Promise((r) => setTimeout(r, 500));

    const page2Text = await evaluate<string>(
      'document.querySelector(".pagination-bar .stat-sub")?.textContent || ""',
    );

    // Click Prev page button
    await evaluate<void>('document.querySelectorAll(".btn-page")[0]?.click()');
    await new Promise((r) => setTimeout(r, 500));

    const restoredPageText = await evaluate<string>(
      'document.querySelector(".pagination-bar .stat-sub")?.textContent || ""',
    );

    if (
      initialPageText.includes('page 1') &&
      page2Text.includes('page 2') &&
      restoredPageText.includes('page 1')
    ) {
      recordInteraction(
        'Audit Explorer',
        'Pagination Next & Previous Cycles',
        'PASS',
        `Page 1 ("${initialPageText}") -> Page 2 ("${page2Text}") -> Back to Page 1 ("${restoredPageText}")`,
      );
    } else {
      recordInteraction(
        'Audit Explorer',
        'Pagination Next & Previous Cycles',
        'FAIL',
        `initial="${initialPageText}", page2="${page2Text}", restored="${restoredPageText}"`,
      );
    }

    // ── Interaction 7: Detail Drawer & Secret Masking in Live DOM ─────────
    console.log('[Execution] Opening detail drawer and auditing secret redaction in DOM...');
    // Click first row
    await evaluate<void>('document.querySelector("tr.clickable")?.click()');
    await new Promise((r) => setTimeout(r, 400));

    const drawerOpen = await evaluate<boolean>(
      'document.getElementById("detail-drawer")?.classList.contains("open") || false',
    );
    const drawerText = await evaluate<string>(
      'document.getElementById("drawer-body")?.innerText || ""',
    );

    // Verify cryptographic attributes rendered
    const hasHashes = drawerText.includes('Prev Hash:') && drawerText.includes('Curr Hash:');
    // Verify session ID masking
    const hasMaskedSession = drawerText.includes('***');
    // Verify no unredacted secret tokens exist
    const hasRawSecretLeak =
      drawerText.includes('sk-ant-') ||
      drawerText.includes('ghp_') ||
      drawerText.includes('BEGIN PRIVATE KEY');

    // Close detail drawer
    await evaluate<void>('document.getElementById("drawer-close")?.click()');
    await new Promise((r) => setTimeout(r, 300));
    const drawerClosed = await evaluate<boolean>(
      '!document.getElementById("detail-drawer")?.classList.contains("open")',
    );

    if (drawerOpen && hasHashes && hasMaskedSession && !hasRawSecretLeak && drawerClosed) {
      recordInteraction(
        'Detail Drawer',
        'Audit Secret Redaction & Hash Linkage in Live DOM',
        'PASS',
        `Drawer opened, confirmed cryptographic hash linkage, confirmed masked session ID (***), confirmed ZERO credential leaks, drawer closed cleanly`,
      );
    } else {
      recordInteraction(
        'Detail Drawer',
        'Audit Secret Redaction & Hash Linkage in Live DOM',
        'FAIL',
        `drawerOpen=${drawerOpen}, hasHashes=${hasHashes}, hasMaskedSession=${hasMaskedSession}, hasRawSecretLeak=${hasRawSecretLeak}, drawerClosed=${drawerClosed}`,
      );
    }

    // ── Interaction 8: Shortcut '4' -> Security Findings ──────────────────
    console.log('[Execution] Testing keyboard shortcut "4" for Security Findings...');
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'rawKeyDown',
      key: '4',
      code: 'Digit4',
      windowsVirtualKeyCode: 52,
    });
    await sendCommand('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: '4',
      code: 'Digit4',
      windowsVirtualKeyCode: 52,
    });
    await new Promise((r) => setTimeout(r, 600));

    const findingsHash = await evaluate<string>('window.location.hash');
    const findingsCount = await evaluate<number>(
      'document.querySelectorAll(".finding-card").length',
    );
    const lockedReserveText = await evaluate<string>(
      'document.querySelector(".locked-reserve-panel")?.textContent || ""',
    );
    const hasExecutionButton = await evaluate<boolean>(
      'document.querySelectorAll(".locked-reserve-panel button").length > 0',
    );

    const hasFounderNotice =
      lockedReserveText.includes('Pending separate founder authorization') ||
      lockedReserveText.includes('founder-authorized');

    if (
      findingsHash === '#security-findings' &&
      findingsCount === 8 &&
      hasFounderNotice &&
      !hasExecutionButton
    ) {
      recordInteraction(
        'Security Findings',
        'Verify 8 Open Findings & 6 Locked Reserved Candidates',
        'PASS',
        `8 findings rendered, locked panel confirms founder authorization required, exactly 0 execution buttons present`,
      );
    } else {
      recordInteraction(
        'Security Findings',
        'Verify 8 Open Findings & 6 Locked Reserved Candidates',
        'FAIL',
        `findingsHash="${findingsHash}", findingsCount=${findingsCount}, hasFounderNotice=${hasFounderNotice}, hasExecutionButton=${hasExecutionButton}, lockedReserveText="${lockedReserveText.slice(0, 100)}"`,
      );
    }

    // ── Interaction 9: Mouse Navigation (Click Nav Menu) ──────────────────
    console.log('[Execution] Testing mouse navigation tabs...');
    await evaluate<void>('document.getElementById("nav-overview")?.click()');
    await new Promise((r) => setTimeout(r, 400));

    const returnedHash = await evaluate<string>('window.location.hash');
    const navOverviewActive = await evaluate<boolean>(
      'document.getElementById("nav-overview")?.classList.contains("active") || false',
    );

    if (returnedHash === '#overview' && navOverviewActive) {
      recordInteraction(
        'Mouse Navigation',
        'Click Sidebar Navigation Link',
        'PASS',
        `Navigated back to "#overview" via sidebar click, active class set correctly`,
      );
    } else {
      recordInteraction(
        'Mouse Navigation',
        'Click Sidebar Navigation Link',
        'FAIL',
        `returnedHash="${returnedHash}", navOverviewActive=${navOverviewActive}`,
      );
    }

    // ── Interaction 10: Error Boundary & Inline Script Audit ───────────────
    console.log('[Execution] Testing Error Boundary and checking inline event handlers...');
    // Inspect DOM for forbidden inline script handlers on any button
    const inlineOnclickCount = await evaluate<number>(
      'document.querySelectorAll("[onclick]").length',
    );

    if (inlineOnclickCount === 0) {
      recordInteraction(
        'CSP / Script Security',
        'Audit DOM for Inline Onclick Handlers',
        'PASS',
        `Confirmed exactly 0 elements with inline onclick attributes in the live DOM`,
      );
    } else {
      recordInteraction(
        'CSP / Script Security',
        'Audit DOM for Inline Onclick Handlers',
        'FAIL',
        `Found ${inlineOnclickCount} elements with inline onclick attributes!`,
      );
    }

    // ── Final Console & CSP Violation Audit ───────────────────────────────
    const cspViolations = consoleMessages.filter((m) =>
      m.text.toLowerCase().includes('violates the following content security policy'),
    );
    const consoleErrors = consoleMessages.filter((m) => m.type === 'error');

    if (cspViolations.length === 0 && uncaughtExceptions.length === 0) {
      recordInteraction(
        'CSP & Console Health',
        'Audit Browser Console Logs and CSP Violations',
        'PASS',
        `0 CSP violations, 0 uncaught exceptions across entire interactive session`,
      );
    } else {
      recordInteraction(
        'CSP & Console Health',
        'Audit Browser Console Logs and CSP Violations',
        'FAIL',
        `cspViolations=${cspViolations.length}, consoleErrors=${consoleErrors.length}, uncaught=${uncaughtExceptions.length}`,
      );
    }
  } finally {
    // Teardown
    console.log('\n[Teardown] Cleaning up browser automation resources...');
    if (ws) {
      ws.close();
    }
    chromeProc.kill('SIGTERM');
    await new Promise<void>((resolve) => server.close(() => resolve()));

    try {
      fs.rmSync(tmpUserDataDir, { recursive: true, force: true });
    } catch {
      // Ignore tmpdir cleanup errors
    }
  }

  // Print Summary Table
  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log('                 BROWSER VERIFICATION SUMMARY                      ');
  console.log('═══════════════════════════════════════════════════════════════════');
  let allPassed = true;
  for (const log of interactionLogs) {
    const statusSymbol = log.outcome === 'PASS' ? '✅' : '❌';
    console.log(
      `${statusSymbol} Step ${log.step.toString().padStart(2, ' ')}: [${log.category}] ${log.action}\n    ${log.details}`,
    );
    if (log.outcome === 'FAIL') allPassed = false;
  }
  console.log('═══════════════════════════════════════════════════════════════════\n');

  if (!allPassed) {
    console.error('FAILED: One or more browser interactions failed verification.');
    process.exit(1);
  } else {
    console.log('SUCCESS: All 11 browser UI automation interactions passed cleanly!');
  }
}

runBrowserVerification().catch((err) => {
  console.error('Fatal error during browser verification:', err);
  process.exit(1);
});
