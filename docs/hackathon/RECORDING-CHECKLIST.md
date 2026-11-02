# Veylith — Presentation & Video Recording Checklist

This runbook ensures clean, reproducible, and professional video recording or live demonstration of the Veylith AI Agent Security Boundary for hackathon judges.

---

## 1. System & Environment Preflight

### A. Terminal Preparation

- [ ] Open a clean terminal window (zsh/bash).
- [ ] Confirm clean git working tree and correct branch:
  ```bash
  git branch --show-current
  # Expected: dev/phase-5d-live-validation
  ```
- [ ] Verify node version and dependencies:
  ```bash
  node -v   # >= v20.0.0
  pnpm -v   # >= 9.x
  ```
- [ ] Ensure terminal color support is active (or verify `NO_COLOR` behavior if using a monochrome terminal).
- [ ] Clear terminal history and scrollback buffer (`clear` or `Cmd+K` on macOS).
- [ ] Set terminal font size to **14pt – 16pt** with monospace font (SF Mono, Menlo, or Fira Code) for high-DPI video readability.

### B. Credential Safety Check

- [ ] Verify that no API keys or sensitive credentials are present in the active shell environment:
  ```bash
  env | grep -E "META_|FIREWORKS_|BASETEN_|OPENAI_|ANTHROPIC_"
  # Should return empty or be safely managed via local .env (never printed)
  ```
- [ ] The demonstration runner `pnpm demo` automatically scrubs both `META_MODEL_API_KEY` and `META_API_KEY` in child environments.

---

## 2. Dashboard Launch & Browser Preparation

### A. Launch Local Research Dashboard

In a dedicated terminal tab or background window, start the local dashboard:

```bash
pnpm --filter @veylith/research-dashboard start
```

Expected startup output:

```text
╔═══════════════════════════════════════════════════════════════════════════════╗
║                   VEYLITH — LOCAL SECURITY RESEARCH DASHBOARD                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  • Status: Active (Read-Only)                                                 ║
║  • Host: 127.0.0.1 (Loopback Only, Strictly No Remote Access)                 ║
║  • URL: http://127.0.0.1:8789                                                 ║
║  • Evaluation: Mock & Deterministic Evidence (0 Paid API Calls)               ║
║  • Security Boundary: Non-Production Research Prototype                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

### B. Browser Configuration

- [ ] Open **Google Chrome** or **Brave/Edge** and navigate to `http://127.0.0.1:8789`.
- [ ] Set browser zoom to **100%** (default).
- [ ] Hide bookmarks bar (`Cmd+Shift+B` on macOS).
- [ ] Disable third-party extensions that might alter DOM or inject CSS.
- [ ] Verify dark theme contrast and confirm zero console warnings or CSP errors (`Cmd+Option+J`).

### C. Screen Resolution & Window Arrangement

- **Recommended Display Resolution:** `1920 x 1080` (1080p, 16:9) or `2560 x 1440` (1440p, 16:9) scaled to 2x for retina sharpness.
- **Window Arrangement Options:**
  - **Option 1 (Tab Switching):** Fullscreen browser showing Dashboard (`8789`), switching to fullscreen terminal for Step 2 (`pnpm demo`).
  - **Option 2 (Split Screen):** Left 60% browser, Right 40% terminal. (Optimal for showing simultaneous UI update or side-by-side terminal verification).

---

## 3. Demonstration Flow Verification Run

Before recording, execute a dry run of the complete 3-minute sequence:

| Step  | Action              |  Shortcut / Command  | Verification Criteria                                                                                                           |
| :---: | :------------------ | :------------------: | :------------------------------------------------------------------------------------------------------------------------------ |
| **1** | Project Overview    |       Key `1`        | Architecture diagram renders cleanly; latency table visible.                                                                    |
| **2** | Batch Terminal Demo | `pnpm demo -- --all` | All 4 scenarios PASS; loopback summary printed in ~2s.                                                                          |
| **3** | Evaluation Lab      |       Key `2`        | Switch to Phase 2A (`#tab-p2a`), Phase 2E (`#tab-p2e`), and Phase 2F (`#tab-p2f`). Denominators and exclusions display clearly. |
| **4** | Audit Explorer      |       Key `3`        | "Chain Integrity Validated" visible; click row 1 to open detail drawer with masked secrets.                                     |
| **5** | Security Findings   |       Key `4`        | 8 open findings rendered; 6 reserved live candidates show "Locked / No Execution Allowed".                                      |

---

## 4. Audio & Video Recording Settings

- **Video Framerate:** 30 fps or 60 fps (constant framerate).
- **Video Bitrate:** >= 8,000 kbps (1080p) or >= 14,000 kbps (1440p) to avoid compression artifacts on code text.
- **Audio Sample Rate:** 48 kHz, 16-bit stereo/mono.
- **Microphone:** Dedicated external microphone with pop filter; verify input gain levels (peaks around -6 dB to -3 dB, no clipping).
- **System Sounds:** Disable all OS notifications, Slack/Discord alerts, and mail chime notifications (`Do Not Disturb` / `Focus Mode` enabled on macOS).

---

## 5. Recovery Procedures (Troubleshooting)

### A. Port Conflict on Startup

If port `8789` or demo ports `19887`/`19888` are occupied by a dangling process from a previous run:

```bash
# Check if port 8789 is in use:
lsof -i :8789
# Terminate orphaned process:
kill -9 <PID>

# Check if demo ports are in use:
lsof -i :19887 -i :19888
kill -9 $(lsof -t -i :19887 -i :19888) 2>/dev/null || true
```

### B. Client Assets Not Updating

If CSS or TypeScript changes in the dashboard client are not reflected:

```bash
# Force re-bundle client assets:
pnpm --filter @veylith/research-dashboard run build:client
# Hard refresh browser (Cmd+Shift+R)
```

### C. Terminal Process Hangs During Interactive Demo

If an interactive demo session hangs waiting for stdin:

- Press `Ctrl+C` to cleanly terminate child gateway and upstream server processes.
- Alternatively, run batch mode directly: `pnpm demo -- --all`.

---

## 6. Pre-Recording Final Checklist

- [ ] `pnpm test:all` verified 100% passing (402/402 tests, 43 files).
- [ ] `verify-browser-cdp.ts` verified 100% passing (12/12 steps).
- [ ] No git unstaged changes in historical canary evidence (`security-lab/compat-results/*`).
- [ ] Live candidate reserve file (`security-lab/v1/live-reserve.json`) remains completely unexecuted.
- [ ] Browser window positioned at `http://127.0.0.1:8789/#overview`.
- [ ] Presenter walkthrough script (`docs/hackathon/JUDGE-WALKTHROUGH.md`) ready.
- [ ] Screen recorder armed.
