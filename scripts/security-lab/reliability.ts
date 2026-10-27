import fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { syncBuiltinESMExports } from 'node:module';
import { spawn, execFileSync } from 'node:child_process';
import { AuditLogChain } from '../../packages/policy-engine/src/audit/chain.js';
import { ClientSessionManager } from '../../packages/policy-engine/src/sessions/manager.js';
import { Fixture } from './fixture.js';
import { readFileSync } from 'node:fs';
import type { LabCase } from './types.js';
import { request } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { connect as socketConnect } from 'node:net';
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'veylith-2e-'));
const results: Array<{ name: string; passed: boolean; evidence: unknown; durationMs: number }> = [];
async function probe(name: string, fn: () => unknown | Promise<unknown>) {
  const t = performance.now();
  console.log(`probe: ${name}`);
  try {
    results.push({ name, passed: true, evidence: await fn(), durationMs: performance.now() - t });
  } catch (e) {
    results.push({ name, passed: false, evidence: String(e), durationMs: performance.now() - t });
  }
}
function check(condition: unknown, message: string) {
  if (!condition) throw new Error(message);
}
const input = {
  serverId: 'synthetic-local',
  mcpMethod: 'tools/call',
  stage: 'call_arguments' as const,
  decision: 'allow' as const,
  reasonCode: 'fixture',
  policyVersion: '2e',
  latencyMs: 0,
};
function open(name: string) {
  return new AuditLogChain({ storagePath: path.join(temporary, name) });
}
try {
  await probe('abrupt process termination, durable acknowledgement, restart', async () => {
    const file = path.join(temporary, 'crash.jsonl');
    const child = spawn(
      process.execPath,
      ['--import', 'tsx', 'scripts/security-lab/audit-child.ts', file, '--wait'],
      { stdio: ['ignore', 'pipe', 'pipe', 'ipc'] },
    );
    await new Promise<void>((resolve, reject) => {
      child.once('message', () => resolve());
      child.once('error', reject);
      child.once('exit', (code) => reject(new Error(`Premature exit ${code}`)));
    });
    const exited = new Promise((resolve) => child.once('exit', resolve));
    child.kill('SIGKILL');
    await exited;
    const chain = new AuditLogChain({ storagePath: file });
    check(chain.verifyChain().valid && chain.getRecords().length === 1, 'Acknowledged record lost');
    chain.append(input);
    chain.close();
    return {
      acknowledgedRecordsRecovered: 1,
      restartAppendSucceeded: true,
      scope: 'process death after fsync acknowledgement, not power-loss simulation',
    };
  });
  await probe('incomplete final JSONL line fails startup without silent repair', () => {
    const a = open('torn.jsonl');
    a.append(input);
    a.close();
    fs.appendFileSync(path.join(temporary, 'torn.jsonl'), '{"partial":');
    let rejected = false;
    try {
      open('torn.jsonl');
    } catch {
      rejected = true;
    }
    check(rejected, 'Torn JSONL accepted');
    return { rejected };
  });
  await probe('concurrent processes reject stale chain writers', async () => {
    // Two cooperating writers may win serially or reject a stale state; never accept a broken chain.
    const file = path.join(temporary, 'concurrent.jsonl');
    const codes = await Promise.all(
      Array.from(
        { length: 4 },
        () =>
          new Promise<number | null>((resolve, reject) => {
            const p = spawn(
              process.execPath,
              ['--import', 'tsx', 'scripts/security-lab/audit-child.ts', file],
              { stdio: 'ignore' },
            );
            p.on('error', reject);
            p.on('exit', resolve);
          }),
      ),
    );
    const loaded = new AuditLogChain({ storagePath: file });
    const valid = loaded.verifyChain().valid;
    loaded.close();
    check(valid, 'Concurrent writers corrupted log');
    return { exitCodes: codes, valid, availabilityMayRejectStaleWriters: true };
  });
  await probe('two in-process writers and live truncation fail closed', () => {
    const a = open('stale.jsonl'),
      b = open('stale.jsonl');
    a.append(input);
    let rejected = false;
    try {
      b.append(input);
    } catch {
      rejected = true;
    }
    a.close();
    b.close();
    check(rejected, 'Stale writer accepted');
    const c = open('stale.jsonl');
    fs.truncateSync(path.join(temporary, 'stale.jsonl'), 0);
    let truncatedRejected = false;
    try {
      c.append(input);
    } catch {
      truncatedRejected = true;
    }
    c.close();
    check(truncatedRejected, 'Live truncation accepted');
    return {
      rejected,
      truncatedRejected,
      validPrefixTruncationAfterRestart: 'not detectable without external anchor',
    };
  });
  await probe('simulated ENOSPC, partial write, sticky failure, restart quarantine', () => {
    const chain = open('enospc.jsonl');
    const original = fs.writeSync;
    let calls = 0;
    fs.writeSync = ((fd: number, buffer: Uint8Array, offset: number, length: number) => {
      calls++;
      if (calls === 1) return original(fd, buffer, offset, Math.min(9, length));
      throw Object.assign(new Error('Synthetic disk-full'), { code: 'ENOSPC' });
    }) as typeof fs.writeSync;
    syncBuiltinESMExports();
    let rejected = false;
    try {
      chain.append(input);
    } catch {
      rejected = true;
    } finally {
      fs.writeSync = original;
      syncBuiltinESMExports();
    }
    let sticky = false;
    try {
      chain.append(input);
    } catch {
      sticky = true;
    }
    chain.close();
    let restartRejected = false;
    try {
      open('enospc.jsonl');
    } catch {
      restartRejected = true;
    }
    check(rejected && sticky && restartRejected, 'Write failure did not quarantine');
    return { rejected, sticky, restartRejected, realDiskExhaustion: false };
  });
  await probe('closed persistent audit sink cannot become memory-only', () => {
    const c = open('closed.jsonl');
    c.close();
    let denied = false;
    try {
      c.append(input);
    } catch {
      denied = true;
    }
    check(denied, 'Closed sink silently accepted');
    return { denied };
  });
  await probe('fsync overhead, 200 appends per arm', () => {
    const memory = new AuditLogChain(),
      disk = open('throughput.jsonl');
    const n = 200;
    let t = performance.now();
    for (let i = 0; i < n; i++) memory.append(input);
    const memoryMs = performance.now() - t;
    t = performance.now();
    for (let i = 0; i < n; i++) disk.append(input);
    const diskMs = performance.now() - t;
    disk.close();
    return {
      n,
      memoryMs,
      diskWithLockAndFsyncMs: diskMs,
      memoryAppendsPerSecond: (n * 1000) / memoryMs,
      durableAppendsPerSecond: (n * 1000) / diskMs,
      perAppendOverheadMs: (diskMs - memoryMs) / n,
      note: 'Includes JSON, lock and fsync; not a pure fsync microbenchmark',
    };
  });
  await probe('local session TTL persists through validation', () => {
    const manager = new ClientSessionManager();
    const s = manager.createSession({ clientIdentity: 'alice', serverId: 'local', ttlMs: 40 });
    const checked = manager.validateSession(s.sessionId);
    check(checked.session && checked.session.expiresAt - Date.now() <= 40, 'Custom TTL expanded');
    return { ttlMs: 40, remainingMs: checked.session!.expiresAt - Date.now() };
  });
  await probe('repeated create/load/cleanup cycles with retained-heap GC samples', () => {
    const retained: number[] = [];
    for (let cycle = 0; cycle < 12; cycle++) {
      const sessions = new ClientSessionManager();
      const chain = new AuditLogChain();
      for (let i = 0; i < 1000; i++) {
        sessions.createSession({ clientIdentity: `c-${i}`, serverId: 'local', ttlMs: -1 });
        chain.append(input);
      }
      sessions.cleanupExpiredSessions();
      check(sessions.getActiveSessionsCount() === 0, 'Session cleanup failed');
      chain.reset();
      global.gc?.();
      retained.push(process.memoryUsage().heapUsed);
    }
    return {
      cycles: 12,
      objectsPerCycle: 1000,
      gcAvailable: Boolean(global.gc),
      retainedHeapBytes: retained,
      growthBytes: retained.at(-1)! - retained[0]!,
      scope:
        'session/audit component cycles; full HTTP cycles separately sampled; no zero-leak conclusion',
    };
  });
  // Real HTTP adapter, ephemeral loopback ports, no special SDK in front of HTTP status probes.
  const fixture = new Fixture();
  await fixture.start();
  fixture.reset(JSON.parse(readFileSync('security-lab/v1/development.json', 'utf8'))[0] as LabCase);
  Object.assign(process.env, {
    GATEWAY_HOST: '127.0.0.1',
    UPSTREAM_MCP_URL: fixture.url,
    META_AI_MODE: 'disabled',
    ENFORCE_SESSIONS: 'false',
    MAX_CONCURRENT_REQUESTS: '2',
    LOG_LEVEL: 'error',
  });
  delete process.env['MAX_REQUEST_BODY_BYTES'];
  delete process.env['AUDIT_LOG_PATH'];
  const gw = await import('../../apps/gateway/src/server.js');
  await new Promise<void>((resolve) => gw.httpServer.listen(0, '127.0.0.1', resolve));
  const address = gw.httpServer.address();
  if (!address || typeof address === 'string') throw new Error('No port');
  const endpoint = `http://127.0.0.1:${address.port}/mcp`;
  try {
    await probe('default body limit and client-observed HTTP 413', async () => {
      check(gw.config.maxRequestBodyBytes === 1048576, 'Wrong default');
      const r = await fetch(endpoint, { method: 'POST', body: 'A'.repeat(1048577) });
      const body = await r.text();
      check(r.status === 413, 'Client did not receive 413');
      return { defaultBytes: gw.config.maxRequestBodyBytes, httpStatus: r.status, body };
    });
    await probe('malformed JSON produces client-observed HTTP 400', async () => {
      const r = await fetch(endpoint, { method: 'POST', body: '{"partial":' });
      await r.text();
      check(r.status === 400, 'Malformed JSON not rejected');
      return { httpStatus: r.status };
    });
    await probe('truncated upload and early disconnect do not crash gateway', async () => {
      await new Promise<void>((resolve) => {
        const s = socketConnect(address.port, '127.0.0.1', () => {
          s.write('POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n{');
          s.end();
        });
        s.on('data', () => {});
        s.setTimeout(1000, () => s.destroy());
        s.on('close', () => resolve());
        s.on('error', () => resolve());
      });
      const r = await fetch(endpoint, { method: 'POST', body: '{' });
      await r.text();
      check(r.status === 400, 'Gateway did not recover');
      return { recoveryStatus: r.status };
    });
    await probe(
      'slow response consumer drains a large harmless response without truncation',
      async () => {
        const original = fixture.current;
        fixture.current = {
          ...original,
          operation: 'response',
          input: 'Z'.repeat(2 * 1024 * 1024),
        };
        try {
          const bytes = await new Promise<number>((resolve, reject) => {
            const r = request(
              endpoint,
              {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  Accept: 'application/json, text/event-stream',
                },
              },
              (res) => {
                let size = 0;
                res.pause();
                setTimeout(() => res.resume(), 25);
                res.on('data', (chunk) => {
                  size += chunk.length;
                });
                res.on('end', () => resolve(size));
                res.on('error', reject);
              },
            );
            r.on('error', reject);
            r.setTimeout(5000, () => r.destroy(new Error('Slow consumer timeout')));
            r.end(
              JSON.stringify({
                jsonrpc: '2.0',
                id: 41,
                method: 'tools/call',
                params: { name: 'reader', arguments: {} },
              }),
            );
          });
          check(bytes >= 2 * 1024 * 1024, 'Large response truncated');
          return { responseBytes: bytes, consumerPauseMs: 25 };
        } finally {
          fixture.current = original;
        }
      },
    );
    await probe('six full MCP load and cleanup cycles with GC samples', async () => {
      const heap: number[] = [];
      for (let cycle = 0; cycle < 6; cycle++) {
        const client = new Client({ name: 'retained-heap-probe', version: '1' });
        try {
          await client.connect(new StreamableHTTPClientTransport(new URL(endpoint)));
          for (let i = 0; i < 25; i++)
            await client.callTool({
              name: 'reader',
              arguments: { marker: `cycle-${cycle}-call-${i}` },
            });
        } finally {
          await client.close();
        }
        gw.auditChain.reset();
        gw.sessionManager.reset();
        gw.invalidateDiscoveryCache();
        global.gc?.();
        heap.push(process.memoryUsage().heapUsed);
      }
      return {
        cycles: 6,
        callsPerCycle: 25,
        gcAvailable: Boolean(global.gc),
        retainedHeapBytes: heap,
        growthBytes: heap.at(-1)! - heap[0]!,
        scope: 'single process gateway + fixture + SDK; short diagnostic, not a zero-leak claim',
      };
    });
    await probe('slow uploads occupy admission slots; client observes 429', async () => {
      const pending: ReturnType<typeof request>[] = [];
      try {
        for (let i = 0; i < 2; i++) {
          const p = request(
            endpoint,
            { method: 'POST', headers: { 'Content-Length': '1000' } },
            (res) => res.resume(),
          );
          p.on('error', () => {});
          p.write('{');
          pending.push(p);
        }
        await new Promise((resolve) => setTimeout(resolve, 30));
        const r = await fetch(endpoint, { method: 'POST', body: '{}' });
        await r.text();
        check(r.status === 429, 'Body-read admission bypass');
        return { httpStatus: r.status };
      } finally {
        pending.forEach((p) => p.destroy());
      }
    });
  } finally {
    gw.httpServer.closeAllConnections();
    await new Promise<void>((resolve) => gw.httpServer.close(() => resolve()));
    await gw.handler.close();
    await fixture.stop();
  }
} finally {
  fs.rmSync(temporary, { recursive: true, force: true });
}
fs.mkdirSync('security-lab/results', { recursive: true });
const report = {
  gitCommit: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  hardware: {
    cpu: os.cpus()[0]?.model,
    logicalCpus: os.cpus().length,
    memoryBytes: os.totalmem(),
    os: os.release(),
    node: process.version,
  },
  actualPaidCalls: 0,
  results,
};
fs.writeFileSync('security-lab/results/reliability.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(results, null, 2));
if (results.some((r) => !r.passed)) process.exitCode = 1;
