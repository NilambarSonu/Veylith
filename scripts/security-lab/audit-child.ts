import { AuditLogChain } from '../../packages/policy-engine/src/audit/chain.js';
const chain = new AuditLogChain({ storagePath: process.argv[2] });
chain.append({
  serverId: 'synthetic-local',
  mcpMethod: 'tools/call',
  stage: 'call_arguments',
  decision: 'allow',
  reasonCode: 'fixture',
  policyVersion: '2e',
  latencyMs: 0,
});
if (process.argv.includes('--wait')) {
  process.send?.({ durable: true });
  setInterval(() => {}, 1000);
} else {
  chain.close();
}
