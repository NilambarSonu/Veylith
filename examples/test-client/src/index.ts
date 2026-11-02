/**
 * Veylith Test Client — exercises the benign MCP server.
 *
 * Can connect either directly to the upstream server or through
 * the Veylith gateway, depending on the UPSTREAM_URL environment variable.
 *
 * Default: http://127.0.0.1:8788/mcp (direct to benign server)
 * Via gateway: http://127.0.0.1:8787/mcp
 */

import { Client } from '@modelcontextprotocol/client';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';

const TARGET_URL = process.env['UPSTREAM_URL'] ?? 'http://127.0.0.1:8788/mcp';

async function main(): Promise<void> {
  console.log(`[test-client] Connecting to ${TARGET_URL}...`);

  const client = new Client({ name: 'veylith-test-client', version: '0.1.0' });

  const transport = new StreamableHTTPClientTransport(new URL(TARGET_URL));
  await client.connect(transport);
  console.log('[test-client] Connected successfully.\n');

  // 1. List tools
  console.log('=== tools/list ===');
  const { tools } = await client.listTools();
  for (const tool of tools) {
    console.log(`  ${tool.name} — ${tool.description}`);
  }
  console.log(`  (${tools.length} tools found)\n`);

  // 2. Call echo
  console.log('=== tools/call: echo ===');
  const echoResult = await client.callTool({
    name: 'echo',
    arguments: { message: 'Hello from Veylith!' },
  });
  for (const block of echoResult.content as Array<{ type: string; text: string }>) {
    if (block.type === 'text') console.log(`  Result: ${block.text}`);
  }
  console.log();

  // 3. Call add
  console.log('=== tools/call: add ===');
  const addResult = await client.callTool({
    name: 'add',
    arguments: { a: 42, b: 58 },
  });
  for (const block of addResult.content as Array<{ type: string; text: string }>) {
    if (block.type === 'text') console.log(`  Result: ${block.text}`);
  }
  console.log();

  // 4. Try restricted_demo_tool (should be blocked when going through gateway)
  console.log('=== tools/call: restricted_demo_tool ===');
  try {
    const restrictedResult = await client.callTool({
      name: 'restricted_demo_tool',
      arguments: { action: 'test' },
    });
    for (const block of restrictedResult.content as Array<{
      type: string;
      text: string;
    }>) {
      if (block.type === 'text') console.log(`  Result: ${block.text}`);
    }
    if (restrictedResult.isError) {
      console.log(`  (returned as error result)`);
    }
  } catch (err) {
    console.log(`  Blocked/Error: ${err instanceof Error ? err.message : String(err)}`);
  }
  console.log();

  // Clean up
  await client.close();
  console.log('[test-client] Done.');
}

main().catch((err) => {
  console.error('[test-client] Fatal error:', err);
  process.exit(1);
});
