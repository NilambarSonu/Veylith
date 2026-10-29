import { createServer, type Server } from 'node:http';
import { loadDashboardConfig, type DashboardConfig } from './config.js';
import { EvidenceLoader } from './evidence-loader.js';
import { createRouter } from './routes.js';

export function startDashboardServer(
  customConfig?: Partial<DashboardConfig>,
): Promise<{ server: Server; port: number; url: string }> {
  const baseConfig = loadDashboardConfig();
  const config: DashboardConfig = {
    ...baseConfig,
    ...customConfig,
  };

  const loader = new EvidenceLoader(config);
  const router = createRouter(config, loader);
  const server = createServer(router);

  return new Promise((resolve, reject) => {
    server.on('error', (err) => {
      reject(err);
    });

    // Strictly bind to 127.0.0.1 (never 0.0.0.0)
    server.listen(config.port, '127.0.0.1', () => {
      const address = server.address();
      const actualPort =
        typeof address === 'object' && address !== null ? address.port : config.port;
      const url = `http://127.0.0.1:${actualPort}`;
      resolve({ server, port: actualPort, url });
    });
  });
}

// When executed directly via tsx/node
if (process.argv[1]?.endsWith('server/index.ts') || process.argv[1]?.endsWith('server/index.js')) {
  startDashboardServer()
    .then(({ url }) => {
      console.log(`
╔═══════════════════════════════════════════════════════════════════════════════╗
║                   VEYLITH — LOCAL SECURITY RESEARCH DASHBOARD                 ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  • Status: Active (Read-Only)                                                 ║
║  • Host: 127.0.0.1 (Loopback Only, Strictly No Remote Access)                 ║
║  • URL: ${url.padEnd(68)}║
║  • Evaluation: Mock & Deterministic Evidence (0 Paid API Calls)               ║
║  • Security Boundary: Non-Production Research Prototype                       ║
╚═══════════════════════════════════════════════════════════════════════════════╝
Press Ctrl+C to terminate.
`);

      const handleShutdown = () => {
        console.log('\n[Veylith Dashboard] Shutting down cleanly...');
        process.exit(0);
      };

      process.on('SIGINT', handleShutdown);
      process.on('SIGTERM', handleShutdown);
    })
    .catch((err) => {
      console.error('[Veylith Dashboard] Failed to start server:', err);
      process.exit(1);
    });
}
