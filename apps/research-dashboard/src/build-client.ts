import * as esbuild from 'esbuild';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

async function buildClient() {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  const clientSrcDir = path.resolve(currentDir, 'client');
  const clientDistDir = path.resolve(currentDir, '..', 'dist', 'client');

  if (!fs.existsSync(clientDistDir)) {
    fs.mkdirSync(clientDistDir, { recursive: true });
  }

  console.log('[build-client] Bundling research dashboard client SPA...');

  await esbuild.build({
    entryPoints: [path.join(clientSrcDir, 'app.ts')],
    bundle: true,
    outfile: path.join(clientDistDir, 'app.js'),
    format: 'esm',
    target: 'es2022',
    minify: false,
    sourcemap: true,
  });

  // Copy HTML and CSS
  fs.copyFileSync(path.join(clientSrcDir, 'index.html'), path.join(clientDistDir, 'index.html'));
  fs.copyFileSync(path.join(clientSrcDir, 'styles.css'), path.join(clientDistDir, 'styles.css'));

  console.log('[build-client] Client assets bundled successfully to dist/client');
}

buildClient().catch((err) => {
  console.error('[build-client] Build failed:', err);
  process.exit(1);
});
