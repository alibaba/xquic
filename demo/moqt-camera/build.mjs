import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = path.dirname(fileURLToPath(import.meta.url));
const moq = process.argv[2] && path.resolve(process.argv[2]);
if (!moq) throw new Error('Usage: node build.mjs /path/to/moq-web [relay-url]');
const relay = process.argv[3] || '';
if (relay && new URL(relay).protocol !== 'https:') {
    throw new Error('Relay URL must use HTTPS');
}
const esbuild = await import(path.join(moq,
    'node_modules/.pnpm/node_modules/esbuild/lib/main.js'));
await fs.mkdir(path.join(root, 'dist'), { recursive: true });
await esbuild.build({ entryPoints: [path.join(root, 'src/main.js')],
    outfile: path.join(root, 'dist/app.js'), bundle: true, format: 'esm',
    sourcemap: true, target: 'chrome120',
    define: { __MOQT_VERSION__: JSON.stringify('draft-22'),
        __DEFAULT_RELAY_URL__: JSON.stringify(relay) },
    alias: {
        '@moq-web/core': path.join(moq, 'packages/core/src/index.ts'),
        '@moq-web/session': path.join(moq, 'packages/session/src/index.ts'),
    }, logLevel: 'info' });
for (const name of ['index.html', 'style.css']) {
    await fs.copyFile(path.join(root, 'src', name), path.join(root, 'dist', name));
}
