import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';

const args = process.argv.slice(2);
const env = {
  ...process.env,
  API_ORIGIN: process.env.API_ORIGIN || process.env.VITE_API_URL || 'http://localhost:8000',
};

const viteEntry = createRequire(import.meta.url).resolve('vite');
const viteBin = path.resolve(viteEntry, '..', '..', '..', 'bin', 'vite.js');
const result = spawnSync(process.execPath, [viteBin, ...args], {
  stdio: 'inherit',
  env,
});

if (result.error) {
  throw result.error;
}

process.exit(result.status ?? 1);
