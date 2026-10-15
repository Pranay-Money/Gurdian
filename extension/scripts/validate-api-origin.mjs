import fs from 'node:fs';
import path from 'node:path';

const rawApiOrigin = (process.env.API_ORIGIN || process.env.VITE_API_URL || '').trim();

if (!rawApiOrigin) {
  console.error('ERROR: API_ORIGIN is required for production builds.');
  process.exit(1);
}

const apiOrigin = rawApiOrigin.replace(/\/+$/, '');
if (apiOrigin.endsWith('.example')) {
  console.error(`ERROR: API_ORIGIN must not end in .example: ${apiOrigin}`);
  process.exit(1);
}

const packageJsonPath = path.resolve(process.cwd(), 'package.json');
if (!fs.existsSync(packageJsonPath)) {
  console.error(`ERROR: package.json not found at ${packageJsonPath}`);
  process.exit(1);
}

console.log(`API_ORIGIN validated: ${apiOrigin}`);
