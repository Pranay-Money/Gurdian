import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import fs from 'fs';
import path from 'path';

const packageJson = JSON.parse(fs.readFileSync('./package.json', 'utf-8'));
const version = packageJson.version;
const rawApiOrigin = (process.env.API_ORIGIN || process.env.VITE_API_URL || '').trim();

if (!rawApiOrigin) {
  throw new Error('API_ORIGIN is required for production builds. Set API_ORIGIN to the production API origin (for example https://api.guardian.example).');
}

const apiOrigin = rawApiOrigin.replace(/\/+$/, '');
if (apiOrigin.endsWith('.example')) {
  throw new Error(`API_ORIGIN must not end in .example: ${apiOrigin}`);
}

export default defineConfig({
  plugins: [
    react(),
    {
      name: 'copy-root-htmls',
      writeBundle() {
        const htmlMappings = [
          ['src/popup/index.html', 'popup.html'],
          ['src/options/index.html', 'options.html'],
          ['src/blocked/index.html', 'blocked.html'],
          ['src/analyze-popup/index.html', 'analyze-popup.html'],
        ];

        for (const [sourceRelative, targetName] of htmlMappings) {
          const sourcePath = path.resolve(__dirname, 'dist', sourceRelative);
          const targetPath = path.resolve(__dirname, 'dist', targetName);
          if (fs.existsSync(sourcePath)) {
            fs.copyFileSync(sourcePath, targetPath);
          }
        }
      },
    },
    {
      name: 'update-manifest-version',
      generateBundle() {
        const manifestPath = path.resolve(__dirname, 'dist/manifest.json');
        if (!fs.existsSync(manifestPath)) return;

        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        manifest.version = version;
        manifest.host_permissions = [`${apiOrigin}/*`];
        manifest.optional_host_permissions = [
          '*://mail.google.com/*',
          '*://outlook.live.com/*',
          '*://*.office.com/*',
          '*://*.office365.com/*',
          '*://mail.yahoo.com/*',
          '*://*.proton.me/*',
          '*://*.protonmail.com/*',
        ];
        manifest.permissions = [
          'storage',
          'webNavigation',
          'declarativeNetRequest',
          'alarms',
          'tabs',
          'notifications',
          'contextMenus',
        ];
        manifest.optional_permissions = [];
        manifest.web_accessible_resources = [
          {
            resources: ['blocked.html', 'blocked.js', 'analyze-popup.html', 'analyze-popup.js'],
            matches: ['http://*/*', 'https://*/*'],
          },
        ];
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
      },
    },
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    minify: 'esbuild',
    sourcemap: false,
    cssCodeSplit: true,
    rollupOptions: {
      input: {
        background: resolve(__dirname, 'src/background/index.ts'),
        content: resolve(__dirname, 'src/content/index.ts'),
        popup: resolve(__dirname, 'src/popup/index.html'),
        options: resolve(__dirname, 'src/options/index.html'),
        blocked: resolve(__dirname, 'src/blocked/index.html'),
        'analyze-popup': resolve(__dirname, 'src/analyze-popup/index.html'),
      },
      output: {
        entryFileNames: '[name].js',
        chunkFileNames: '[name].js',
        assetFileNames: '[name].[ext]',
      },
    },
    target: 'chrome109',
    reportCompressedSize: true,
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@shared': resolve(__dirname, 'src/shared'),
    },
  },
  define: {
    'import.meta.env.VITE_API_URL': JSON.stringify(apiOrigin),
    'import.meta.env.VITE_EXTENSION_VERSION': JSON.stringify(version),
  },
});