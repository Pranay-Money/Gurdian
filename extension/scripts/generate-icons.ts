// Icon generation script - Run with: npx tsx scripts/generate-icons.ts
// Requires: npm install -D sharp @types/sharp

import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const sizes = [16, 32, 48, 128];
const svgPath = path.resolve(__dirname, '../public/icons/icon.svg');
const outputDir = path.resolve(__dirname, '../public/icons');

async function generateIcons() {
  console.log('Generating icons from SVG...');
  
  for (const size of sizes) {
    const outputPath = path.join(outputDir, `icon${size}.png`);
    
    await sharp(svgPath)
      .resize(size, size, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(outputPath);
    
    console.log(`  Generated: icon${size}.png`);
  }
  
  console.log('Done!');
}

generateIcons().catch(console.error);