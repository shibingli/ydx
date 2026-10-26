import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, '..');
const captchaRoot = resolve(packageRoot, '../..');
const dist = resolve(packageRoot, 'dist');
const assets = resolve(captchaRoot, 'pages/assets');
const transportAssets = resolve(captchaRoot, 'transport/assets');

await mkdir(dist, { recursive: true });
await mkdir(assets, { recursive: true });
await mkdir(transportAssets, { recursive: true });

const langsDir = resolve(captchaRoot, 'core/langs');
const localeFiles = (await readdir(langsDir)).filter((name) => name.endsWith('.json'));
const catalogs = {};
for (const name of localeFiles) {
  const catalog = JSON.parse(await readFile(resolve(langsDir, name), 'utf8'));
  const labels = {};
  for (const [key, value] of Object.entries(catalog)) {
    if (key.startsWith('sdk.')) labels[key.slice(4)] = value;
  }
  catalogs[name.slice(0, -'.json'.length)] = labels;
}
if (Object.keys(catalogs).length === 0) throw new Error('no locale catalogs found');

const files = ['yd-captcha.js', 'yd-captcha.css'];
for (const name of files) {
  const source = resolve(packageRoot, 'src', name);
  let contents = await readFile(source, 'utf8');
  if (!contents.startsWith('/*!')) throw new Error(`${name} is missing its banner`);
  if (name === 'yd-captcha.js') {
    const marker = 'var LABELS_CATALOG = {};';
    if (!contents.includes(marker)) throw new Error(`${name} is missing the label catalog marker`);
    contents = contents.replace(marker, `var LABELS_CATALOG = ${JSON.stringify(catalogs)};`);
  }
  await writeFile(resolve(dist, name), contents, 'utf8');
  await writeFile(resolve(assets, name), contents, 'utf8');
  await writeFile(resolve(transportAssets, name), contents, 'utf8');
}

console.log(`built ${files.join(', ')} with ${Object.keys(catalogs).join(', ')} -> dist, transport/assets and pages/assets`);
