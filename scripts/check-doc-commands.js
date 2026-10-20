#!/usr/bin/env node
/**
 * Documentation command check (Issues #89, #516).
 *
 * Scans the markdown guides for `npm run <script>` references and fails
 * when a documented script does not exist in package.json. This keeps the
 * quick-start, integration and CLI guides executable: a command added to a
 * guide without a backing script breaks CI instead of breaking readers.
 *
 * Usage: npm run docs:check-commands
 */

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const scripts = new Set(Object.keys(pkg.scripts || {}));

// Local script manifests whose commands are documented in their own guides.
for (const manifest of ['circuits/package.json', 'sdk/package.json']) {
  const p = path.join(root, manifest);
  if (fs.existsSync(p)) {
    const sub = JSON.parse(fs.readFileSync(p, 'utf8'));
    for (const name of Object.keys(sub.scripts || {})) scripts.add(name);
  }
}

const docFiles = fs
  .readdirSync(path.join(root, 'docs'))
  .filter((f) => f.endsWith('.md'))
  .map((f) => path.join('docs', f));

if (fs.existsSync(path.join(root, 'README.md'))) docFiles.push('README.md');
if (fs.existsSync(path.join(root, 'GUIDE.md'))) docFiles.push('GUIDE.md');

const CMD_RE = /npm run ([a-z][a-z0-9:_-]*)/g;

let failures = 0;
let checked = 0;

for (const file of docFiles) {
  const full = path.join(root, file);
  if (!fs.existsSync(full)) continue;
  const text = fs.readFileSync(full, 'utf8');
  let match;
  while ((match = CMD_RE.exec(text)) !== null) {
    const script = match[1];
    // Interpolated placeholders like `npm run <script>` are not commands.
    if (script.startsWith('<')) continue;
    checked += 1;
    if (!scripts.has(script)) {
      console.error(`✗ ${file}: documented \`npm run ${script}\` has no matching package.json script`);
      failures += 1;
    }
  }
}

console.log(`Checked ${checked} documented npm command(s) across ${docFiles.length} file(s).`);
if (failures > 0) {
  console.error(`${failures} documented command(s) do not exist.`);
  process.exit(1);
}
console.log('All documented npm commands exist.');
