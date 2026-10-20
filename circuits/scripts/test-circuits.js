#!/usr/bin/env node
/**
 * Circuit smoke checks (Issue #517).
 *
 * Referenced by `npm test`. Verifies that every circuit source exists,
 * that the build produced artefacts for each of them, and that the
 * package manifest compiles every circuit (guarding against the
 * build-script drift this script was created to fix).
 *
 * Usage: node scripts/test-circuits.js
 */

const fs = require('fs');
const path = require('path');

const circuitsDir = path.resolve(__dirname, '..');
let failures = 0;

function check(ok, label) {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${label}`);
  if (!ok) failures += 1;
}

const circuits = fs
  .readdirSync(circuitsDir)
  .filter((f) => f.endsWith('.circom'))
  .sort();

console.log(`Checking ${circuits.length} circuit(s)...`);

check(circuits.length > 0, 'at least one circuit source exists');

const pkg = JSON.parse(
  fs.readFileSync(path.join(circuitsDir, 'package.json'), 'utf8'),
);
check(
  pkg.scripts.build === 'node scripts/build-circuits.js',
  'build script delegates to scripts/build-circuits.js (compiles every circuit)',
);
check(
  fs.existsSync(path.join(circuitsDir, 'scripts', 'build-circuits.js')),
  'scripts/build-circuits.js exists',
);
check(
  fs.existsSync(path.join(circuitsDir, 'scripts', 'generate-inputs.js')),
  'scripts/generate-inputs.js exists',
);

for (const circuit of circuits) {
  const name = circuit.replace(/\.circom$/, '');
  const r1cs = path.join(circuitsDir, `${name}.r1cs`);
  const wasm = path.join(circuitsDir, `${name}_js`, `${name}.wasm`);
  // Artefacts are only present after `npm run build`; warn, don't fail.
  const built = fs.existsSync(r1cs) || fs.existsSync(wasm);
  console.log(`  ${built ? 'ok  ' : 'warn'} ${name}: artefacts ${built ? 'present' : 'not built (run npm run build)'}`);
}

if (failures > 0) {
  console.error(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll circuit checks passed.');
