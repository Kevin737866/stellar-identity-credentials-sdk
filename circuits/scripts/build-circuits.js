#!/usr/bin/env node
/**
 * Build every Circom circuit in circuits/ (Issue #517).
 *
 * Single-command, reproducible build: compiles each .circom source to
 * .r1cs / .wasm / .sym. Exits non-zero if any circuit fails so CI can
 * gate on a full build.
 *
 * Usage: node scripts/build-circuits.js
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const circuitsDir = path.resolve(__dirname, '..');

const circuits = fs
  .readdirSync(circuitsDir)
  .filter((f) => f.endsWith('.circom'))
  .sort();

if (circuits.length === 0) {
  console.error('No .circom files found in', circuitsDir);
  process.exit(1);
}

console.log(`Building ${circuits.length} circuit(s)...`);

let failed = false;
for (const circuit of circuits) {
  const name = circuit.replace(/\.circom$/, '');
  process.stdout.write(`  ${name} ... `);
  try {
    execFileSync('circom', [circuit, '--r1cs', '--wasm', '--sym'], {
      cwd: circuitsDir,
      stdio: ['ignore', 'ignore', 'pipe'],
    });
    console.log('ok');
  } catch (err) {
    failed = true;
    console.log('FAILED');
    const stderr = err && err.stderr ? err.stderr.toString().trim() : '';
    if (stderr) console.error(`    ${stderr.split('\n').slice(-3).join('\n    ')}`);
  }
}

if (failed) {
  console.error('\nCircuit build failed.');
  process.exit(1);
}
console.log('\nAll circuits built successfully.');
