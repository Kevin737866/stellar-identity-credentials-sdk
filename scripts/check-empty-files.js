#!/usr/bin/env node
/**
 * Repository hygiene check (Issue #519).
 *
 * Fails when a tracked file under docs/ or src/ is zero bytes. Empty
 * placeholder files in the documentation or source tree usually mark an
 * abandoned intention and are indistinguishable from lost content, so they
 * must not accumulate.
 *
 * Usage: node scripts/check-empty-files.js
 */

const { execFileSync } = require('child_process');
const path = require('path');

const root = path.resolve(__dirname, '..');

let tracked;
try {
  tracked = execFileSync('git', ['ls-files', 'docs', 'src'], {
    cwd: root,
    encoding: 'utf8',
  })
    .split('\n')
    .filter(Boolean);
} catch {
  console.error('git ls-files failed — is this a git checkout?');
  process.exit(1);
}

const fs = require('fs');

const empty = tracked.filter((file) => {
  const full = path.join(root, file);
  try {
    const stat = fs.statSync(full);
    return stat.isFile() && stat.size === 0;
  } catch {
    return false;
  }
});

if (empty.length > 0) {
  for (const file of empty) {
    console.error(`✗ zero-byte tracked file: ${file}`);
  }
  console.error(
    `\n${empty.length} empty file(s) tracked under docs/ or src/. ` +
      'Delete them or write their intended content.',
  );
  process.exit(1);
}

console.log(`OK: ${tracked.length} tracked file(s) under docs/ and src/ are non-empty.`);
