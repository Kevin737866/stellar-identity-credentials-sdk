#!/usr/bin/env node
/**
 * Generate sample inputs for every circuit (Issue #517).
 *
 * Referenced by `npm run generate-random`. Produces
 * <circuit>_input.json with in-range placeholder values so the
 * prove/verify pipeline can be exercised locally.
 *
 * Usage: node scripts/generate-inputs.js [circuit-name]
 */

const fs = require('fs');
const path = require('path');

const circuitsDir = path.resolve(__dirname, '..');

/** Sample inputs keyed by circuit main-component signal names. */
const SAMPLE_INPUTS = {
  'range_proof': { value: 42, lower: 0, upper: 100 },
  'age_verification': {
    birthDate: [1985, 3, 20],
    currentDate: [2024, 1, 1],
    minimumAge: 18,
  },
  'set_membership': { element: 7, set: [1, 3, 7, 9, 11] },
  'credential_ownership': {
    didHash: 123456789,
    credentialIdHash: 987654321,
    ownerSecret: 555555555,
  },
  'membership_verification': {
    memberHash: 424242,
    merkleRoot: 987654,
    proof: [111111, 222222],
    pathIndices: [0, 1],
  },
  'income_verification': {
    incomeHash: 31337,
    threshold: 50000,
    currentDate: [2024, 1, 1],
  },
  'selective_disclosure': {
    attributesHash: 24680,
    disclosedMask: 5,
    issuerSecret: 13579,
  },
  'composite_proof': {
    proofA: 100,
    proofB: 200,
    publicHash: 300,
  },
};

const only = process.argv[2];
const targets = Object.entries(SAMPLE_INPUTS).filter(
  ([name]) => !only || name === only,
);

if (targets.length === 0) {
  console.error(`Unknown circuit: ${only}`);
  console.error(`Known circuits: ${Object.keys(SAMPLE_INPUTS).join(', ')}`);
  process.exit(1);
}

for (const [name, input] of targets) {
  const file = path.join(circuitsDir, `${name}_input.json`);
  fs.writeFileSync(file, JSON.stringify(input, null, 2) + '\n');
  console.log(`Wrote ${path.relative(process.cwd(), file)}`);
}
