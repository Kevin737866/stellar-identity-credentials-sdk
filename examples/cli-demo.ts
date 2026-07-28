/**
 * Interactive CLI Demo — Stellar Identity Credentials SDK
 *
 * Walks through all SDK features with a menu-driven interface and
 * color-coded output. Run with:
 *
 *   npm run example:cli-demo
 *
 * Or directly:
 *
 *   npx ts-node examples/cli-demo.ts
 */

import * as readline from 'readline';
import { Keypair } from 'stellar-sdk';

// ---------------------------------------------------------------------------
// ANSI color helpers
// ---------------------------------------------------------------------------

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  bgBlue: '\x1b[44m',
};

function ok(msg: string): void { console.log(`${C.green}✓ ${msg}${C.reset}`); }
function fail(msg: string): void { console.log(`${C.red}✗ ${msg}${C.reset}`); }
function info(msg: string): void { console.log(`${C.blue}ℹ ${msg}${C.reset}`); }

function heading(msg: string): void {
  console.log(`\n${C.bold}${C.cyan}${'═'.repeat(60)}${C.reset}`);
  console.log(`${C.bold}${C.cyan}  ${msg}${C.reset}`);
  console.log(`${C.bold}${C.cyan}${'═'.repeat(60)}${C.reset}\n`);
}

function subheading(msg: string): void {
  console.log(`\n${C.yellow}── ${msg} ${'─'.repeat(Math.max(0, 54 - msg.length))}${C.reset}\n`);
}

function printJSON(label: string, data: unknown): void {
  console.log(`${C.dim}${label}:${C.reset}`);
  const json = JSON.stringify(data, null, 2);
  const highlighted = json
    .replace(/"([^"]+)":/g, `${C.cyan}"$1"${C.reset}:`)
    .replace(/: "([^"]+)"/g, `: ${C.green}"$1"${C.reset}`)
    .replace(/: (\d+)/g, `: ${C.yellow}$1${C.reset}`)
    .replace(/: (true|false)/g, `: ${C.magenta}$1${C.reset}`);
  console.log(highlighted);
}

// ---------------------------------------------------------------------------
// Readline wrapper
// ---------------------------------------------------------------------------

let rl: readline.Interface;

function createRL(): void {
  rl = readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(question: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(`${C.white}${question}${C.reset}`, (answer) => resolve(answer.trim()));
  });
}

async function askDefault(question: string, def: string): Promise<string> {
  const answer = await ask(`${question} [${def}]: `);
  return answer || def;
}

async function pause(): Promise<void> {
  await ask(`\n${C.dim}Press Enter to continue...${C.reset}`);
}

// ---------------------------------------------------------------------------
// Mock data generators
// ---------------------------------------------------------------------------

function mockKP(): { publicKey: string; secretKey: string } {
  const kp = Keypair.random();
  return { publicKey: kp.publicKey(), secretKey: kp.secret() };
}

function mockDID(addr: string): string { return `did:stellar:${addr}`; }

function mockDIDDoc(did: string, addr: string) {
  return {
    id: did, controller: addr,
    verificationMethod: [{
      id: `${did}#key-1`, type: 'Ed25519VerificationKey2020',
      controller: addr, publicKey: addr.slice(0, 32) + '...',
    }],
    authentication: [`${did}#key-1`],
    service: [{ id: `${did}#identity-hub`, type: 'IdentityHub', endpoint: 'https://identity-hub.example.com' }],
    created: Date.now() - 86400000, updated: Date.now(),
  };
}

function mockCred(issuer: string, subject: string, type: string) {
  return {
    id: `cred-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    issuer, subject, type: [type, 'VerifiableCredential'],
    credentialData: { type, verificationLevel: 'Standard', issuedBy: issuer, timestamp: Date.now() } as Record<string, unknown>,
    issuanceDate: Date.now(),
    expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
    proof: 'ed25519-sig-' + Math.random().toString(36).slice(2, 18),
  };
}

function mockRep(addr: string) {
  const score = Math.floor(Math.random() * 400) + 550;
  return {
    did: `did:stellar:${addr}`, score,
    tier: score >= 900 ? 'Prime' : score >= 750 ? 'Strong' : score >= 550 ? 'Established' : score >= 300 ? 'Emerging' : 'Seedling',
    rawScore: score * 10, percentile: Math.floor(Math.random() * 30) + 60,
    factors: {
      transactionVolume: Math.floor(Math.random() * 100),
      transactionConsistency: Math.floor(Math.random() * 100),
      credentialCount: Math.floor(Math.random() * 10) + 1,
      credentialDiversity: Math.floor(Math.random() * 5) + 1,
      accountAge: Math.floor(Math.random() * 365) + 30,
      disputeHistory: Math.floor(Math.random() * 3),
    },
    penalties: { sanctionsMatches: 0, credentialRevocations: 0, disputes: 0 },
    lastUpdated: Date.now(),
  };
}

function mockProof(circuit: string) {
  return {
    proofId: `proof-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    circuitId: circuit,
    publicInputs: ['commitment-' + Math.random().toString(36).slice(2, 10)],
    proofBytes: Buffer.from('{"pi_a":["..."],"pi_b":["..."],"pi_c":["..."]}').toString('base64').slice(0, 48) + '...',
    verifierAddress: mockKP().publicKey,
    createdAt: Date.now(), expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    metadata: { type: circuit } as Record<string, string>,
    nullifier: 'nf-' + Math.random().toString(36).slice(2, 18),
  };
}

function mockScreen(addr: string, status: 'clear' | 'suspicious' | 'blocked' = 'clear') {
  const scores: Record<string, number> = { clear: 5, suspicious: 65, blocked: 95 };
  return {
    address: addr, status, riskScore: scores[status],
    matches: status === 'blocked' ? ['OFAC-SDN'] : [] as string[],
    timestamp: Date.now(), provider: 'on-chain',
  };
}

// ---------------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------------

interface State {
  keypairs: Map<string, { publicKey: string; secretKey: string; label: string }>;
  dids: Map<string, { did: string; address: string; document: ReturnType<typeof mockDIDDoc> }>;
  credentials: Map<string, ReturnType<typeof mockCred>>;
  reputations: Map<string, ReturnType<typeof mockRep>>;
  proofs: Map<string, ReturnType<typeof mockProof>>;
}

const state: State = {
  keypairs: new Map(), dids: new Map(), credentials: new Map(),
  reputations: new Map(), proofs: new Map(),
};

// ---------------------------------------------------------------------------
// Menu helper
// ---------------------------------------------------------------------------

async function showMenu(title: string, opts: string[]): Promise<number> {
  console.log(`\n${C.bold}${C.bgBlue}${C.white} ${title} ${C.reset}\n`);
  opts.forEach((o, i) => console.log(`  ${C.cyan}${i + 1}.${C.reset} ${o}`));
  console.log();
  while (true) {
    const n = parseInt(await ask(`Select option (1-${opts.length}): `), 10);
    if (n >= 1 && n <= opts.length) return n;
    fail(`Invalid choice. Enter a number between 1 and ${opts.length}.`);
  }
}

function clampIdx(idx: number, len: number): number { return Math.max(0, Math.min(idx, len - 1)); }

// ---------------------------------------------------------------------------
// DID Management
// ---------------------------------------------------------------------------

async function didMenu(): Promise<void> {
  while (true) {
    const c = await showMenu('DID Management', [
      'Generate Keypair', 'Create DID', 'Resolve DID', 'Update DID (Add Service)',
      'Deactivate DID', 'Check DID Exists', 'List Managed DIDs', 'Back to Main Menu',
    ]);
    if (c === 8) return;
    if (c === 1) { await genKeypair(); }
    else if (c === 2) { await createDID(); }
    else if (c === 3) { await resolveDID(); }
    else if (c === 4) { await updateDID(); }
    else if (c === 5) { await deactivateDID(); }
    else if (c === 6) { await checkDID(); }
    else { listDIDs(); await pause(); }
  }
}

async function genKeypair(): Promise<void> {
  subheading('Generate Keypair');
  const label = await askDefault('Label for this keypair', `keypair-${state.keypairs.size + 1}`);
  const kp = mockKP();
  state.keypairs.set(label, { ...kp, label });
  ok(`Keypair "${label}" generated`);
  printJSON('Keypair', { label, publicKey: kp.publicKey, secretKey: kp.secretKey.slice(0, 8) + '...' });
  await pause();
}

async function createDID(): Promise<void> {
  subheading('Create DID');
  if (state.keypairs.size === 0) {
    info('No keypairs available. Generating one...');
    const kp = mockKP();
    state.keypairs.set('default', { ...kp, label: 'default' });
    ok('Default keypair generated');
  }
  const keys = Array.from(state.keypairs.entries());
  console.log('Available keypairs:');
  keys.forEach(([label, kp], i) => console.log(`  ${i + 1}. ${label} (${kp.publicKey.slice(0, 12)}...)`));
  const idx = clampIdx(parseInt(await ask(`Select keypair (1-${keys.length}): `), 10) - 1, keys.length);
  const [label, kp] = keys[idx];
  info(`Creating DID for keypair "${label}"...`);
  const did = mockDID(kp.publicKey);
  const doc = mockDIDDoc(did, kp.publicKey);
  state.dids.set(did, { did, address: kp.publicKey, document: doc });
  ok(`DID created: ${did}`);
  printJSON('DID Document', doc);
  await pause();
}

async function resolveDID(): Promise<void> {
  subheading('Resolve DID');
  let did: string;
  if (state.dids.size > 0) {
    const dids = Array.from(state.dids.keys());
    console.log('Known DIDs:');
    dids.forEach((d, i) => console.log(`  ${i + 1}. ${d.slice(0, 40)}...`));
    console.log(`  ${dids.length + 1}. Enter custom DID`);
    const idx = parseInt(await ask(`Select (1-${dids.length + 1}): `), 10);
    did = idx <= dids.length ? dids[idx - 1] : await ask('Enter DID: ');
  } else {
    did = await ask('Enter DID (e.g., did:stellar:GABC...): ');
  }
  if (!did.startsWith('did:stellar:')) { fail('Invalid DID format. Must start with did:stellar:'); await pause(); return; }
  info(`Resolving ${did.slice(0, 40)}...`);
  const existing = state.dids.get(did);
  if (existing) {
    ok('DID resolved successfully');
    printJSON('DID Document', existing.document);
    printJSON('Resolution Metadata', { method: 'stellar', network: 'testnet' });
  } else {
    const addr = did.slice(12).split(':')[0];
    ok('DID resolved (simulated)');
    printJSON('DID Document', mockDIDDoc(did, addr));
  }
  await pause();
}

async function updateDID(): Promise<void> {
  subheading('Update DID — Add Service Endpoint');
  if (state.dids.size === 0) { fail('No DIDs to update. Create one first.'); await pause(); return; }
  const dids = Array.from(state.dids.entries());
  dids.forEach(([, d], i) => console.log(`  ${i + 1}. ${d.did.slice(0, 40)}...`));
  const idx = clampIdx(parseInt(await ask(`Select DID (1-${dids.length}): `), 10) - 1, dids.length);
  const [, sel] = dids[idx];
  const svcType = await askDefault('Service type', 'LinkedDomains');
  const endpoint = await askDefault('Service endpoint', 'https://example.com/profile');
  const svcId = await askDefault('Service ID', `#${svcType.toLowerCase()}`);
  sel.document.service.push({ id: svcId, type: svcType, endpoint });
  sel.document.updated = Date.now();
  ok(`Service endpoint added to ${sel.did.slice(0, 40)}...`);
  printJSON('Updated Services', sel.document.service);
  await pause();
}

async function deactivateDID(): Promise<void> {
  subheading('Deactivate DID');
  if (state.dids.size === 0) { fail('No DIDs to deactivate.'); await pause(); return; }
  const dids = Array.from(state.dids.entries());
  dids.forEach(([, d], i) => console.log(`  ${i + 1}. ${d.did.slice(0, 40)}...`));
  const idx = clampIdx(parseInt(await ask(`Select DID (1-${dids.length}): `), 10) - 1, dids.length);
  const [key, sel] = dids[idx];
  const confirm = await ask(`Deactivate ${sel.did.slice(0, 40)}...? (yes/no): `);
  if (confirm.toLowerCase() !== 'yes') { info('Cancelled.'); await pause(); return; }
  state.dids.delete(key);
  ok(`DID deactivated (tombstoned): ${sel.did.slice(0, 40)}...`);
  info('The DID record is preserved on-chain for audit purposes.');
  await pause();
}

async function checkDID(): Promise<void> {
  subheading('Check DID Exists');
  const did = await ask('Enter DID to check: ');
  if (!did.startsWith('did:stellar:')) { fail('Invalid DID format.'); await pause(); return; }
  if (state.dids.has(did)) ok(`DID exists: ${did.slice(0, 40)}...`);
  else info(`DID not found in local state: ${did.slice(0, 40)}...`);
  await pause();
}

function listDIDs(): void {
  subheading('Managed DIDs');
  if (state.dids.size === 0) { info('No DIDs created yet.'); return; }
  state.dids.forEach((d) => {
    console.log(`  ${C.green}●${C.reset} ${d.did}`);
    console.log(`    ${C.dim}Address: ${d.address.slice(0, 20)}...  Services: ${d.document.service.length}  Keys: ${d.document.verificationMethod.length}${C.reset}`);
  });
}

// ---------------------------------------------------------------------------
// Credential Management
// ---------------------------------------------------------------------------

async function credMenu(): Promise<void> {
  while (true) {
    const c = await showMenu('Credential Management', [
      'Issue Credential', 'Verify Credential', 'Revoke Credential', 'Get Credential Details',
      'Issue KYC Credential', 'Issue Education Credential', 'List Credentials', 'Back to Main Menu',
    ]);
    if (c === 8) return;
    if (c === 1) await issueCred();
    else if (c === 2) await verifyCred();
    else if (c === 3) await revokeCred();
    else if (c === 4) await credDetails();
    else if (c === 5) await issueKYC();
    else if (c === 6) await issueEdu();
    else { listCreds(); await pause(); }
  }
}

async function issueCred(): Promise<void> {
  subheading('Issue Credential');
  const issuer = await askDefault('Issuer address', mockKP().publicKey);
  const subject = await askDefault('Subject address', mockKP().publicKey);
  const type = await askDefault('Credential type', 'VerifiableCredential');
  info('Issuing credential...');
  const cred = mockCred(issuer, subject, type);
  state.credentials.set(cred.id, cred);
  ok(`Credential issued: ${cred.id}`);
  printJSON('Credential', cred);
  await pause();
}

async function verifyCred(): Promise<void> {
  subheading('Verify Credential');
  if (state.credentials.size === 0) { fail('No credentials to verify. Issue one first.'); await pause(); return; }
  const creds = Array.from(state.credentials.entries());
  creds.forEach(([id], i) => console.log(`  ${i + 1}. ${id}`));
  const idx = clampIdx(parseInt(await ask(`Select credential (1-${creds.length}): `), 10) - 1, creds.length);
  const [, cred] = creds[idx];
  info(`Verifying ${cred.id}...`);
  const expired = cred.expirationDate != null && Date.now() > cred.expirationDate;
  const revoked = !!cred.proof?.startsWith('REVOKED:');
  const result = { valid: !expired && !revoked, revoked, expired, issuer: cred.issuer, subject: cred.subject, issuanceDate: cred.issuanceDate, expirationDate: cred.expirationDate };
  if (result.valid) ok('Credential is VALID');
  else fail('Credential is INVALID');
  printJSON('Verification Result', result);
  await pause();
}

async function revokeCred(): Promise<void> {
  subheading('Revoke Credential');
  if (state.credentials.size === 0) { fail('No credentials to revoke.'); await pause(); return; }
  const creds = Array.from(state.credentials.entries());
  creds.forEach(([id], i) => console.log(`  ${i + 1}. ${id}`));
  const idx = clampIdx(parseInt(await ask(`Select credential (1-${creds.length}): `), 10) - 1, creds.length);
  const [key, cred] = creds[idx];
  const reason = await askDefault('Revocation reason', 'Manually revoked');
  cred.proof = `REVOKED:${reason}`;
  state.credentials.set(key, cred);
  ok(`Credential revoked: ${cred.id}`);
  info(`Reason: ${reason}`);
  await pause();
}

async function credDetails(): Promise<void> {
  subheading('Credential Details');
  if (state.credentials.size === 0) { fail('No credentials available.'); await pause(); return; }
  const creds = Array.from(state.credentials.entries());
  creds.forEach(([id], i) => console.log(`  ${i + 1}. ${id}`));
  const idx = clampIdx(parseInt(await ask(`Select credential (1-${creds.length}): `), 10) - 1, creds.length);
  printJSON('Credential Details', creds[idx][1]);
  await pause();
}

async function issueKYC(): Promise<void> {
  subheading('Issue KYC Credential');
  const subject = await askDefault('Subject address', mockKP().publicKey);
  const firstName = await askDefault('First name', 'Alice');
  const lastName = await askDefault('Last name', 'Johnson');
  const dob = await askDefault('Date of birth', '1990-05-15');
  const nationality = await askDefault('Nationality', 'US');
  const docType = await askDefault('Document type', 'Passport');
  const docNum = await askDefault('Document number', 'P123456789');
  info('Issuing KYC credential...');
  const cred = mockCred(mockKP().publicKey, subject, 'KYCVerification');
  cred.credentialData = { type: 'KYCVerification', data: { firstName, lastName, dateOfBirth: dob, nationality, documentType: docType, documentNumber: docNum, expiryDate: '2030-12-31' }, verificationLevel: 'Standard', timestamp: Date.now() };
  state.credentials.set(cred.id, cred);
  ok(`KYC Credential issued: ${cred.id}`);
  printJSON('KYC Credential', cred);
  await pause();
}

async function issueEdu(): Promise<void> {
  subheading('Issue Education Credential');
  const subject = await askDefault('Subject address', mockKP().publicKey);
  const degree = await askDefault('Degree', 'Bachelor of Science');
  const institution = await askDefault('Institution', 'Stellar University');
  const field = await askDefault('Field of study', 'Computer Science');
  const gradDate = await askDefault('Graduation date', '2024-06-15');
  info('Issuing education credential...');
  const cred = mockCred(mockKP().publicKey, subject, 'EducationCredential');
  cred.credentialData = { type: 'EducationCredential', data: { degree, institution, fieldOfStudy: field, graduationDate: gradDate, gpa: 3.8 }, timestamp: Date.now() };
  state.credentials.set(cred.id, cred);
  ok(`Education Credential issued: ${cred.id}`);
  printJSON('Education Credential', cred);
  await pause();
}

function listCreds(): void {
  subheading('Issued Credentials');
  if (state.credentials.size === 0) { info('No credentials issued yet.'); return; }
  state.credentials.forEach((cred) => {
    const revoked = !!cred.proof?.startsWith('REVOKED:');
    const icon = revoked ? `${C.red}●` : `${C.green}●`;
    const status = revoked ? `${C.red}REVOKED` : `${C.green}ACTIVE`;
    console.log(`  ${icon}${C.reset} ${cred.id}`);
    console.log(`    ${C.dim}Type: ${cred.type.join(', ')}  |  Status: ${status}${C.reset}`);
    console.log(`    ${C.dim}Issuer: ${cred.issuer.slice(0, 16)}...  Subject: ${cred.subject.slice(0, 16)}...${C.reset}`);
  });
}

// ---------------------------------------------------------------------------
// Reputation System
// ---------------------------------------------------------------------------

async function repMenu(): Promise<void> {
  while (true) {
    const c = await showMenu('Reputation System', [
      'Initialize Reputation', 'Get Reputation Score', 'Get Reputation Breakdown',
      'Compare Reputations', 'Get Reputation Tier', 'Calculate Trend',
      'List Tracked Reputations', 'Back to Main Menu',
    ]);
    if (c === 8) return;
    if (c === 1) await initRep();
    else if (c === 2) await getRep();
    else if (c === 3) await repBreakdown();
    else if (c === 4) await compareRep();
    else if (c === 5) await repTier();
    else if (c === 6) await repTrend();
    else { listReps(); await pause(); }
  }
}

function tierColor(tier: string): string {
  const m: Record<string, string> = { Prime: C.cyan, Strong: C.blue, Established: C.yellow, Emerging: C.red, Seedling: C.dim };
  return m[tier] || C.white;
}

function printBar(label: string, val: number, maxVal: number, width: number = 30): void {
  const len = maxVal > 0 ? Math.round((val / maxVal) * width) : 0;
  console.log(`  ${label.padEnd(25)} ${C.green}${'█'.repeat(len)}${C.dim}${'░'.repeat(width - len)}${C.reset} ${val}`);
}

async function initRep(): Promise<void> {
  subheading('Initialize Reputation');
  const addr = await askDefault('Stellar address', mockKP().publicKey);
  info(`Initializing reputation for ${addr.slice(0, 16)}...`);
  const data = mockRep(addr);
  data.score = 100; data.tier = 'Seedling';
  state.reputations.set(addr, data);
  ok('Reputation initialized');
  printJSON('Initial Reputation', data);
  await pause();
}

async function pickAddr(): Promise<string> {
  if (state.reputations.size > 0) {
    const addrs = Array.from(state.reputations.keys());
    addrs.forEach((a, i) => console.log(`  ${i + 1}. ${a.slice(0, 20)}...`));
    console.log(`  ${addrs.length + 1}. Enter custom address`);
    const idx = parseInt(await ask(`Select (1-${addrs.length + 1}): `), 10);
    if (idx <= addrs.length) return addrs[idx - 1];
  }
  return await askDefault('Stellar address', mockKP().publicKey);
}

function ensureRep(addr: string): ReturnType<typeof mockRep> {
  let d = state.reputations.get(addr);
  if (!d) { d = mockRep(addr); state.reputations.set(addr, d); }
  return d;
}

async function getRep(): Promise<void> {
  subheading('Get Reputation Score');
  const addr = await pickAddr();
  info(`Fetching reputation for ${addr.slice(0, 16)}...`);
  const d = ensureRep(addr);
  console.log(`\n  ${C.bold}Score: ${d.score}${C.reset}  |  Tier: ${tierColor(d.tier)}${d.tier}${C.reset}  |  Percentile: ${d.percentile}th`);
  ok('Reputation score retrieved');
  await pause();
}

async function repBreakdown(): Promise<void> {
  subheading('Reputation Breakdown');
  const addr = await pickAddr();
  const d = ensureRep(addr);
  printJSON('Reputation Breakdown', d);
  console.log(`\n  ${C.bold}Factor Analysis:${C.reset}`);
  const max = Math.max(...Object.values(d.factors));
  for (const [k, v] of Object.entries(d.factors)) printBar(k, v, max);
  await pause();
}

async function compareRep(): Promise<void> {
  subheading('Compare Reputations');
  const a = await askDefault('Address A', mockKP().publicKey);
  const b = await askDefault('Address B', mockKP().publicKey);
  const da = ensureRep(a), db = ensureRep(b);
  const winner = da.score === db.score ? 'Tie' : da.score > db.score ? 'Address A' : 'Address B';
  printJSON('Comparison', {
    addressA: { score: da.score, tier: da.tier, percentile: da.percentile },
    addressB: { score: db.score, tier: db.tier, percentile: db.percentile },
    delta: { score: da.score - db.score, percentile: da.percentile - db.percentile },
    winner,
  });
  ok(`Winner: ${winner}`);
  await pause();
}

async function repTier(): Promise<void> {
  subheading('Reputation Tier Lookup');
  const score = parseInt(await askDefault('Score (0-1000)', '750'), 10);
  const tiers = [
    { min: 900, tier: 'Prime', desc: 'Deep history, verified credentials, and strong network trust.' },
    { min: 750, tier: 'Strong', desc: 'Reliable activity profile suitable for governance and lending.' },
    { min: 550, tier: 'Established', desc: 'Moderate trust with room to deepen signal diversity.' },
    { min: 300, tier: 'Emerging', desc: 'Early-stage reputation with limited history.' },
    { min: 0, tier: 'Seedling', desc: 'Sybil-resistant base tier for new or lightly used accounts.' },
  ];
  const matched = tiers.find(t => score >= t.min) || tiers[tiers.length - 1];
  console.log(`\n  Score: ${C.bold}${score}${C.reset}`);
  console.log(`  Tier:  ${tierColor(matched.tier)}${C.bold}${matched.tier}${C.reset}`);
  console.log(`  ${C.dim}${matched.desc}${C.reset}\n`);
  tiers.forEach(t => {
    const marker = t.tier === matched.tier ? ` ${C.green}<--${C.reset}` : '';
    console.log(`    ${tierColor(t.tier)}${t.tier.padEnd(14)}${C.reset} ${t.min}+${marker}`);
  });
  await pause();
}

async function repTrend(): Promise<void> {
  subheading('Calculate Reputation Trend');
  const history = Array.from({ length: 20 }, () => Math.floor(Math.random() * 200) + 500);
  const recent = history.slice(-5), older = history.slice(-10, -5);
  const rAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
  const oAvg = older.reduce((a, b) => a + b, 0) / older.length;
  const change = rAvg - oAvg;
  const pct = oAvg === 0 ? 0 : (change / oAvg) * 100;
  const trend = Math.abs(pct) < 2 ? 'stable' : change > 0 ? 'up' : 'down';
  const icon = trend === 'up' ? `${C.green}↑` : trend === 'down' ? `${C.red}↓` : `${C.yellow}→`;
  console.log(`\n  Trend: ${icon} ${trend}${C.reset}`);
  console.log(`  Change: ${change > 0 ? '+' : ''}${change.toFixed(1)} (${pct.toFixed(1)}%)`);
  console.log(`\n  ${C.dim}Score History (last 20 data points):${C.reset}`);
  const mx = Math.max(...history), mn = Math.min(...history), range = mx - mn || 1;
  history.forEach((s, i) => {
    const len = Math.round(((s - mn) / range) * 30);
    console.log(`  ${String(i + 1).padStart(3)} ${C.green}${'█'.repeat(len)}${C.reset} ${s}`);
  });
  await pause();
}

function listReps(): void {
  subheading('Tracked Reputations');
  if (state.reputations.size === 0) { info('No reputations tracked yet.'); return; }
  state.reputations.forEach((d, addr) => {
    console.log(`  ${tierColor(d.tier)}●${C.reset} ${addr.slice(0, 20)}... — Score: ${C.bold}${d.score}${C.reset} (${tierColor(d.tier)}${d.tier}${C.reset})`);
  });
}

// ---------------------------------------------------------------------------
// ZK Proofs
// ---------------------------------------------------------------------------

async function zkMenu(): Promise<void> {
  while (true) {
    const c = await showMenu('Zero-Knowledge Proofs', [
      'Generate Age Proof', 'Generate Income Proof', 'Generate Credential Ownership Proof',
      'Verify Proof', 'List Available Circuits', 'List Generated Proofs', 'Back to Main Menu',
    ]);
    if (c === 7) return;
    if (c === 1) await ageProof();
    else if (c === 2) await incomeProof();
    else if (c === 3) await credOwnershipProof();
    else if (c === 4) await verifyProof();
    else if (c === 5) { listCircuits(); await pause(); }
    else { listProofs(); await pause(); }
  }
}

async function ageProof(): Promise<void> {
  subheading('Generate Age Proof (ZK Range Proof)');
  const birthYear = parseInt(await askDefault('Birth year', '1990'), 10);
  const minAge = parseInt(await askDefault('Minimum age to prove', '18'), 10);
  const age = new Date().getFullYear() - birthYear;
  if (age < minAge) { fail(`Age ${age} does not meet minimum ${minAge}.`); info('Proof generation would fail.'); await pause(); return; }
  info(`Proving age >= ${minAge} without revealing actual birth year...`);
  info(`Actual age: ${age} (private — not revealed in the proof)`);
  const p = mockProof('age_range_proof');
  p.metadata = { type: 'age_verification', minAge: String(minAge) };
  state.proofs.set(p.proofId, p);
  ok(`Age proof generated: ${p.proofId}`);
  printJSON('ZK Proof', p);
  info(`Verifier only learns: age >= ${minAge}. Nothing else.`);
  await pause();
}

async function incomeProof(): Promise<void> {
  subheading('Generate Income Proof (ZK Range Proof)');
  const income = parseInt(await askDefault('Actual income', '85000'), 10);
  const min = parseInt(await askDefault('Minimum income to prove', '50000'), 10);
  if (income < min) { fail(`Income $${income} below minimum $${min}.`); await pause(); return; }
  info(`Proving income >= $${min} without revealing actual income...`);
  const p = mockProof('income_range_proof');
  p.metadata = { type: 'income_verification', minIncome: String(min) };
  state.proofs.set(p.proofId, p);
  ok(`Income proof generated: ${p.proofId}`);
  printJSON('ZK Proof', p);
  info(`Verifier learns income >= $${min}, actual amount remains private.`);
  await pause();
}

async function credOwnershipProof(): Promise<void> {
  subheading('Generate Credential Ownership Proof');
  if (state.credentials.size === 0) {
    info('No credentials available. Creating a sample...');
    const c = mockCred(mockKP().publicKey, mockKP().publicKey, 'SampleCredential');
    state.credentials.set(c.id, c);
    ok(`Sample credential created: ${c.id}`);
  }
  const creds = Array.from(state.credentials.entries());
  creds.forEach(([id], i) => console.log(`  ${i + 1}. ${id}`));
  const idx = clampIdx(parseInt(await ask(`Select credential (1-${creds.length}): `), 10) - 1, creds.length);
  const [, cred] = creds[idx];
  info(`Generating ownership proof for ${cred.id}...`);
  const p = mockProof('credential_ownership');
  p.metadata = { type: 'credential_ownership', credential_id: cred.id };
  state.proofs.set(p.proofId, p);
  ok(`Credential ownership proof generated: ${p.proofId}`);
  printJSON('ZK Proof', p);
  await pause();
}

async function verifyProof(): Promise<void> {
  subheading('Verify ZK Proof');
  if (state.proofs.size === 0) { fail('No proofs to verify. Generate one first.'); await pause(); return; }
  const proofs = Array.from(state.proofs.entries());
  proofs.forEach(([id, p], i) => console.log(`  ${i + 1}. ${id} (${p.circuitId})`));
  const idx = clampIdx(parseInt(await ask(`Select proof (1-${proofs.length}): `), 10) - 1, proofs.length);
  const [, p] = proofs[idx];
  info(`Verifying proof ${p.proofId}...`);
  const expired = p.expiresAt != null && Date.now() > p.expiresAt;
  const result = { valid: !expired, circuitId: p.circuitId, proofId: p.proofId, verifiedAt: Date.now(), expiresAt: p.expiresAt };
  if (result.valid) ok('Proof is VALID');
  else fail('Proof is INVALID (expired)');
  printJSON('Verification Result', result);
  await pause();
}

function listCircuits(): void {
  subheading('Available ZK Circuits');
  const circuits = [
    { id: 'age_range_proof', name: 'Age Range Proof', type: 'RangeProof', desc: 'Prove age within a range without revealing exact value' },
    { id: 'income_range_proof', name: 'Income Range Proof', type: 'RangeProof', desc: 'Prove income meets minimum threshold' },
    { id: 'credential_ownership', name: 'Credential Ownership', type: 'CredentialOwnership', desc: 'Prove ownership without revealing contents' },
    { id: 'kyc_composite_proof', name: 'KYC Composite Proof', type: 'CompositeProof', desc: 'Combined age + country + credential verification' },
    { id: 'loan_application_composite_proof', name: 'Loan Application', type: 'CompositeProof', desc: 'Combined income + credit + employment + residence proof' },
  ];
  circuits.forEach(c => {
    console.log(`  ${C.cyan}●${C.reset} ${C.bold}${c.name}${C.reset} (${c.id})`);
    console.log(`    ${C.dim}Type: ${c.type}  |  ${c.desc}${C.reset}`);
  });
}

function listProofs(): void {
  subheading('Generated Proofs');
  if (state.proofs.size === 0) { info('No proofs generated yet.'); return; }
  state.proofs.forEach((p) => {
    const expired = p.expiresAt != null && Date.now() > p.expiresAt;
    const icon = expired ? `${C.red}●` : `${C.green}●`;
    const status = expired ? `${C.red}EXPIRED` : `${C.green}VALID`;
    console.log(`  ${icon}${C.reset} ${p.proofId}`);
    console.log(`    ${C.dim}Circuit: ${p.circuitId}  |  Status: ${status}${C.reset}`);
  });
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

async function complianceMenu(): Promise<void> {
  while (true) {
    const c = await showMenu('Compliance & Screening', [
      'Screen Address', 'Screen Transaction', 'Generate Compliance Report',
      'Prove Compliance Status (ZK)', 'Build Travel Rule Payload',
      'List Sanctions Lists', 'Back to Main Menu',
    ]);
    if (c === 7) return;
    if (c === 1) await screenAddr();
    else if (c === 2) await screenTx();
    else if (c === 3) await compReport();
    else if (c === 4) await proveCompliance();
    else if (c === 5) await travelRule();
    else { listSanctions(); await pause(); }
  }
}

async function screenAddr(): Promise<void> {
  subheading('Screen Address');
  const addr = await askDefault('Address to screen', mockKP().publicKey);
  info(`Screening ${addr.slice(0, 16)}...`);
  const statuses: Array<'clear' | 'suspicious' | 'blocked'> = ['clear', 'clear', 'clear', 'suspicious'];
  const status = statuses[Math.floor(Math.random() * statuses.length)];
  const result = mockScreen(addr, status);
  const sc = status === 'clear' ? C.green : status === 'suspicious' ? C.yellow : C.red;
  console.log(`\n  Status: ${sc}${C.bold}${status.toUpperCase()}${C.reset}  |  Risk Score: ${result.riskScore}/100`);
  if (status === 'clear') ok('Address cleared — no sanctions matches');
  else if (status === 'suspicious') fail('Address flagged as SUSPICIOUS — review recommended');
  else fail('Address is BLOCKED — sanctions match found');
  printJSON('Screening Result', result);
  await pause();
}

async function screenTx(): Promise<void> {
  subheading('Screen Transaction');
  const sender = await askDefault('Sender address', mockKP().publicKey);
  const receiver = await askDefault('Receiver address', mockKP().publicKey);
  const amount = await askDefault('Amount', '5000');
  const asset = await askDefault('Asset', 'XLM');
  info('Screening transaction...');
  const sR = mockScreen(sender, 'clear'), rR = mockScreen(receiver, 'clear');
  const travel = parseFloat(amount) >= 1000;
  const result = {
    txHash: 'tx-' + Math.random().toString(36).slice(2, 14),
    sender, receiver, amount, asset, senderRisk: sR, receiverRisk: rR,
    overallRisk: Math.max(sR.riskScore, rR.riskScore),
    flags: travel ? ['fatf-travel-rule-required'] : [] as string[],
    requiresTravelRule: travel, timestamp: Date.now(),
  };
  if (travel) info(`FATF Travel Rule applies — amount ($${amount}) >= $1000 threshold`);
  if (result.overallRisk < 30) ok('Transaction risk assessment: LOW');
  else if (result.overallRisk < 70) fail('Transaction risk assessment: MEDIUM');
  else fail('Transaction risk assessment: HIGH');
  printJSON('Transaction Risk Analysis', result);
  await pause();
}

async function compReport(): Promise<void> {
  subheading('Generate Compliance Report');
  const did = await askDefault('Subject DID', `did:stellar:${mockKP().publicKey}`);
  info(`Generating compliance report for ${did.slice(0, 40)}...`);
  const report = {
    subject: did, generatedAt: Date.now(),
    timeframeStart: Date.now() - 90 * 86400000, timeframeEnd: Date.now(),
    riskSummary: { currentScore: 12, peakScore: 25, averageScore: 15, totalScreenings: 8 },
    regulatoryFlags: [] as string[],
    auditTrail: [
      { action: 'screening', timestamp: Date.now() - 7 * 86400000, detail: 'Routine check', ledgerSequence: 1234567 },
      { action: 'screening', timestamp: Date.now() - 86400000, detail: 'Routine check', ledgerSequence: 1234890 },
    ],
  };
  ok('Compliance report generated');
  printJSON('Compliance Report', report);
  console.log(`\n  ${C.bold}Risk Summary:${C.reset}`);
  console.log(`    Current Score:    ${report.riskSummary.currentScore}/100`);
  console.log(`    Peak Score:       ${report.riskSummary.peakScore}/100`);
  console.log(`    Average Score:    ${report.riskSummary.averageScore}/100`);
  console.log(`    Total Screenings: ${report.riskSummary.totalScreenings}`);
  console.log(`    Flags:            ${report.regulatoryFlags.length === 0 ? 'None' : report.regulatoryFlags.join(', ')}`);
  await pause();
}

async function proveCompliance(): Promise<void> {
  subheading('Prove Compliance Status (Zero-Knowledge)');
  const types = ['sanctions-clear', 'kyc-valid', 'threshold-below'] as const;
  console.log('Proof types:');
  types.forEach((t, i) => console.log(`  ${i + 1}. ${t}`));
  const idx = clampIdx(parseInt(await ask(`Select type (1-${types.length}): `), 10) - 1, types.length);
  const proofType = types[idx];
  info(`Generating ZK proof of ${proofType} status...`);
  const proof = {
    proofType,
    commitment: 'sha256-' + Math.random().toString(36).slice(2, 18) + Math.random().toString(36).slice(2, 18),
    proofValue: Buffer.from(Math.random().toString()).toString('base64'),
    verificationMethod: `did:stellar:${mockKP().publicKey}#key-1`,
    createdAt: Date.now(), expiresAt: Date.now() + 86400000,
  };
  ok('ZK compliance proof generated');
  printJSON('ZK Compliance Proof', proof);
  info("Verifier confirms compliance without learning the subject's identity.");
  await pause();
}

async function travelRule(): Promise<void> {
  subheading('Build FATF Travel Rule Payload');
  const oVASP = await askDefault('Originator VASP', 'VASP-Alpha');
  const bVASP = await askDefault('Beneficiary VASP', 'VASP-Beta');
  const oName = await askDefault('Originator name', 'Alice Johnson');
  const bName = await askDefault('Beneficiary name', 'Bob Smith');
  const amount = await askDefault('Transfer amount', '15000');
  const asset = await askDefault('Asset', 'USDC');
  const payload = {
    originatorVASP: oVASP, beneficiaryVASP: bVASP,
    originator: { name: oName, accountNumber: mockKP().publicKey },
    beneficiary: { name: bName, accountNumber: mockKP().publicKey },
    transferAmount: amount, asset,
    transactionRef: 'tx-' + Math.random().toString(36).slice(2, 14),
    timestamp: Date.now(),
  };
  ok('Travel Rule payload constructed');
  printJSON('FATF Travel Rule Payload', payload);
  info('Attach this payload to the Stellar transaction memo or send via secure VASP channel.');
  await pause();
}

function listSanctions(): void {
  subheading('Active Sanctions Lists');
  const lists = [
    { source: 'OFAC-SDN', updated: 2, entries: 12487 },
    { source: 'EU-Sanctions', updated: 5, entries: 8932 },
    { source: 'UN-Consolidated', updated: 1, entries: 6721 },
    { source: 'UK-HMT', updated: 3, entries: 4256 },
  ];
  lists.forEach(l => {
    console.log(`  ${C.green}●${C.reset} ${C.bold}${l.source}${C.reset}`);
    console.log(`    ${C.dim}Entries: ${l.entries.toLocaleString()}  |  Updated: ${l.updated}d ago  |  Active: true${C.reset}`);
  });
}

// ---------------------------------------------------------------------------
// Demo Mode — automated walkthrough with mock data
// ---------------------------------------------------------------------------

async function runDemo(): Promise<void> {
  heading('DEMO MODE — Full Feature Walkthrough');
  info('Running through all SDK features with mock data...\n');

  // 1. DID
  subheading('1. DID Management');
  const kp = mockKP();
  ok(`Generated keypair: ${kp.publicKey.slice(0, 20)}...`);
  const did = mockDID(kp.publicKey);
  const doc = mockDIDDoc(did, kp.publicKey);
  state.dids.set(did, { did, address: kp.publicKey, document: doc });
  ok(`Created DID: ${did.slice(0, 40)}...`);
  printJSON('DID Document', doc);
  doc.service.push({ id: '#linkedin', type: 'LinkedDomains', endpoint: 'https://linkedin.com/in/demo-user' });
  ok('Added LinkedIn service endpoint');

  // 2. Credentials
  subheading('2. Credential Issuance');
  const kycCred = mockCred(kp.publicKey, mockKP().publicKey, 'KYCVerification');
  kycCred.credentialData = { type: 'KYCVerification', data: { firstName: 'Alice', lastName: 'Johnson', nationality: 'US', documentType: 'Passport' }, verificationLevel: 'Standard' };
  state.credentials.set(kycCred.id, kycCred);
  ok(`Issued KYC credential: ${kycCred.id}`);
  printJSON('KYC Credential', kycCred);
  const eduCred = mockCred(kp.publicKey, mockKP().publicKey, 'EducationCredential');
  eduCred.credentialData = { type: 'EducationCredential', data: { degree: 'B.Sc. Computer Science', institution: 'Stellar University', gpa: 3.8 } };
  state.credentials.set(eduCred.id, eduCred);
  ok(`Issued Education credential: ${eduCred.id}`);
  info('Verifying KYC credential...');
  ok('Credential is VALID');

  // 3. Reputation
  subheading('3. Reputation System');
  const rep = mockRep(kp.publicKey);
  state.reputations.set(kp.publicKey, rep);
  ok(`Reputation score: ${rep.score} (${rep.tier})`);
  const max = Math.max(...Object.values(rep.factors));
  for (const [k, v] of Object.entries(rep.factors)) printBar(k, v, max, 25);

  // 4. ZK Proofs
  subheading('4. Zero-Knowledge Proofs');
  const ap = mockProof('age_range_proof');
  ap.metadata = { type: 'age_verification', minAge: '18' };
  state.proofs.set(ap.proofId, ap);
  ok(`Generated age proof (>= 18): ${ap.proofId}`);
  info('Verifier learns: age >= 18. Nothing else is revealed.');
  const ip = mockProof('income_range_proof');
  ip.metadata = { type: 'income_verification', minIncome: '50000' };
  state.proofs.set(ip.proofId, ip);
  ok(`Generated income proof (>= $50k): ${ip.proofId}`);
  info('Verifying age proof...');
  ok('ZK Proof is VALID');

  // 5. Compliance
  subheading('5. Compliance & Screening');
  const screening = mockScreen(kp.publicKey, 'clear');
  ok(`Address screening: ${screening.status.toUpperCase()} (risk: ${screening.riskScore}/100)`);
  ok('Compliance report generated');
  console.log(`  Risk Summary: Current=12 | Peak=25 | Avg=15`);
  console.log(`  Screenings: 8 | Flags: None`);
  info('Generating ZK proof of sanctions-clear status...');
  ok('ZK compliance proof generated — verifier confirms compliance without learning identity');

  // Summary
  subheading('Demo Summary');
  console.log(`  ${C.green}✓${C.reset} DID Management       — Create, Resolve, Update`);
  console.log(`  ${C.green}✓${C.reset} Credentials           — Issue KYC, Education, Verify`);
  console.log(`  ${C.green}✓${C.reset} Reputation System     — Score, Breakdown, Tiers`);
  console.log(`  ${C.green}✓${C.reset} Zero-Knowledge Proofs — Age, Income, Ownership`);
  console.log(`  ${C.green}✓${C.reset} Compliance            — Screen, Report, Travel Rule`);
  console.log(`\n${C.bold}${C.green}Demo complete! All SDK features demonstrated successfully.${C.reset}\n`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function mainMenu(): Promise<void> {
  while (true) {
    heading('Stellar Identity Credentials SDK — Interactive CLI Demo');
    console.log(`  ${C.dim}Network: testnet  |  Mode: Demo (mock data)${C.reset}\n`);
    const c = await showMenu('Main Menu', [
      'DID Management', 'Credentials', 'Reputation', 'ZK Proofs',
      'Compliance', 'Run Full Demo', 'Exit',
    ]);
    if (c === 1) await didMenu();
    else if (c === 2) await credMenu();
    else if (c === 3) await repMenu();
    else if (c === 4) await zkMenu();
    else if (c === 5) await complianceMenu();
    else if (c === 6) { await runDemo(); await pause(); }
    else { console.log(`\n${C.cyan}Goodbye!${C.reset}\n`); rl.close(); process.exit(0); }
  }
}

async function main(): Promise<void> {
  createRL();
  console.clear();
  console.log(`${C.bold}${C.cyan}`);
  console.log('  ╔══════════════════════════════════════════════════════╗');
  console.log('  ║     Stellar Identity Credentials SDK                ║');
  console.log('  ║     Interactive CLI Demo                            ║');
  console.log('  ╚══════════════════════════════════════════════════════╝');
  console.log(`${C.reset}`);
  console.log(`  ${C.dim}Explore DID management, verifiable credentials,`);
  console.log(`  reputation scoring, zero-knowledge proofs, and`);
  console.log(`  regulatory compliance — all from your terminal.${C.reset}\n`);

  const c = await showMenu('How would you like to start?', [
    'Interactive Menu (explore features manually)',
    'Demo Mode (automated walkthrough of all features)',
    'Exit',
  ]);
  if (c === 1) await mainMenu();
  else if (c === 2) { await runDemo(); await pause(); await mainMenu(); }
  else { console.log(`\n${C.cyan}Goodbye!${C.reset}\n`); rl.close(); process.exit(0); }
}

main().catch((err) => {
  console.error(`${C.red}Fatal error: ${err instanceof Error ? err.message : String(err)}${C.reset}`);
  process.exit(1);
});
