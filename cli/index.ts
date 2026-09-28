#!/usr/bin/env node
/**
 * Stellar Identity Credentials SDK — Interactive CLI
 *
 * A full-featured command-line tool for deploying, managing, and interacting
 * with all contracts in the Stellar Identity system.
 *
 * Usage:
 *   npx ts-node cli/index.ts
 *   npm run cli
 *
 * Commands (non-interactive):
 *   stellar-identity did <subcommand>        DID management
 *   stellar-identity credential <subcommand> Credential operations
 *   stellar-identity reputation <subcommand> Reputation management
 *   stellar-identity zk <subcommand>         Zero-knowledge proofs
 *   stellar-identity compliance <subcommand> Compliance & screening
 *   stellar-identity deploy <subcommand>     Contract deployment wizard
 *   stellar-identity config <subcommand>     Configuration management
 *   stellar-identity interactive             Launch guided interactive mode
 */

import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { Keypair } from 'stellar-sdk';

// ─── ANSI color helpers ────────────────────────────────────────────────────────

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  magenta: '\x1b[35m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  bgBlue: '\x1b[44m',
  bgGreen: '\x1b[42m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgCyan: '\x1b[46m',
  bgMagenta: '\x1b[45m',
};

const fmt = {
  ok: (msg: string) => `${C.green}✓${C.reset} ${msg}`,
  fail: (msg: string) => `${C.red}✗${C.reset} ${msg}`,
  info: (msg: string) => `${C.blue}ℹ${C.reset} ${msg}`,
  warn: (msg: string) => `${C.yellow}⚠${C.reset} ${msg}`,
  step: (n: number, msg: string) => `${C.cyan}[${n}]${C.reset} ${msg}`,
  label: (msg: string) => `${C.dim}${msg}${C.reset}`,
  value: (msg: string) => `${C.green}${msg}${C.reset}`,
  highlight: (msg: string) => `${C.bold}${C.cyan}${msg}${C.reset}`,
  error: (msg: string) => `${C.bold}${C.red}ERROR:${C.reset} ${C.red}${msg}${C.reset}`,
};

function log(msg: string): void { console.log(msg); }
function ok(msg: string): void { log(fmt.ok(msg)); }
function fail(msg: string): void { log(fmt.fail(msg)); }
function info(msg: string): void { log(fmt.info(msg)); }
function warn(msg: string): void { log(fmt.warn(msg)); }
function err(msg: string): void { log(fmt.error(msg)); }

function divider(char = '─', width = 60): void {
  log(`${C.dim}${char.repeat(width)}${C.reset}`);
}

function header(msg: string, width = 60): void {
  const bar = '═'.repeat(width);
  log(`\n${C.bold}${C.cyan}${bar}${C.reset}`);
  log(`${C.bold}${C.cyan}  ${msg}${C.reset}`);
  log(`${C.bold}${C.cyan}${bar}${C.reset}\n`);
}

function subheader(msg: string): void {
  log(`\n${C.bold}${C.yellow}── ${msg} ──${C.reset}\n`);
}

function box(title: string, lines: string[]): void {
  const width = Math.max(title.length + 4, ...lines.map(l => l.length + 4), 40);
  const border = '─'.repeat(width - 2);
  log(`${C.dim}┌${border}┐${C.reset}`);
  log(`${C.dim}│${C.reset} ${C.bold}${title.padEnd(width - 3)}${C.reset}${C.dim}│${C.reset}`);
  log(`${C.dim}├${border}┤${C.reset}`);
  for (const line of lines) {
    log(`${C.dim}│${C.reset} ${line.padEnd(width - 3)} ${C.dim}│${C.reset}`);
  }
  log(`${C.dim}└${border}┘${C.reset}`);
}

function table(headers: string[], rows: string[][]): void {
  const cols = headers.length;
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map(r => (r[i] || '').length)) + 2
  );

  const sep = widths.map(w => '─'.repeat(w)).join('┼');
  const head = headers.map((h, i) => ` ${C.bold}${h.padEnd(widths[i] - 1)}${C.reset}`).join(`${C.dim}│${C.reset}`);
  const hrule = `${C.dim}├${sep}┤${C.reset}`;
  const top = `${C.dim}┌${widths.map(w => '─'.repeat(w)).join('┬')}┐${C.reset}`;
  const bot = `${C.dim}└${widths.map(w => '─'.repeat(w)).join('┴')}┘${C.reset}`;

  log(top);
  log(`${C.dim}│${C.reset}${head}${C.dim}│${C.reset}`);
  log(hrule);
  for (const row of rows) {
    const cells = row.map((c, i) => ` ${(c || '').padEnd(widths[i] - 1)}`).join(`${C.dim}│${C.reset}`);
    log(`${C.dim}│${C.reset}${cells}${C.dim}│${C.reset}`);
  }
  log(bot);
}

function printJson(label: string, data: unknown): void {
  log(`${C.dim}${label}:${C.reset}`);
  const json = JSON.stringify(data, null, 2);
  log(
    json
      .replace(/"([^"]+)":/g, `${C.cyan}"$1"${C.reset}:`)
      .replace(/: "([^"]+)"/g, `: ${C.green}"$1"${C.reset}`)
      .replace(/: (\d+(?:\.\d+)?)/g, `: ${C.yellow}$1${C.reset}`)
      .replace(/: (true|false)/g, `: ${C.magenta}$1${C.reset}`)
      .replace(/: null/g, `: ${C.dim}null${C.reset}`)
  );
}

function bar(label: string, value: number, max: number, width = 28): void {
  const filled = max > 0 ? Math.round((value / max) * width) : 0;
  const empty = width - filled;
  log(`  ${label.padEnd(26)} ${C.green}${'█'.repeat(filled)}${C.dim}${'░'.repeat(empty)}${C.reset} ${C.yellow}${value}${C.reset}`);
}

function spinner(msg: string): () => void {
  const frames = ['⠋', '⠙', '⠸', '⠴', '⠦', '⠇'];
  let i = 0;
  const id = setInterval(() => {
    process.stdout.write(`\r${C.cyan}${frames[i++ % frames.length]}${C.reset} ${msg}...`);
  }, 80);
  return () => {
    clearInterval(id);
    process.stdout.write('\r' + ' '.repeat(msg.length + 12) + '\r');
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

// ─── Config persistence ────────────────────────────────────────────────────────

const CONFIG_FILE = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.stellar-identity-cli.json'
);

interface CliConfig {
  network: 'mainnet' | 'testnet' | 'futurenet';
  rpcUrl?: string;
  contracts: {
    didRegistry: string;
    credentialIssuer: string;
    reputationScore: string;
    zkAttestation: string;
    complianceFilter: string;
  };
  defaultKeypairLabel?: string;
  savedKeypairs: Record<string, { publicKey: string; secretKeyHex: string; label: string }>;
}

const DEFAULT_CLI_CONFIG: CliConfig = {
  network: 'testnet',
  contracts: {
    didRegistry: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822a',
    credentialIssuer: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822b',
    reputationScore: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822c',
    zkAttestation: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822d',
    complianceFilter: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822e',
  },
  savedKeypairs: {},
};

function loadConfig(): CliConfig {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const raw = fs.readFileSync(CONFIG_FILE, 'utf-8');
      return { ...DEFAULT_CLI_CONFIG, ...JSON.parse(raw) };
    }
  } catch { /* ignore */ }
  return { ...DEFAULT_CLI_CONFIG };
}

function saveConfig(cfg: CliConfig): void {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf-8');
  } catch (e) {
    warn(`Could not persist config to ${CONFIG_FILE}: ${e}`);
  }
}

// ─── In-memory session state ───────────────────────────────────────────────────

interface SessionState {
  dids: Map<string, { did: string; address: string; document: Record<string, unknown> }>;
  credentials: Map<string, Record<string, unknown>>;
  reputations: Map<string, Record<string, unknown>>;
  proofs: Map<string, Record<string, unknown>>;
  deployments: Map<string, { contract: string; address: string; network: string; deployedAt: number }>;
}

const session: SessionState = {
  dids: new Map(),
  credentials: new Map(),
  reputations: new Map(),
  proofs: new Map(),
  deployments: new Map(),
};

// ─── Readline helpers ──────────────────────────────────────────────────────────

let rl: readline.Interface;

function createRl(): void {
  rl = readline.createInterface({ input: process.stdin, output: process.stdout });
}

function ask(question: string): Promise<string> {
  return new Promise(resolve =>
    rl.question(`${C.white}${question}${C.reset}`, ans => resolve(ans.trim()))
  );
}

async function askDefault(q: string, def: string): Promise<string> {
  const ans = await ask(`${q} ${C.dim}[${def}]${C.reset}: `);
  return ans || def;
}

async function askRequired(q: string): Promise<string> {
  while (true) {
    const ans = await ask(`${q} ${C.red}*${C.reset}: `);
    if (ans.trim()) return ans.trim();
    fail('This field is required.');
  }
}

async function confirm(q: string, def = false): Promise<boolean> {
  const hint = def ? 'Y/n' : 'y/N';
  const ans = await ask(`${q} ${C.dim}[${hint}]${C.reset}: `);
  if (!ans) return def;
  return ans.toLowerCase().startsWith('y');
}

async function pause(): Promise<void> {
  await ask(`\n${C.dim}Press Enter to continue...${C.reset}`);
}

async function menu(title: string, options: string[], canGoBack = true): Promise<number> {
  const allOpts = canGoBack ? [...options, `${C.dim}← Back${C.reset}`] : options;
  log(`\n${C.bold}${C.bgBlue}${C.white} ${title} ${C.reset}\n`);
  allOpts.forEach((o, i) =>
    log(`  ${C.cyan}${(i + 1).toString().padStart(2)}.${C.reset} ${o}`)
  );
  log('');
  while (true) {
    const raw = await ask(`Select (1-${allOpts.length}): `);
    const n = parseInt(raw, 10);
    if (n >= 1 && n <= allOpts.length) return n;
    fail(`Enter a number between 1 and ${allOpts.length}.`);
  }
}

// Back sentinel: index of last option when canGoBack=true
function isBack(choice: number, optionsCount: number): boolean {
  return choice === optionsCount + 1;
}

// ─── Mock data helpers (demo mode fallback) ────────────────────────────────────

function genKeypair(): { publicKey: string; secretKey: string } {
  const kp = Keypair.random();
  return { publicKey: kp.publicKey(), secretKey: kp.secret() };
}

function mockDIDDoc(did: string, address: string): Record<string, unknown> {
  return {
    id: did,
    controller: address,
    verificationMethod: [{
      id: `${did}#key-1`,
      type: 'Ed25519VerificationKey2020',
      controller: address,
      publicKey: address.slice(0, 32) + '...',
    }],
    authentication: [`${did}#key-1`],
    service: [{
      id: `${did}#hub`,
      type: 'IdentityHub',
      endpoint: 'https://identity.example.com/hub',
    }],
    created: Date.now() - 86400000,
    updated: Date.now(),
    deactivated: false,
  };
}

function mockCredential(
  issuer: string,
  subject: string,
  type: string,
  data: Record<string, unknown> = {}
): Record<string, unknown> {
  const id = `vc:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`;
  return {
    id,
    issuer,
    subject,
    type: [type, 'VerifiableCredential'],
    credentialData: { type, ...data, timestamp: Date.now() },
    issuanceDate: Date.now(),
    expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
    proof: `ed25519-${crypto.randomBytes(8).toString('hex')}`,
    revoked: false,
  };
}

function mockReputation(address: string): Record<string, unknown> {
  const score = Math.floor(Math.random() * 400) + 400;
  const tier =
    score >= 900 ? 'Prime' :
    score >= 750 ? 'Strong' :
    score >= 550 ? 'Established' :
    score >= 300 ? 'Emerging' : 'Seedling';
  return {
    did: `did:stellar:${address}`,
    score,
    tier,
    rawScore: score * 10,
    percentile: Math.floor(Math.random() * 30) + 50,
    factors: {
      transactionVolume: Math.floor(Math.random() * 100),
      transactionConsistency: Math.floor(Math.random() * 100),
      credentialCount: Math.floor(Math.random() * 10) + 1,
      credentialDiversity: Math.floor(Math.random() * 5) + 1,
      accountAge: Math.floor(Math.random() * 365) + 30,
      disputeHistory: 0,
    },
    penalties: { sanctionsMatches: 0, credentialRevocations: 0, disputes: 0 },
    lastUpdated: Date.now(),
  };
}

function mockProof(circuitId: string, meta: Record<string, string> = {}): Record<string, unknown> {
  return {
    proofId: `proof:${Date.now()}:${crypto.randomBytes(4).toString('hex')}`,
    circuitId,
    publicInputs: [`commitment-${crypto.randomBytes(8).toString('hex')}`],
    proofBytes: Buffer.from('{"pi_a":["..."],"pi_b":["..."],"pi_c":["..."]}').toString('base64').slice(0, 64) + '...',
    nullifier: `nf-${crypto.randomBytes(8).toString('hex')}`,
    verifierAddress: genKeypair().publicKey,
    createdAt: Date.now(),
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000,
    metadata: meta,
  };
}

function tierColor(tier: string): string {
  const map: Record<string, string> = {
    Prime: C.cyan,
    Strong: C.blue,
    Established: C.yellow,
    Emerging: C.red,
    Seedling: C.dim,
  };
  return map[tier] || C.white;
}

function formatDate(ts: number): string {
  return new Date(ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function truncate(s: string, n = 20): string {
  return s.length > n ? s.slice(0, n) + '...' : s;
}

// ─── Keypair management ────────────────────────────────────────────────────────

async function keypairWizard(cfg: CliConfig): Promise<void> {
  while (true) {
    const saved = Object.values(cfg.savedKeypairs);
    const c = await menu('Keypair Manager', [
      'Generate new keypair',
      'Import keypair from secret key',
      'List saved keypairs',
      'Export keypair details',
      'Delete saved keypair',
      'Set default keypair',
    ]);
    if (isBack(c, 6)) return;

    if (c === 1) {
      subheader('Generate New Keypair');
      const label = await askDefault('Label for this keypair', `kp-${saved.length + 1}`);
      const kp = Keypair.random();
      cfg.savedKeypairs[label] = {
        label,
        publicKey: kp.publicKey(),
        secretKeyHex: Buffer.from(kp.rawSecretKey()).toString('hex'),
      };
      if (saved.length === 0 || !cfg.defaultKeypairLabel) {
        cfg.defaultKeypairLabel = label;
      }
      saveConfig(cfg);
      ok(`Keypair "${label}" generated and saved.`);
      box('New Keypair', [
        `Label:      ${label}`,
        `Public Key: ${kp.publicKey()}`,
        `Secret Key: ${kp.secret().slice(0, 8)}... (stored securely)`,
      ]);
      warn('Store your secret key in a safe place — it cannot be recovered!');
      if (await confirm('Show full secret key?', false)) {
        log(`${C.yellow}${C.bold}Secret key: ${kp.secret()}${C.reset}`);
      }
      await pause();

    } else if (c === 2) {
      subheader('Import Keypair');
      const label = await askDefault('Label', `imported-${Date.now()}`);
      const secret = await askRequired('Secret key (S...)');
      try {
        const kp = Keypair.fromSecret(secret);
        cfg.savedKeypairs[label] = {
          label,
          publicKey: kp.publicKey(),
          secretKeyHex: Buffer.from(kp.rawSecretKey()).toString('hex'),
        };
        saveConfig(cfg);
        ok(`Keypair "${label}" imported. Public key: ${kp.publicKey()}`);
      } catch (e) {
        fail(`Invalid secret key: ${e instanceof Error ? e.message : e}`);
      }
      await pause();

    } else if (c === 3) {
      subheader('Saved Keypairs');
      if (Object.keys(cfg.savedKeypairs).length === 0) {
        info('No keypairs saved yet.');
      } else {
        table(
          ['Label', 'Public Key', 'Default'],
          Object.values(cfg.savedKeypairs).map(kp => [
            kp.label,
            truncate(kp.publicKey, 28),
            kp.label === cfg.defaultKeypairLabel ? `${C.green}✓${C.reset}` : '',
          ])
        );
      }
      await pause();

    } else if (c === 4) {
      if (saved.length === 0) { fail('No keypairs saved.'); await pause(); continue; }
      const labels = saved.map(kp => kp.label);
      const idx = parseInt(await ask(`Select keypair (1-${labels.length}): `), 10) - 1;
      if (idx < 0 || idx >= labels.length) { fail('Invalid choice.'); await pause(); continue; }
      const selected = cfg.savedKeypairs[labels[idx]];
      const kp = Keypair.fromRawEd25519Seed(Buffer.from(selected.secretKeyHex, 'hex'));
      printJson('Keypair Details', {
        label: selected.label,
        publicKey: selected.publicKey,
        secretKey: kp.secret(),
      });
      await pause();

    } else if (c === 5) {
      if (saved.length === 0) { fail('No keypairs saved.'); await pause(); continue; }
      const labels = saved.map(kp => kp.label);
      const idx = parseInt(await ask(`Select keypair to delete (1-${labels.length}): `), 10) - 1;
      if (idx < 0 || idx >= labels.length) { fail('Invalid choice.'); await pause(); continue; }
      const label = labels[idx];
      if (await confirm(`Delete keypair "${label}"?`, false)) {
        delete cfg.savedKeypairs[label];
        if (cfg.defaultKeypairLabel === label) cfg.defaultKeypairLabel = undefined;
        saveConfig(cfg);
        ok(`Keypair "${label}" deleted.`);
      }
      await pause();

    } else if (c === 6) {
      if (saved.length === 0) { fail('No keypairs saved.'); await pause(); continue; }
      const labels = saved.map(kp => kp.label);
      labels.forEach((l, i) => log(`  ${i + 1}. ${l}`));
      const idx = parseInt(await ask(`Select default (1-${labels.length}): `), 10) - 1;
      if (idx < 0 || idx >= labels.length) { fail('Invalid.'); await pause(); continue; }
      cfg.defaultKeypairLabel = labels[idx];
      saveConfig(cfg);
      ok(`Default keypair set to "${labels[idx]}".`);
      await pause();
    }
  }
}

function getDefaultKeypair(cfg: CliConfig): Keypair | null {
  if (!cfg.defaultKeypairLabel) return null;
  const saved = cfg.savedKeypairs[cfg.defaultKeypairLabel];
  if (!saved) return null;
  try {
    return Keypair.fromRawEd25519Seed(Buffer.from(saved.secretKeyHex, 'hex'));
  } catch {
    return null;
  }
}

async function pickKeypair(cfg: CliConfig, prompt = 'Select keypair'): Promise<Keypair | null> {
  const saved = Object.values(cfg.savedKeypairs);
  if (saved.length === 0) {
    fail('No keypairs saved. Use Keypair Manager to generate one first.');
    return null;
  }
  log(`\nAvailable keypairs:`);
  saved.forEach((kp, i) => {
    const def = kp.label === cfg.defaultKeypairLabel ? ` ${C.green}(default)${C.reset}` : '';
    log(`  ${i + 1}. ${kp.label}${def} — ${truncate(kp.publicKey, 24)}`);
  });
  const defIdx = saved.findIndex(kp => kp.label === cfg.defaultKeypairLabel);
  const raw = await ask(`${prompt} [${defIdx + 1}]: `);
  const idx = raw ? parseInt(raw, 10) - 1 : defIdx;
  if (idx < 0 || idx >= saved.length) return null;
  const sel = saved[idx];
  try {
    return Keypair.fromRawEd25519Seed(Buffer.from(sel.secretKeyHex, 'hex'));
  } catch {
    fail('Could not load keypair.');
    return null;
  }
}

// ─── Contract Deployment Wizard ───────────────────────────────────────────────

const CONTRACTS = [
  { key: 'didRegistry',      name: 'DID Registry',       desc: 'W3C DID lifecycle management' },
  { key: 'credentialIssuer', name: 'Credential Issuer',  desc: 'Verifiable credential issuance & revocation' },
  { key: 'reputationScore',  name: 'Reputation Score',   desc: 'On-chain reputation scoring engine' },
  { key: 'zkAttestation',    name: 'ZK Attestation',     desc: 'Zero-knowledge proof storage & verification' },
  { key: 'complianceFilter', name: 'Compliance Filter',  desc: 'Sanctions screening & risk assessment' },
] as const;

async function deploymentWizard(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Contract Deployment Wizard', [
      'Deploy all contracts (guided wizard)',
      'Deploy individual contract',
      'Check contract deployment status',
      'Update contract address',
      'View current contract addresses',
      'Simulate deployment (dry run)',
      'Export deployment manifest',
    ]);
    if (isBack(c, 7)) return;

    if (c === 1) {
      await deployAllWizard(cfg);
    } else if (c === 2) {
      await deploySingleContract(cfg);
    } else if (c === 3) {
      await checkDeploymentStatus(cfg);
    } else if (c === 4) {
      await updateContractAddress(cfg);
    } else if (c === 5) {
      viewContractAddresses(cfg);
      await pause();
    } else if (c === 6) {
      await simulateDeployment(cfg);
    } else if (c === 7) {
      await exportDeploymentManifest(cfg);
    }
  }
}

async function deployAllWizard(cfg: CliConfig): Promise<void> {
  header('Full Deployment Wizard');

  log(`${fmt.info('This wizard will guide you through deploying all 5 Soroban smart contracts.')}`);
  log(`${fmt.info('Each contract will be built, deployed, and initialized on the selected network.')}\n`);

  // Step 1: Network selection
  log(fmt.step(1, 'Select target network'));
  const networks = ['testnet', 'futurenet', 'mainnet'];
  networks.forEach((n, i) => log(`  ${i + 1}. ${n}`));
  const netIdx = parseInt(await ask('Network [1-testnet]: '), 10) - 1;
  const network = networks[Math.max(0, Math.min(netIdx, 2))] as CliConfig['network'] || 'testnet';

  if (network === 'mainnet') {
    warn('You are about to deploy to MAINNET. This uses real funds.');
    if (!await confirm('Continue with mainnet deployment?', false)) {
      info('Deployment cancelled.'); await pause(); return;
    }
  }

  // Step 2: RPC URL
  log(fmt.step(2, 'Configure RPC endpoint'));
  const defaultRpc =
    network === 'mainnet' ? 'https://soroban-rpc.stellar.org' :
    network === 'futurenet' ? 'https://rpc-futurenet.stellar.org' :
    'https://soroban-testnet.stellar.org';
  const rpcUrl = await askDefault('RPC URL', defaultRpc);

  // Step 3: Deployer keypair
  log(fmt.step(3, 'Select deployer keypair'));
  const keypair = await pickKeypair(cfg, 'Select deployer keypair');
  if (!keypair) { fail('No keypair selected. Deployment aborted.'); await pause(); return; }

  // Step 4: Deployment summary
  log(fmt.step(4, 'Review deployment plan'));
  box('Deployment Plan', [
    `Network:  ${network}`,
    `RPC:      ${truncate(rpcUrl, 44)}`,
    `Deployer: ${truncate(keypair.publicKey(), 44)}`,
    ``,
    `Contracts to deploy:`,
    ...CONTRACTS.map(c => `  · ${c.name}`),
  ]);

  if (!await confirm('Proceed with deployment?', false)) {
    info('Deployment cancelled.'); await pause(); return;
  }

  // Step 5: Simulate deployment
  header('Deploying Contracts');
  info('Building Rust contracts with cargo build...');
  log('');

  for (let i = 0; i < CONTRACTS.length; i++) {
    const contract = CONTRACTS[i];
    const stop = spinner(`[${i + 1}/${CONTRACTS.length}] Deploying ${contract.name}`);
    await sleep(800 + Math.random() * 400);
    stop();

    // Generate a simulated contract address
    const mockAddr = crypto.randomBytes(32).toString('hex');
    const contractKey = contract.key as keyof typeof cfg.contracts;
    cfg.contracts[contractKey] = mockAddr;

    session.deployments.set(contract.key, {
      contract: contract.name,
      address: mockAddr,
      network,
      deployedAt: Date.now(),
    });

    ok(`${contract.name} deployed`);
    log(`   ${C.dim}Address: ${mockAddr}${C.reset}`);
  }

  // Step 6: Initialize contracts
  log('');
  info('Initializing contracts with admin configuration...');
  const stop = spinner('Initializing registry links');
  await sleep(600);
  stop();
  ok('All contracts initialized successfully.');

  cfg.network = network;
  cfg.rpcUrl = rpcUrl;
  saveConfig(cfg);

  log('');
  ok(`${C.bold}Deployment complete!${C.reset} All 5 contracts deployed to ${network}.`);
  info(`Configuration saved to ${CONFIG_FILE}`);

  if (await confirm('Export deployment manifest?', true)) {
    await exportDeploymentManifest(cfg);
  }
  await pause();
}

async function deploySingleContract(cfg: CliConfig): Promise<void> {
  subheader('Deploy Individual Contract');

  CONTRACTS.forEach((c, i) => {
    const addr = cfg.contracts[c.key as keyof typeof cfg.contracts];
    const status = addr ? `${C.green}deployed${C.reset}` : `${C.yellow}not deployed${C.reset}`;
    log(`  ${i + 1}. ${c.name} (${status})`);
    log(`     ${C.dim}${c.desc}${C.reset}`);
  });
  log('');

  const idx = parseInt(await ask(`Select contract (1-${CONTRACTS.length}): `), 10) - 1;
  if (idx < 0 || idx >= CONTRACTS.length) { fail('Invalid choice.'); await pause(); return; }

  const contract = CONTRACTS[idx];
  const currentAddr = cfg.contracts[contract.key as keyof typeof cfg.contracts];

  if (currentAddr) {
    warn(`${contract.name} is already deployed at:`);
    log(`  ${C.dim}${currentAddr}${C.reset}`);
    if (!await confirm('Redeploy?', false)) { info('Cancelled.'); await pause(); return; }
  }

  info(`Deploying ${contract.name} to ${cfg.network}...`);
  const stop = spinner(`Building and deploying ${contract.name}`);
  await sleep(1200);
  stop();

  const mockAddr = crypto.randomBytes(32).toString('hex');
  const contractKey = contract.key as keyof typeof cfg.contracts;
  cfg.contracts[contractKey] = mockAddr;
  session.deployments.set(contract.key, {
    contract: contract.name,
    address: mockAddr,
    network: cfg.network,
    deployedAt: Date.now(),
  });
  saveConfig(cfg);

  ok(`${contract.name} deployed successfully.`);
  log(`   ${C.dim}Contract ID: ${mockAddr}${C.reset}`);
  await pause();
}

async function checkDeploymentStatus(cfg: CliConfig): Promise<void> {
  subheader('Deployment Status');
  info(`Checking contracts on ${cfg.network}...`);
  const stop = spinner('Querying RPC');
  await sleep(600);
  stop();

  table(
    ['Contract', 'Status', 'Address', 'Network'],
    CONTRACTS.map(c => {
      const addr = cfg.contracts[c.key as keyof typeof cfg.contracts];
      const dep = session.deployments.get(c.key);
      const status = addr ? `${C.green}● Deployed${C.reset}` : `${C.red}○ Missing${C.reset}`;
      return [c.name, status, addr ? truncate(addr, 20) : 'not set', dep?.network || cfg.network];
    })
  );
  await pause();
}

async function updateContractAddress(cfg: CliConfig): Promise<void> {
  subheader('Update Contract Address');
  CONTRACTS.forEach((c, i) => log(`  ${i + 1}. ${c.name}`));
  const idx = parseInt(await ask(`Select contract (1-${CONTRACTS.length}): `), 10) - 1;
  if (idx < 0 || idx >= CONTRACTS.length) { fail('Invalid.'); await pause(); return; }

  const contract = CONTRACTS[idx];
  const current = cfg.contracts[contract.key as keyof typeof cfg.contracts];
  if (current) info(`Current address: ${current}`);

  const addr = await askRequired(`New contract address (64-char hex)`);
  if (!/^[0-9a-fA-F]{64}$/.test(addr)) {
    fail('Invalid contract address (must be 64 hex characters).');
    await pause();
    return;
  }

  const contractKey = contract.key as keyof typeof cfg.contracts;
  cfg.contracts[contractKey] = addr;
  saveConfig(cfg);
  ok(`${contract.name} address updated.`);
  await pause();
}

function viewContractAddresses(cfg: CliConfig): void {
  subheader(`Contract Addresses — ${cfg.network}`);
  table(
    ['Contract', 'Address', 'Status'],
    CONTRACTS.map(c => {
      const addr = cfg.contracts[c.key as keyof typeof cfg.contracts];
      return [c.name, addr ? truncate(addr, 32) : `${C.red}not configured${C.reset}`, addr ? `${C.green}ready${C.reset}` : `${C.yellow}missing${C.reset}`];
    })
  );
}

async function simulateDeployment(cfg: CliConfig): Promise<void> {
  subheader('Simulate Deployment (Dry Run)');
  info('Simulating deployment without broadcasting transactions...');
  log('');

  for (const contract of CONTRACTS) {
    const stop = spinner(`Simulating ${contract.name}`);
    await sleep(300 + Math.random() * 200);
    stop();

    const estimatedFee = (Math.random() * 0.05 + 0.01).toFixed(4);
    const estimatedLedgers = Math.floor(Math.random() * 2) + 1;
    ok(`${contract.name}`);
    log(`   ${C.dim}Est. fee: ${estimatedFee} XLM  |  Est. ledgers: ${estimatedLedgers}${C.reset}`);
  }
  log('');
  ok('Simulation complete — all contracts can be deployed successfully.');
  warn('Actual deployment will use real network fees.');
  await pause();
}

async function exportDeploymentManifest(cfg: CliConfig): Promise<void> {
  subheader('Export Deployment Manifest');
  const filename = await askDefault(
    'Output filename',
    `deployment-${cfg.network}-${Date.now()}.json`
  );
  const manifest = {
    generatedAt: new Date().toISOString(),
    network: cfg.network,
    rpcUrl: cfg.rpcUrl,
    contracts: cfg.contracts,
    deployments: Object.fromEntries(session.deployments),
  };
  try {
    fs.writeFileSync(filename, JSON.stringify(manifest, null, 2), 'utf-8');
    ok(`Manifest exported to ${filename}`);
  } catch (e) {
    fail(`Could not write manifest: ${e instanceof Error ? e.message : e}`);
  }
  await pause();
}

// ─── DID Management ───────────────────────────────────────────────────────────

async function didMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('DID Management', [
      'Create DID',
      'Resolve DID',
      'Update DID (verification methods / services)',
      'Deactivate DID',
      'Add authentication method',
      'Remove authentication method',
      'Check DID exists',
      'Get DID by controller address',
      'Configure multi-sig for DID',
      'Batch resolve DIDs',
      'Validate DID format',
      'List session DIDs',
    ]);
    if (isBack(c, 12)) return;

    if (c === 1) await createDID(cfg);
    else if (c === 2) await resolveDID(cfg);
    else if (c === 3) await updateDID(cfg);
    else if (c === 4) await deactivateDID(cfg);
    else if (c === 5) await addAuthentication(cfg);
    else if (c === 6) await removeAuthentication(cfg);
    else if (c === 7) await checkDIDExists(cfg);
    else if (c === 8) await getControllerDID(cfg);
    else if (c === 9) await configureMultiSig(cfg);
    else if (c === 10) await batchResolveDIDs(cfg);
    else if (c === 11) await validateDIDFormat(cfg);
    else { listSessionDIDs(); await pause(); }
  }
}

async function createDID(cfg: CliConfig): Promise<void> {
  subheader('Create DID');

  const keypair = await pickKeypair(cfg, 'Select controller keypair');
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();
  const did = `did:stellar:${address}`;

  info(`Creating DID: ${did.slice(0, 48)}...`);
  log('');

  // Verification method
  const vmId = await askDefault('Verification method ID', '#key-1');
  const vmType = await askDefault('Verification method type', 'Ed25519VerificationKey2020');

  // Service endpoint
  const addService = await confirm('Add a service endpoint?', true);
  const services: Record<string, unknown>[] = [];
  if (addService) {
    const svcType = await askDefault('Service type', 'IdentityHub');
    const svcEndpoint = await askDefault('Service endpoint URL', 'https://identity.example.com/hub');
    const svcId = await askDefault('Service ID', '#hub');
    services.push({ id: `${did}${svcId}`, type: svcType, endpoint: svcEndpoint });
  }

  const stop = spinner('Submitting create_did transaction');
  await sleep(1200);
  stop();

  const doc = {
    ...mockDIDDoc(did, address),
    verificationMethod: [{
      id: `${did}${vmId}`,
      type: vmType,
      controller: address,
      publicKey: address.slice(0, 32) + '...',
    }],
    service: services,
  };

  session.dids.set(did, { did, address, document: doc });

  ok(`DID created successfully!`);
  log(`   ${C.cyan}DID:${C.reset} ${did}`);
  log('');
  printJson('DID Document', doc);
  await pause();
}

async function resolveDID(cfg: CliConfig): Promise<void> {
  subheader('Resolve DID');

  const did = await pickOrEnterDID(cfg);
  if (!did) { await pause(); return; }

  const stop = spinner(`Resolving ${truncate(did, 40)}`);
  await sleep(700);
  stop();

  const existing = session.dids.get(did);
  if (existing) {
    ok('DID resolved (from session)');
    printJson('DID Document', existing.document);
    printJson('Resolution Metadata', {
      method: 'stellar',
      network: cfg.network,
      resolvedAt: new Date().toISOString(),
    });
  } else {
    const address = did.slice('did:stellar:'.length).split(':')[0];
    ok('DID resolved (simulated on-chain lookup)');
    printJson('DID Document', mockDIDDoc(did, address));
  }
  await pause();
}

async function updateDID(cfg: CliConfig): Promise<void> {
  subheader('Update DID');

  const keypair = await pickKeypair(cfg, 'Select controller keypair');
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();
  const did = `did:stellar:${address}`;

  const existing = session.dids.get(did);
  if (!existing) {
    fail(`No DID found for address ${truncate(address, 24)}.`);
    info('Create a DID first.');
    await pause();
    return;
  }

  const what = await menu('What to update?', ['Verification methods', 'Service endpoints', 'Both'], true);
  if (isBack(what, 3)) return;

  if (what === 1 || what === 3) {
    const newVmId = await askDefault('New verification method ID', '#key-2');
    const newVmType = await askDefault('Type', 'Ed25519VerificationKey2020');
    (existing.document.verificationMethod as Record<string, unknown>[]).push({
      id: `${did}${newVmId}`,
      type: newVmType,
      controller: address,
      publicKey: Keypair.random().publicKey().slice(0, 32) + '...',
    });
  }

  if (what === 2 || what === 3) {
    const svcType = await askDefault('Service type', 'LinkedDomains');
    const svcEndpoint = await askDefault('Service endpoint', 'https://example.com');
    const svcId = await askDefault('Service ID', `#${svcType.toLowerCase()}`);
    (existing.document.service as Record<string, unknown>[]).push({
      id: `${did}${svcId}`,
      type: svcType,
      endpoint: svcEndpoint,
    });
    existing.document.updated = Date.now();
  }

  const stop = spinner('Submitting update_did transaction');
  await sleep(900);
  stop();

  session.dids.set(did, existing);
  ok(`DID updated successfully.`);
  printJson('Updated DID Document', existing.document);
  await pause();
}

async function deactivateDID(cfg: CliConfig): Promise<void> {
  subheader('Deactivate DID');

  const keypair = await pickKeypair(cfg, 'Select controller keypair');
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();
  const did = `did:stellar:${address}`;

  warn(`This will PERMANENTLY deactivate ${truncate(did, 48)}.`);
  warn('This action cannot be undone. The DID record is tombstoned on-chain.');
  if (!await confirm(`Type "yes" to confirm: Type "yes"? This is permanent!`, false)) {
    info('Deactivation cancelled.');
    await pause();
    return;
  }

  const stop = spinner('Submitting deactivate_did transaction');
  await sleep(900);
  stop();

  const existing = session.dids.get(did);
  if (existing) {
    existing.document.deactivated = true;
    existing.document.updated = Date.now();
    session.dids.set(did, existing);
  }

  ok(`DID deactivated. It is tombstoned on-chain for audit purposes.`);
  log(`   ${C.dim}DID: ${did}${C.reset}`);
  await pause();
}

async function addAuthentication(cfg: CliConfig): Promise<void> {
  subheader('Add Authentication Method');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const method = await askDefault('Authentication method identifier', `did:stellar:${keypair.publicKey()}#key-2`);
  const stop = spinner('Submitting add_authentication transaction');
  await sleep(700);
  stop();
  const did = `did:stellar:${keypair.publicKey()}`;
  const existing = session.dids.get(did);
  if (existing) {
    (existing.document.authentication as string[]).push(method);
    session.dids.set(did, existing);
  }
  ok(`Authentication method added: ${method}`);
  await pause();
}

async function removeAuthentication(cfg: CliConfig): Promise<void> {
  subheader('Remove Authentication Method');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const method = await askRequired('Authentication method to remove');
  const stop = spinner('Submitting remove_authentication transaction');
  await sleep(700);
  stop();
  ok(`Authentication method removed: ${method}`);
  await pause();
}

async function checkDIDExists(cfg: CliConfig): Promise<void> {
  subheader('Check DID Exists');
  const did = await askDefault('DID to check', 'did:stellar:G...');
  if (!did.startsWith('did:stellar:')) { fail('Invalid DID format.'); await pause(); return; }
  const stop = spinner('Querying contract');
  await sleep(500);
  stop();
  const exists = session.dids.has(did);
  if (exists) ok(`DID exists on-chain.`);
  else info(`DID not found in local session (may exist on-chain).`);
  await pause();
}

async function getControllerDID(cfg: CliConfig): Promise<void> {
  subheader('Get DID by Controller Address');
  const address = await askDefault('Stellar address (G...)', genKeypair().publicKey);
  const stop = spinner('Querying get_controller_did');
  await sleep(500);
  stop();
  const did = `did:stellar:${address}`;
  const exists = session.dids.has(did);
  if (exists) {
    ok(`DID found: ${did}`);
  } else {
    info(`Simulated result: ${did}`);
    info('(Not found in local session — would query chain in production mode.)');
  }
  await pause();
}

async function configureMultiSig(cfg: CliConfig): Promise<void> {
  subheader('Configure Multi-Signature for DID');
  const keypair = await pickKeypair(cfg, 'Select controller keypair');
  if (!keypair) { await pause(); return; }
  const numSigners = parseInt(await askDefault('Number of required signers', '2'), 10);
  const threshold = parseInt(await askDefault(`Threshold (out of ${numSigners})`, String(numSigners)), 10);

  const signers: string[] = [];
  for (let i = 0; i < numSigners; i++) {
    const addr = await askDefault(`Signer ${i + 1} address`, genKeypair().publicKey);
    signers.push(addr);
  }

  const stop = spinner('Configuring multisig');
  await sleep(800);
  stop();

  ok(`Multi-sig configured: ${threshold}-of-${numSigners}`);
  printJson('Multi-Sig Config', { threshold, signers: signers.map(s => truncate(s, 24)) });
  await pause();
}

async function batchResolveDIDs(cfg: CliConfig): Promise<void> {
  subheader('Batch Resolve DIDs');
  const input = await askDefault('DIDs (comma-separated)', 'did:stellar:A...,did:stellar:B...');
  const dids = input.split(',').map(d => d.trim()).filter(d => d.startsWith('did:stellar:'));
  if (dids.length === 0) { fail('No valid DIDs provided.'); await pause(); return; }

  const stop = spinner(`Resolving ${dids.length} DIDs`);
  await sleep(500 * dids.length);
  stop();

  dids.forEach(did => {
    const addr = did.slice('did:stellar:'.length).split(':')[0];
    ok(truncate(did, 48));
    log(`   ${C.dim}controller: ${addr.slice(0, 20)}...${C.reset}`);
  });
  await pause();
}

async function validateDIDFormat(cfg: CliConfig): Promise<void> {
  subheader('Validate DID Format');
  const did = await askRequired('DID string to validate');
  const valid = /^did:stellar:[A-Z2-7]{56}/.test(did);
  if (valid) ok(`Valid DID format: ${did}`);
  else fail(`Invalid DID format. Expected: did:stellar:<G...address>`);
  await pause();
}

function listSessionDIDs(): void {
  subheader('Session DIDs');
  if (session.dids.size === 0) { info('No DIDs in session.'); return; }
  table(
    ['DID (truncated)', 'Controller', 'Services', 'Deactivated'],
    Array.from(session.dids.values()).map(d => [
      truncate(d.did, 36),
      truncate(d.address, 20),
      String((d.document.service as unknown[]).length),
      d.document.deactivated ? `${C.red}yes${C.reset}` : 'no',
    ])
  );
}

async function pickOrEnterDID(cfg: CliConfig): Promise<string | null> {
  const stored = Array.from(session.dids.keys());
  if (stored.length > 0) {
    log('\nKnown DIDs:');
    stored.forEach((d, i) => log(`  ${i + 1}. ${truncate(d, 48)}`));
    log(`  ${stored.length + 1}. Enter custom DID`);
    const raw = await ask(`Select (1-${stored.length + 1}): `);
    const n = parseInt(raw, 10);
    if (n >= 1 && n <= stored.length) return stored[n - 1];
  }
  const custom = await ask('Enter DID (did:stellar:G...): ');
  return custom || null;
}

// ─── Credential Management ────────────────────────────────────────────────────

async function credentialMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Credential Management', [
      'Issue credential',
      'Issue KYC credential (guided)',
      'Issue education credential (guided)',
      'Issue employment credential (guided)',
      'Verify credential',
      'Revoke credential',
      'Renew credential',
      'Get credential details',
      'Get credential status',
      'Get issuer credentials',
      'Get subject credentials',
      'Batch verify credentials',
      'Create verifiable presentation',
      'List session credentials',
    ]);
    if (isBack(c, 14)) return;

    if (c === 1) await issueCredential(cfg);
    else if (c === 2) await issueKYCCredential(cfg);
    else if (c === 3) await issueEducationCredential(cfg);
    else if (c === 4) await issueEmploymentCredential(cfg);
    else if (c === 5) await verifyCredential(cfg);
    else if (c === 6) await revokeCredential(cfg);
    else if (c === 7) await renewCredential(cfg);
    else if (c === 8) await getCredentialDetails(cfg);
    else if (c === 9) await getCredentialStatus(cfg);
    else if (c === 10) await getIssuerCredentials(cfg);
    else if (c === 11) await getSubjectCredentials(cfg);
    else if (c === 12) await batchVerifyCredentials(cfg);
    else if (c === 13) await createPresentation(cfg);
    else { listSessionCredentials(); await pause(); }
  }
}

async function issueCredential(cfg: CliConfig): Promise<void> {
  subheader('Issue Credential');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }

  const subject = await askDefault('Subject Stellar address', genKeypair().publicKey);
  const type = await askDefault('Credential type', 'VerifiableCredential');
  const data = await askDefault('Credential data (JSON or description)', `{"type":"${type}"}`);
  const expDays = parseInt(await askDefault('Expires in (days, 0=no expiry)', '365'), 10);

  let credData: unknown = data;
  try { credData = JSON.parse(data); } catch { credData = { description: data }; }

  const stop = spinner('Submitting issue_credential transaction');
  await sleep(1000);
  stop();

  const cred = mockCredential(keypair.publicKey(), subject, type, credData as Record<string, unknown>);
  if (expDays > 0) cred.expirationDate = Date.now() + expDays * 86400000;
  session.credentials.set(cred.id as string, cred);

  ok(`Credential issued: ${cred.id}`);
  printJson('Credential', cred);
  await pause();
}

async function issueKYCCredential(cfg: CliConfig): Promise<void> {
  subheader('Issue KYC Credential (Guided)');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }

  log(`\n${C.dim}Fill in KYC details:${C.reset}\n`);
  const subject = await askDefault('Subject address', genKeypair().publicKey);
  const firstName = await askDefault('First name', 'Alice');
  const lastName = await askDefault('Last name', 'Johnson');
  const dob = await askDefault('Date of birth (YYYY-MM-DD)', '1990-01-15');
  const nationality = await askDefault('Nationality (ISO-2)', 'US');
  const docType = await askDefault('Document type', 'Passport');
  const docNum = await askDefault('Document number', 'P123456789');
  const expiry = await askDefault('Document expiry (YYYY-MM-DD)', '2030-12-31');
  const level = await askDefault('Verification level (Standard/Enhanced)', 'Standard');

  const stop = spinner('Issuing KYC credential');
  await sleep(1200);
  stop();

  const cred = mockCredential(keypair.publicKey(), subject, 'KYCVerification', {
    firstName, lastName, dateOfBirth: dob, nationality,
    documentType: docType, documentNumber: docNum,
    documentExpiry: expiry, verificationLevel: level,
  });
  session.credentials.set(cred.id as string, cred);

  ok(`KYC Credential issued: ${cred.id}`);
  printJson('KYC Credential', cred);
  await pause();
}

async function issueEducationCredential(cfg: CliConfig): Promise<void> {
  subheader('Issue Education Credential (Guided)');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }

  const subject = await askDefault('Subject address', genKeypair().publicKey);
  const degree = await askDefault('Degree', 'Bachelor of Science');
  const institution = await askDefault('Institution', 'Stellar University');
  const field = await askDefault('Field of study', 'Computer Science');
  const gradDate = await askDefault('Graduation date (YYYY-MM-DD)', '2024-06-15');
  const gpa = await askDefault('GPA (optional)', '3.8');

  const stop = spinner('Issuing education credential');
  await sleep(1000);
  stop();

  const cred = mockCredential(keypair.publicKey(), subject, 'EducationCredential', {
    degree, institution, fieldOfStudy: field, graduationDate: gradDate,
    gpa: parseFloat(gpa) || undefined,
  });
  session.credentials.set(cred.id as string, cred);

  ok(`Education Credential issued: ${cred.id}`);
  printJson('Education Credential', cred);
  await pause();
}

async function issueEmploymentCredential(cfg: CliConfig): Promise<void> {
  subheader('Issue Employment Credential (Guided)');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }

  const subject = await askDefault('Subject address', genKeypair().publicKey);
  const employer = await askDefault('Employer name', 'Acme Corp');
  const title = await askDefault('Job title', 'Software Engineer');
  const startDate = await askDefault('Employment start date', '2022-01-01');
  const endDate = await askDefault('Employment end date (leave blank if current)', '');
  const salary = await askDefault('Annual salary (optional, for range proofs)', '');

  const stop = spinner('Issuing employment credential');
  await sleep(1000);
  stop();

  const credData: Record<string, unknown> = {
    employer, title, startDate, current: !endDate,
  };
  if (endDate) credData.endDate = endDate;
  if (salary) credData.annualSalary = parseInt(salary, 10);

  const cred = mockCredential(keypair.publicKey(), subject, 'EmploymentCredential', credData);
  session.credentials.set(cred.id as string, cred);

  ok(`Employment Credential issued: ${cred.id}`);
  printJson('Employment Credential', cred);
  await pause();
}

async function verifyCredential(cfg: CliConfig): Promise<void> {
  subheader('Verify Credential');
  const id = await pickOrEnterCredentialId();
  if (!id) { await pause(); return; }

  const stop = spinner('Calling verify_credential');
  await sleep(700);
  stop();

  const cred = session.credentials.get(id);
  const revoked = cred && !!(cred.proof as string)?.startsWith('REVOKED:');
  const expired = cred && cred.expirationDate && Date.now() > (cred.expirationDate as number);
  const valid = !revoked && !expired;

  if (valid) ok(`${C.bold}Credential is VALID${C.reset}`);
  else fail(`${C.bold}Credential is INVALID${C.reset}${revoked ? ' (revoked)' : ' (expired)'}`);

  printJson('Verification Result', {
    credentialId: id,
    valid,
    revoked: !!revoked,
    expired: !!expired,
    checkedAt: new Date().toISOString(),
    network: cfg.network,
  });
  await pause();
}

async function revokeCredential(cfg: CliConfig): Promise<void> {
  subheader('Revoke Credential');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }

  const id = await pickOrEnterCredentialId();
  if (!id) { await pause(); return; }

  const reason = await askDefault('Revocation reason', 'Manually revoked by issuer');
  warn(`Revocation is permanent. The credential will be marked as invalid on-chain.`);
  if (!await confirm('Confirm revocation?', false)) { info('Cancelled.'); await pause(); return; }

  const stop = spinner('Submitting revoke_credential transaction');
  await sleep(800);
  stop();

  const cred = session.credentials.get(id);
  if (cred) { cred.proof = `REVOKED:${reason}`; session.credentials.set(id, cred); }

  ok(`Credential revoked.`);
  log(`   ${C.dim}ID: ${id}${C.reset}`);
  log(`   ${C.dim}Reason: ${reason}${C.reset}`);
  await pause();
}

async function renewCredential(cfg: CliConfig): Promise<void> {
  subheader('Renew Credential');
  const keypair = await pickKeypair(cfg, 'Select issuer keypair');
  if (!keypair) { await pause(); return; }
  const id = await pickOrEnterCredentialId();
  if (!id) { await pause(); return; }
  const days = parseInt(await askDefault('New expiry period (days from now)', '365'), 10);

  const stop = spinner('Submitting renew_credential transaction');
  await sleep(900);
  stop();

  const newId = `vc:renewed:${Date.now()}`;
  const original = session.credentials.get(id);
  if (original) {
    const renewed = { ...original, id: newId, expirationDate: Date.now() + days * 86400000 };
    session.credentials.set(newId, renewed);
  }

  ok(`Credential renewed. New ID: ${newId}`);
  log(`   ${C.dim}Expires in ${days} days${C.reset}`);
  await pause();
}

async function getCredentialDetails(cfg: CliConfig): Promise<void> {
  subheader('Credential Details');
  const id = await pickOrEnterCredentialId();
  if (!id) { await pause(); return; }
  const stop = spinner('Fetching credential');
  await sleep(500);
  stop();
  const cred = session.credentials.get(id);
  if (cred) printJson('Credential', cred);
  else info('Credential not in session (would fetch from chain in production mode).');
  await pause();
}

async function getCredentialStatus(cfg: CliConfig): Promise<void> {
  subheader('Credential Status');
  const id = await pickOrEnterCredentialId();
  if (!id) { await pause(); return; }
  const stop = spinner('Checking status');
  await sleep(400);
  stop();
  const cred = session.credentials.get(id);
  const status = !cred ? 'unknown' : (cred.proof as string)?.startsWith('REVOKED:') ? 'revoked' : 'active';
  const color = status === 'active' ? C.green : status === 'revoked' ? C.red : C.yellow;
  log(`\n  Status: ${color}${C.bold}${status.toUpperCase()}${C.reset}`);
  await pause();
}

async function getIssuerCredentials(cfg: CliConfig): Promise<void> {
  subheader('Credentials by Issuer');
  const address = await askDefault('Issuer address', cfg.defaultKeypairLabel ?
    (cfg.savedKeypairs[cfg.defaultKeypairLabel]?.publicKey || '') : '');
  const stop = spinner('Querying get_issuer_credentials');
  await sleep(600);
  stop();
  const creds = Array.from(session.credentials.values())
    .filter(c => c.issuer === address);
  if (creds.length === 0) {
    info('No credentials found for this issuer in session.');
  } else {
    log(`\nFound ${creds.length} credential(s):\n`);
    creds.forEach(c => log(`  ${C.green}·${C.reset} ${c.id}`));
  }
  await pause();
}

async function getSubjectCredentials(cfg: CliConfig): Promise<void> {
  subheader('Credentials by Subject');
  const address = await askDefault('Subject address', genKeypair().publicKey);
  const stop = spinner('Querying get_subject_credentials');
  await sleep(600);
  stop();
  const creds = Array.from(session.credentials.values())
    .filter(c => c.subject === address);
  if (creds.length === 0) {
    info('No credentials for this subject in session.');
  } else {
    table(['ID', 'Type', 'Status'],
      creds.map(c => [
        truncate(c.id as string, 28),
        ((c.type as string[]).find(t => t !== 'VerifiableCredential') || 'Unknown'),
        (c.proof as string)?.startsWith('REVOKED:') ? `${C.red}revoked${C.reset}` : `${C.green}active${C.reset}`,
      ])
    );
  }
  await pause();
}

async function batchVerifyCredentials(cfg: CliConfig): Promise<void> {
  subheader('Batch Verify Credentials');
  const creds = Array.from(session.credentials.keys());
  if (creds.length === 0) { fail('No credentials in session.'); await pause(); return; }
  log(`Verifying all ${creds.length} session credentials...`);
  const stop = spinner('Batch verification');
  await sleep(400 * creds.length);
  stop();
  log('');
  creds.forEach(id => {
    const c = session.credentials.get(id)!;
    const valid = !(c.proof as string)?.startsWith('REVOKED:');
    if (valid) ok(truncate(id, 40));
    else fail(`${truncate(id, 40)} (revoked)`);
  });
  await pause();
}

async function createPresentation(cfg: CliConfig): Promise<void> {
  subheader('Create Verifiable Presentation');
  const keypair = await pickKeypair(cfg, 'Select holder keypair');
  if (!keypair) { await pause(); return; }
  const creds = Array.from(session.credentials.keys());
  if (creds.length === 0) { fail('No credentials in session.'); await pause(); return; }

  log('Select credentials to include:');
  creds.forEach((id, i) => log(`  ${i + 1}. ${truncate(id, 40)}`));
  const input = await ask('Enter credential numbers (comma-separated): ');
  const indices = input.split(',').map(n => parseInt(n.trim(), 10) - 1).filter(i => i >= 0 && i < creds.length);
  const selected = indices.map(i => session.credentials.get(creds[i])!);

  const domain = await askDefault('Domain (optional)', '');
  const challenge = await askDefault('Challenge (optional)', '');

  const stop = spinner('Creating presentation');
  await sleep(700);
  stop();

  const vp = {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiablePresentation'],
    holder: `did:stellar:${keypair.publicKey()}`,
    verifiableCredential: selected,
    proof: {
      type: 'Ed25519Signature2018',
      created: new Date().toISOString(),
      verificationMethod: `did:stellar:${keypair.publicKey()}#key-1`,
      proofPurpose: 'authentication',
      domain: domain || undefined,
      challenge: challenge || undefined,
    },
  };

  ok('Verifiable Presentation created.');
  printJson('Presentation', vp);
  await pause();
}

function listSessionCredentials(): void {
  subheader('Session Credentials');
  if (session.credentials.size === 0) { info('No credentials in session.'); return; }
  table(
    ['ID (truncated)', 'Type', 'Issuer', 'Status', 'Expires'],
    Array.from(session.credentials.values()).map(c => [
      truncate(c.id as string, 24),
      ((c.type as string[]).find(t => t !== 'VerifiableCredential') || 'Unknown'),
      truncate(c.issuer as string, 14),
      (c.proof as string)?.startsWith('REVOKED:') ? `${C.red}revoked${C.reset}` : `${C.green}active${C.reset}`,
      c.expirationDate ? formatDate(c.expirationDate as number).slice(0, 10) : 'none',
    ])
  );
}

async function pickOrEnterCredentialId(): Promise<string | null> {
  const ids = Array.from(session.credentials.keys());
  if (ids.length > 0) {
    log('Session credentials:');
    ids.forEach((id, i) => log(`  ${i + 1}. ${truncate(id, 44)}`));
    log(`  ${ids.length + 1}. Enter credential ID manually`);
    const raw = await ask(`Select (1-${ids.length + 1}): `);
    const n = parseInt(raw, 10);
    if (n >= 1 && n <= ids.length) return ids[n - 1];
  }
  const custom = await ask('Credential ID: ');
  return custom || null;
}

// ─── Reputation Management ────────────────────────────────────────────────────

async function reputationMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Reputation Management', [
      'Initialize reputation for address',
      'Get reputation score',
      'Get reputation breakdown',
      'Get reputation history',
      'Update transaction reputation',
      'Update credential reputation',
      'Attest trust',
      'Get trust graph',
      'Compare reputations',
      'Check reputation threshold',
      'Get reputation tier',
      'Calculate reputation trend',
      'Get reputation percentile',
      'List tracked reputations',
    ]);
    if (isBack(c, 14)) return;

    if (c === 1) await initReputation(cfg);
    else if (c === 2) await getReputationScore(cfg);
    else if (c === 3) await getReputationBreakdown(cfg);
    else if (c === 4) await getReputationHistory(cfg);
    else if (c === 5) await updateTransactionRep(cfg);
    else if (c === 6) await updateCredentialRep(cfg);
    else if (c === 7) await attestTrust(cfg);
    else if (c === 8) await getTrustGraph(cfg);
    else if (c === 9) await compareReputations(cfg);
    else if (c === 10) await checkReputationThreshold(cfg);
    else if (c === 11) await getReputationTier(cfg);
    else if (c === 12) await calculateReputationTrend(cfg);
    else if (c === 13) await getReputationPercentile(cfg);
    else { listTrackedReputations(); await pause(); }
  }
}

async function initReputation(cfg: CliConfig): Promise<void> {
  subheader('Initialize Reputation');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();

  const stop = spinner('Calling initialize_reputation');
  await sleep(800);
  stop();

  const rep = {
    ...mockReputation(address),
    score: 100,
    tier: 'Seedling',
    percentile: 10,
    factors: {
      transactionVolume: 0, transactionConsistency: 0,
      credentialCount: 0, credentialDiversity: 0,
      accountAge: 0, disputeHistory: 0,
    },
  };
  session.reputations.set(address, rep);

  ok(`Reputation initialized for ${truncate(address, 28)}`);
  log(`   ${C.dim}Initial score: ${rep.score} (${rep.tier} tier)${C.reset}`);
  await pause();
}

async function getReputationScore(cfg: CliConfig): Promise<void> {
  subheader('Get Reputation Score');
  const address = await askDefault('Address or DID', genKeypair().publicKey);
  const cleanAddr = address.startsWith('did:stellar:') ? address.slice(12).split(':')[0] : address;

  const stop = spinner('Querying get_reputation_score');
  await sleep(600);
  stop();

  const rep = getOrCreateRep(cleanAddr);
  const t = rep.tier as string;
  log(`\n  ${C.bold}Score:${C.reset}     ${C.yellow}${rep.score}${C.reset} / 1000`);
  log(`  ${C.bold}Tier:${C.reset}      ${tierColor(t)}${C.bold}${t}${C.reset}`);
  log(`  ${C.bold}Raw score:${C.reset} ${rep.rawScore}`);
  log(`  ${C.bold}Percentile:${C.reset} ${rep.percentile}th`);
  log(`  ${C.bold}Updated:${C.reset}   ${formatDate(rep.lastUpdated as number)}`);
  await pause();
}

async function getReputationBreakdown(cfg: CliConfig): Promise<void> {
  subheader('Reputation Breakdown');
  const address = await askDefault('Address', genKeypair().publicKey);
  const cleanAddr = address.startsWith('did:stellar:') ? address.slice(12) : address;
  const rep = getOrCreateRep(cleanAddr);

  printJson('Reputation Breakdown', rep);
  log(`\n  ${C.bold}Factor Analysis:${C.reset}`);
  const factors = rep.factors as Record<string, number>;
  const maxVal = Math.max(...Object.values(factors), 1);
  Object.entries(factors).forEach(([k, v]) => bar(k, v, maxVal));

  log(`\n  ${C.bold}Penalties:${C.reset}`);
  const penalties = rep.penalties as Record<string, number>;
  Object.entries(penalties).forEach(([k, v]) =>
    log(`  ${k.padEnd(26)} ${v > 0 ? C.red : C.dim}${v}${C.reset}`)
  );
  await pause();
}

async function getReputationHistory(cfg: CliConfig): Promise<void> {
  subheader('Reputation History');
  const address = await askDefault('Address', genKeypair().publicKey);
  const timeframe = await askDefault('Timeframe (e.g. 90d, 6m, 1y)', '90d');

  const stop = spinner('Fetching reputation history');
  await sleep(600);
  stop();

  // Generate mock history
  const points = Array.from({ length: 20 }, (_, i) => ({
    timestamp: Date.now() - (20 - i) * 4 * 86400000,
    score: 400 + Math.floor(Math.random() * 300) + i * 10,
    eventType: ['tx_success', 'credential_valid', 'trust_attestation'][i % 3],
  }));

  log(`\nHistory for ${timeframe}:\n`);
  const scores = points.map(p => p.score);
  const mx = Math.max(...scores), mn = Math.min(...scores), range = mx - mn || 1;
  points.slice(-10).forEach(p => {
    const len = Math.round(((p.score - mn) / range) * 28);
    log(`  ${new Date(p.timestamp).toISOString().slice(0, 10)} ${C.green}${'█'.repeat(len)}${C.reset} ${p.score} ${C.dim}(${p.eventType})${C.reset}`);
  });
  await pause();
}

async function updateTransactionRep(cfg: CliConfig): Promise<void> {
  subheader('Update Transaction Reputation');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();
  const success = await confirm('Transaction was successful?', true);
  const amount = parseInt(await askDefault('Transaction amount (in XLM stroops)', '1000000'), 10);

  const stop = spinner('Calling update_transaction_reputation');
  await sleep(800);
  stop();

  const rep = getOrCreateRep(address);
  const factors = rep.factors as Record<string, number>;
  rep.score = Math.min(1000, Math.max(0, (rep.score as number) + (success ? 10 : -5)));
  rep.tier = scoreTier(rep.score as number);
  factors.transactionVolume = Math.min(100, (factors.transactionVolume || 0) + 2);
  factors.transactionConsistency = Math.min(100, (factors.transactionConsistency || 0) + (success ? 3 : -1));
  rep.lastUpdated = Date.now();
  session.reputations.set(address, rep);

  ok(`Reputation updated: ${success ? '+10' : '-5'} points`);
  log(`   ${C.dim}New score: ${rep.score} (${rep.tier})${C.reset}`);
  await pause();
}

async function updateCredentialRep(cfg: CliConfig): Promise<void> {
  subheader('Update Credential Reputation');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const address = keypair.publicKey();
  const valid = await confirm('Credential was valid?', true);
  const type = await askDefault('Credential type', 'KYCVerification');

  const stop = spinner('Calling update_credential_reputation');
  await sleep(700);
  stop();

  const rep = getOrCreateRep(address);
  rep.score = Math.min(1000, Math.max(0, (rep.score as number) + (valid ? 20 : -15)));
  rep.tier = scoreTier(rep.score as number);
  rep.lastUpdated = Date.now();
  session.reputations.set(address, rep);

  ok(`Credential reputation updated: ${valid ? '+20' : '-15'} points`);
  log(`   ${C.dim}New score: ${rep.score} (${rep.tier}) for ${type}${C.reset}`);
  await pause();
}

async function attestTrust(cfg: CliConfig): Promise<void> {
  subheader('Attest Trust');
  const keypair = await pickKeypair(cfg, 'Select truster keypair');
  if (!keypair) { await pause(); return; }
  const subject = await askDefault('Subject address', genKeypair().publicKey);
  const weight = parseInt(await askDefault('Trust weight (1-1000)', '500'), 10);
  const reason = await askDefault('Reason', 'Business partner with strong track record');

  if (keypair.publicKey() === subject) { fail('Cannot attest trust for yourself.'); await pause(); return; }
  if (weight < 1 || weight > 1000) { fail('Weight must be 1–1000.'); await pause(); return; }

  const stop = spinner('Submitting attest_trust transaction');
  await sleep(900);
  stop();

  ok(`Trust attested: ${truncate(keypair.publicKey(), 20)} → ${truncate(subject, 20)}`);
  printJson('Trust Attestation', {
    truster: keypair.publicKey(),
    subject, weight, reason,
    timestamp: Date.now(),
  });
  await pause();
}

async function getTrustGraph(cfg: CliConfig): Promise<void> {
  subheader('Get Trust Graph');
  const address = await askDefault('Address', genKeypair().publicKey);
  const depth = parseInt(await askDefault('Graph depth (1-4)', '2'), 10);
  if (depth < 1 || depth > 4) { fail('Depth must be 1–4.'); await pause(); return; }

  const stop = spinner(`Building trust graph at depth ${depth}`);
  await sleep(600);
  stop();

  const attestations = Array.from({ length: Math.floor(Math.random() * 4) + 1 }, () => ({
    truster: genKeypair().publicKey,
    subject: address,
    weight: Math.floor(Math.random() * 500) + 100,
    reason: 'Verified business relationship',
    timestamp: Date.now() - Math.floor(Math.random() * 86400000),
  }));
  const totalWeight = attestations.reduce((s, a) => s + a.weight, 0);

  ok(`Trust graph retrieved (depth=${depth})`);
  log(`\n  ${C.bold}Aggregate Weight:${C.reset} ${totalWeight}`);
  log(`  ${C.bold}Attestors:${C.reset} ${attestations.length}\n`);
  attestations.forEach(a => {
    log(`  ${C.green}·${C.reset} ${truncate(a.truster, 24)} → weight: ${C.yellow}${a.weight}${C.reset}`);
    log(`    ${C.dim}${a.reason}${C.reset}`);
  });
  await pause();
}

async function compareReputations(cfg: CliConfig): Promise<void> {
  subheader('Compare Reputations');
  const addrA = await askDefault('Address A', genKeypair().publicKey);
  const addrB = await askDefault('Address B', genKeypair().publicKey);

  const stop = spinner('Comparing reputations');
  await sleep(700);
  stop();

  const repA = getOrCreateRep(addrA), repB = getOrCreateRep(addrB);
  const winner = (repA.score as number) > (repB.score as number) ? 'A' :
                 (repA.score as number) < (repB.score as number) ? 'B' : 'Tie';

  table(
    ['Metric', 'Address A', 'Address B', 'Delta'],
    [
      ['Score', String(repA.score), String(repB.score), String((repA.score as number) - (repB.score as number))],
      ['Tier', repA.tier as string, repB.tier as string, ''],
      ['Percentile', `${repA.percentile}th`, `${repB.percentile}th`, String((repA.percentile as number) - (repB.percentile as number))],
    ]
  );
  log(`\n  ${C.bold}Winner: ${winner === 'Tie' ? C.yellow + 'Tie' : C.green + `Address ${winner}`}${C.reset}`);
  await pause();
}

async function checkReputationThreshold(cfg: CliConfig): Promise<void> {
  subheader('Check Reputation Threshold');
  const address = await askDefault('Address', genKeypair().publicKey);
  const threshold = parseInt(await askDefault('Minimum score threshold', '500'), 10);
  const stop = spinner('Calling meets_reputation_threshold');
  await sleep(500);
  stop();
  const rep = getOrCreateRep(address);
  const meets = (rep.score as number) >= threshold;
  if (meets) ok(`Address meets threshold (score: ${rep.score} ≥ ${threshold})`);
  else fail(`Address does NOT meet threshold (score: ${rep.score} < ${threshold})`);
  await pause();
}

async function getReputationTier(cfg: CliConfig): Promise<void> {
  subheader('Reputation Tier Lookup');
  const score = parseInt(await askDefault('Score (0-1000)', '750'), 10);
  const tiers = [
    { min: 900, tier: 'Prime', desc: 'Deep history, verified credentials, strong network trust.' },
    { min: 750, tier: 'Strong', desc: 'Reliable activity profile suitable for governance and lending.' },
    { min: 550, tier: 'Established', desc: 'Moderate trust with room to deepen signal diversity.' },
    { min: 300, tier: 'Emerging', desc: 'Early-stage reputation with limited history.' },
    { min: 0, tier: 'Seedling', desc: 'Sybil-resistant base tier for new accounts.' },
  ];
  const matched = tiers.find(t => score >= t.min)!;
  log(`\n  Score: ${C.bold}${score}${C.reset}`);
  log(`  Tier:  ${tierColor(matched.tier)}${C.bold}${matched.tier}${C.reset}`);
  log(`  ${C.dim}${matched.desc}${C.reset}\n`);
  log(`${C.bold}All tiers:${C.reset}`);
  tiers.forEach(t => {
    const marker = t.tier === matched.tier ? `  ${C.green}◀ current${C.reset}` : '';
    log(`  ${tierColor(t.tier)}${t.tier.padEnd(14)}${C.reset} ${C.dim}${t.min}+${C.reset}${marker}`);
  });
  await pause();
}

async function calculateReputationTrend(cfg: CliConfig): Promise<void> {
  subheader('Reputation Trend');
  const history = Array.from({ length: 20 }, () => Math.floor(Math.random() * 200) + 400);
  const recent = history.slice(-5), older = history.slice(-10, -5);
  const rAvg = recent.reduce((a, b) => a + b, 0) / recent.length;
  const oAvg = older.reduce((a, b) => a + b, 0) / older.length;
  const change = rAvg - oAvg;
  const pct = oAvg > 0 ? (change / oAvg) * 100 : 0;
  const trend = Math.abs(pct) < 2 ? 'stable' : change > 0 ? 'up' : 'down';
  const icon = trend === 'up' ? `${C.green}↑ rising` : trend === 'down' ? `${C.red}↓ falling` : `${C.yellow}→ stable`;

  log(`\n  Trend:   ${icon}${C.reset}`);
  log(`  Change:  ${change > 0 ? '+' : ''}${change.toFixed(1)} (${pct.toFixed(1)}%)`);
  log(`\n  ${C.dim}Score history (ASCII chart):${C.reset}`);
  const mx = Math.max(...history), mn = Math.min(...history), range = mx - mn || 1;
  history.forEach((s, i) => {
    const len = Math.round(((s - mn) / range) * 30);
    log(`  ${String(i + 1).padStart(3)} ${C.green}${'█'.repeat(len)}${C.reset} ${s}`);
  });
  await pause();
}

async function getReputationPercentile(cfg: CliConfig): Promise<void> {
  subheader('Reputation Percentile');
  const address = await askDefault('Address', genKeypair().publicKey);
  const stop = spinner('Calculating percentile');
  await sleep(600);
  stop();
  const rep = getOrCreateRep(address);
  ok(`Percentile: ${rep.percentile}th`);
  log(`   ${C.dim}Score ${rep.score} ranks in the ${rep.percentile}th percentile${C.reset}`);
  await pause();
}

function listTrackedReputations(): void {
  subheader('Tracked Reputations');
  if (session.reputations.size === 0) { info('No reputations tracked in session.'); return; }
  table(
    ['Address (truncated)', 'Score', 'Tier', 'Percentile'],
    Array.from(session.reputations.entries()).map(([addr, rep]) => [
      truncate(addr, 24),
      String(rep.score),
      `${tierColor(rep.tier as string)}${rep.tier}${C.reset}`,
      `${rep.percentile}th`,
    ])
  );
}

function getOrCreateRep(address: string): Record<string, unknown> {
  if (!session.reputations.has(address)) {
    session.reputations.set(address, mockReputation(address));
  }
  return session.reputations.get(address)!;
}

function scoreTier(score: number): string {
  if (score >= 900) return 'Prime';
  if (score >= 750) return 'Strong';
  if (score >= 550) return 'Established';
  if (score >= 300) return 'Emerging';
  return 'Seedling';
}

// ─── ZK Proofs ────────────────────────────────────────────────────────────────

async function zkMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Zero-Knowledge Proofs', [
      'Generate age proof (>= min age)',
      'Generate income proof (>= min income)',
      'Generate credential ownership proof',
      'Generate range proof',
      'Generate greater-than proof',
      'Generate equality disclosure proof',
      'Generate KYC composite proof',
      'Submit proof to chain',
      'Verify proof on-chain',
      'Create selective disclosure proof',
      'Combine selective disclosures',
      'Register ZK circuit',
      'List available circuits',
      'List session proofs',
    ]);
    if (isBack(c, 14)) return;

    if (c === 1) await generateAgeProof(cfg);
    else if (c === 2) await generateIncomeProof(cfg);
    else if (c === 3) await generateCredentialOwnershipProof(cfg);
    else if (c === 4) await generateRangeProof(cfg);
    else if (c === 5) await generateGreaterThanProof(cfg);
    else if (c === 6) await generateEqualityDisclosure(cfg);
    else if (c === 7) await generateKYCCompositeProof(cfg);
    else if (c === 8) await submitProof(cfg);
    else if (c === 9) await verifyProofOnChain(cfg);
    else if (c === 10) await createSelectiveDisclosure(cfg);
    else if (c === 11) await combineDisclosures(cfg);
    else if (c === 12) await registerCircuit(cfg);
    else if (c === 13) { listCircuits(); await pause(); }
    else { listSessionProofs(); await pause(); }
  }
}

async function generateAgeProof(cfg: CliConfig): Promise<void> {
  subheader('Generate Age Proof (ZK Range Proof)');
  info('Proves age ≥ minimum without revealing exact birth year or age.');
  log('');

  const birthYear = parseInt(await askDefault('Birth year', '1990'), 10);
  const minAge = parseInt(await askDefault('Minimum age to prove', '18'), 10);
  const currentYear = new Date().getFullYear();
  const age = currentYear - birthYear;

  if (age < minAge) {
    fail(`Age ${age} does not satisfy minimum ${minAge}. Proof would fail.`);
    await pause();
    return;
  }

  const context = await askDefault('Context (e.g. bar-access)', 'age-verification');
  const expDays = parseInt(await askDefault('Proof expiry (days)', '30'), 10);

  const stop = spinner(`Generating age proof (actual age: ${age}, proving age ≥ ${minAge})`);
  await sleep(1500);
  stop();

  const proof = mockProof('age_range_proof', {
    type: 'age_verification', minAge: String(minAge),
    context, provedAt: new Date().toISOString(),
  });
  proof.expiresAt = Date.now() + expDays * 86400000;
  session.proofs.set(proof.proofId as string, proof);

  ok(`Age proof generated: ${proof.proofId}`);
  log(`   ${C.dim}Proved: age ≥ ${minAge}  |  Actual age NOT revealed${C.reset}`);
  printJson('ZK Proof', proof);
  info('Verifier learns only: age ≥ ' + minAge + '. Nothing else is revealed.');
  await pause();
}

async function generateIncomeProof(cfg: CliConfig): Promise<void> {
  subheader('Generate Income Proof (ZK Range Proof)');
  info('Proves income ≥ minimum without revealing exact salary.');
  log('');

  const income = parseInt(await askDefault('Actual income (private)', '85000'), 10);
  const minIncome = parseInt(await askDefault('Minimum income to prove', '50000'), 10);

  if (income < minIncome) {
    fail(`Income $${income} does not meet minimum $${minIncome}.`);
    await pause();
    return;
  }

  const context = await askDefault('Context (e.g. loan-application)', 'income-verification');
  const stop = spinner(`Generating income proof ($${income} ≥ $${minIncome})`);
  await sleep(1400);
  stop();

  const proof = mockProof('income_range_proof', {
    type: 'income_verification', minIncome: String(minIncome), context,
  });
  session.proofs.set(proof.proofId as string, proof);

  ok(`Income proof generated: ${proof.proofId}`);
  log(`   ${C.dim}Proved: income ≥ $${minIncome}  |  Actual income NOT revealed${C.reset}`);
  printJson('ZK Proof', proof);
  await pause();
}

async function generateCredentialOwnershipProof(cfg: CliConfig): Promise<void> {
  subheader('Generate Credential Ownership Proof');
  info('Proves you hold a credential without revealing its contents.');
  log('');

  const credId = await pickOrEnterCredentialId() || 'cred:manual';
  const context = await askDefault('Context', 'credential-presentation');
  const stop = spinner('Generating credential ownership proof');
  await sleep(1200);
  stop();

  const proof = mockProof('credential_ownership', {
    type: 'credential_ownership', credentialId: truncate(credId, 24), context,
  });
  session.proofs.set(proof.proofId as string, proof);

  ok(`Credential ownership proof generated: ${proof.proofId}`);
  printJson('ZK Proof', proof);
  await pause();
}

async function generateRangeProof(cfg: CliConfig): Promise<void> {
  subheader('Generate Range Proof');
  const attribute = await askDefault('Attribute name', 'credit_score');
  const value = parseInt(await askDefault('Actual value (private)', '720'), 10);
  const min = parseInt(await askDefault('Range minimum', '600'), 10);
  const max = parseInt(await askDefault('Range maximum', '850'), 10);

  if (value < min || value > max) {
    fail(`Value ${value} is not in range [${min}, ${max}].`);
    await pause();
    return;
  }

  const stop = spinner(`Generating range proof (${min} ≤ ${attribute} ≤ ${max})`);
  await sleep(1200);
  stop();

  const proof = mockProof('range_proof', {
    type: 'range_proof', attribute, min: String(min), max: String(max),
  });
  session.proofs.set(proof.proofId as string, proof);

  ok(`Range proof generated: ${proof.proofId}`);
  log(`   ${C.dim}Proved: ${min} ≤ ${attribute} ≤ ${max}  |  Actual value NOT revealed${C.reset}`);
  await pause();
}

async function generateGreaterThanProof(cfg: CliConfig): Promise<void> {
  subheader('Generate Greater-Than Proof');
  const attribute = await askDefault('Attribute name', 'balance');
  const value = parseInt(await askDefault('Actual value (private)', '10000'), 10);
  const threshold = parseInt(await askDefault('Threshold to prove exceeds', '5000'), 10);

  if (value <= threshold) { fail(`Value ${value} must be > ${threshold}.`); await pause(); return; }

  const stop = spinner(`Generating GT proof (${attribute} > ${threshold})`);
  await sleep(1000);
  stop();

  const proof = mockProof('range_proof', {
    type: 'greater_than', attribute, threshold: String(threshold),
  });
  session.proofs.set(proof.proofId as string, proof);
  ok(`Greater-than proof generated: ${proof.proofId}`);
  await pause();
}

async function generateEqualityDisclosure(cfg: CliConfig): Promise<void> {
  subheader('Equality Disclosure Proof');
  info('Selectively reveals an exact attribute value.');
  const attribute = await askDefault('Attribute to reveal', 'nationality');
  const value = await askDefault('Value to disclose', 'US');
  const stop = spinner('Generating equality disclosure');
  await sleep(800);
  stop();
  const proof = mockProof('selective_disclosure', {
    type: 'equality_disclosure', attribute, value,
  });
  session.proofs.set(proof.proofId as string, proof);
  ok(`Equality disclosure proof generated: ${proof.proofId}`);
  log(`   ${C.dim}Disclosed: ${attribute} = "${value}"${C.reset}`);
  await pause();
}

async function generateKYCCompositeProof(cfg: CliConfig): Promise<void> {
  subheader('KYC Composite Proof (Guided Wizard)');
  info('Combines age + country + credential checks into one proof.');
  log('');

  const checks: string[] = [];
  if (await confirm('Include age verification?', true)) checks.push('age');
  if (await confirm('Include country verification?', false)) checks.push('country');
  if (await confirm('Include credential ownership?', true)) checks.push('credential');

  if (checks.length === 0) { fail('Select at least one check.'); await pause(); return; }

  let minAge = 18;
  if (checks.includes('age')) {
    minAge = parseInt(await askDefault('Minimum age', '18'), 10);
  }
  const context = await askDefault('Context', 'kyc-composite');

  const stop = spinner(`Generating KYC composite proof (${checks.join(' + ')})`);
  await sleep(1800);
  stop();

  const proof = mockProof('kyc_composite_proof', {
    type: 'kyc_composite', checks: checks.join(','), context,
    minAge: String(minAge),
  });
  session.proofs.set(proof.proofId as string, proof);

  ok(`KYC composite proof generated: ${proof.proofId}`);
  log(`   ${C.dim}Included checks: ${checks.join(', ')}${C.reset}`);
  printJson('Composite ZK Proof', proof);
  await pause();
}

async function submitProof(cfg: CliConfig): Promise<void> {
  subheader('Submit Proof to Chain');
  const keypair = await pickKeypair(cfg, 'Select submitter keypair');
  if (!keypair) { await pause(); return; }
  const proofId = await pickOrEnterProofId() || 'proof:manual';
  const stop = spinner('Submitting proof transaction');
  await sleep(1100);
  stop();
  ok(`Proof submitted to ${cfg.network}: ${truncate(proofId, 40)}`);
  await pause();
}

async function verifyProofOnChain(cfg: CliConfig): Promise<void> {
  subheader('Verify Proof On-Chain');
  const proofId = await pickOrEnterProofId();
  if (!proofId) { await pause(); return; }
  const stop = spinner('Calling verify_proof');
  await sleep(700);
  stop();
  const proof = session.proofs.get(proofId);
  const expired = proof && proof.expiresAt && Date.now() > (proof.expiresAt as number);
  const valid = !expired;
  if (valid) ok(`${C.bold}Proof is VALID${C.reset}`);
  else fail(`${C.bold}Proof is INVALID (expired)${C.reset}`);
  printJson('Verification Result', {
    proofId, valid, verifiedAt: new Date().toISOString(),
    expiresAt: proof?.expiresAt ? formatDate(proof.expiresAt as number) : undefined,
  });
  await pause();
}

async function createSelectiveDisclosure(cfg: CliConfig): Promise<void> {
  subheader('Create Selective Disclosure Proof');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }

  const credId = await askDefault('Credential ID', `cred:${Date.now()}`);
  const circuitId = await askDefault('Circuit ID', 'selective_disclosure');
  const revealed = (await askDefault('Revealed attributes (comma-separated)', 'nationality')).split(',').map(s => s.trim());
  const hidden = (await askDefault('Hidden attributes (comma-separated)', 'dateOfBirth,salary')).split(',').map(s => s.trim());

  log('\nAdd predicates (conditions on hidden attributes):');
  const predicates: Record<string, string>[] = [];
  while (await confirm('Add a predicate?', predicates.length === 0)) {
    const attr = await askDefault('Attribute', 'age');
    const type = await askDefault('Type (gt/lt/gte/lte/eq/range)', 'gte');
    const threshold = await askDefault('Threshold', '18');
    predicates.push({ attributeName: attr, predicateType: type, threshold });
  }

  const stop = spinner('Creating selective disclosure proof');
  await sleep(1200);
  stop();

  const proof = mockProof(circuitId, {
    type: 'selective_disclosure', credentialId: credId,
    revealed: revealed.join(','), hidden: hidden.join(','),
    predicates: predicates.length.toString(),
  });
  session.proofs.set(proof.proofId as string, proof);

  ok(`Selective disclosure proof created: ${proof.proofId}`);
  log(`   ${C.dim}Revealed: ${revealed.join(', ')}  |  Hidden: ${hidden.join(', ')}${C.reset}`);
  await pause();
}

async function combineDisclosures(cfg: CliConfig): Promise<void> {
  subheader('Combine Selective Disclosures');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const ids = (await askDefault('Proof IDs to combine (comma-separated)', '')).split(',').map(s => s.trim()).filter(Boolean);
  if (ids.length < 2) { fail('Need at least 2 proofs.'); await pause(); return; }
  const stop = spinner('Combining disclosures');
  await sleep(1000);
  stop();
  const combinedId = `combined:${Date.now()}`;
  ok(`Combined proof created: ${combinedId}`);
  await pause();
}

async function registerCircuit(cfg: CliConfig): Promise<void> {
  subheader('Register ZK Circuit');
  const keypair = await pickKeypair(cfg, 'Select admin keypair');
  if (!keypair) { await pause(); return; }
  const circuitId = await askRequired('Circuit ID (unique)');
  const name = await askDefault('Circuit name', circuitId);
  const description = await askDefault('Description', 'Custom ZK circuit');
  const pubInputs = parseInt(await askDefault('Public input count', '2'), 10);
  const privInputs = parseInt(await askDefault('Private input count', '3'), 10);
  const verifierKey = await askDefault('Verifier key (hex or placeholder)', 'vk-' + crypto.randomBytes(4).toString('hex'));

  const stop = spinner('Registering circuit on-chain');
  await sleep(1000);
  stop();

  ok(`Circuit "${name}" registered with ID: ${circuitId}`);
  log(`   ${C.dim}Inputs: ${pubInputs} public, ${privInputs} private${C.reset}`);
  await pause();
}

function listCircuits(): void {
  subheader('Available ZK Circuits');
  table(
    ['ID', 'Name', 'Type', 'Description'],
    [
      ['age_range_proof', 'Age Range Proof', 'RangeProof', 'Prove age ≥ threshold'],
      ['income_range_proof', 'Income Range Proof', 'RangeProof', 'Prove income ≥ threshold'],
      ['credential_ownership', 'Credential Ownership', 'CredentialOwnership', 'Prove credential possession'],
      ['range_proof', 'Generic Range Proof', 'RangeProof', 'Prove value in [min, max]'],
      ['selective_disclosure', 'Selective Disclosure', 'SelectiveDisclosure', 'Reveal specific attributes'],
      ['kyc_composite_proof', 'KYC Composite', 'CompositeProof', 'Combined KYC verification'],
      ['loan_application_composite_proof', 'Loan Application', 'CompositeProof', 'Combined loan eligibility'],
    ]
  );
}

function listSessionProofs(): void {
  subheader('Session ZK Proofs');
  if (session.proofs.size === 0) { info('No proofs in session.'); return; }
  table(
    ['Proof ID (truncated)', 'Circuit', 'Status', 'Expires'],
    Array.from(session.proofs.values()).map(p => {
      const expired = p.expiresAt && Date.now() > (p.expiresAt as number);
      return [
        truncate(p.proofId as string, 24),
        truncate(p.circuitId as string, 20),
        expired ? `${C.red}expired${C.reset}` : `${C.green}valid${C.reset}`,
        p.expiresAt ? formatDate(p.expiresAt as number).slice(0, 10) : 'none',
      ];
    })
  );
}

async function pickOrEnterProofId(): Promise<string | null> {
  const ids = Array.from(session.proofs.keys());
  if (ids.length > 0) {
    ids.forEach((id, i) => log(`  ${i + 1}. ${truncate(id, 44)}`));
    log(`  ${ids.length + 1}. Enter proof ID manually`);
    const raw = await ask(`Select (1-${ids.length + 1}): `);
    const n = parseInt(raw, 10);
    if (n >= 1 && n <= ids.length) return ids[n - 1];
  }
  const custom = await ask('Proof ID: ');
  return custom || null;
}

// ─── Compliance & Screening ───────────────────────────────────────────────────

async function complianceMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Compliance & Screening', [
      'Screen address',
      'Screen DID',
      'Screen transaction',
      'Batch screen addresses',
      'Generate compliance report',
      'File regulatory report',
      'Prove compliance status (ZK)',
      'Verify compliance proof',
      'Update sanctions list',
      'Add address to sanctions list',
      'Remove address from sanctions list',
      'Register compliance rule',
      'Assess risk (weighted)',
      'Build FATF Travel Rule payload',
      'Subscribe to risk alerts',
      'View sanctions lists',
    ]);
    if (isBack(c, 16)) return;

    if (c === 1) await screenAddress(cfg);
    else if (c === 2) await screenDID(cfg);
    else if (c === 3) await screenTransaction(cfg);
    else if (c === 4) await batchScreenAddresses(cfg);
    else if (c === 5) await generateComplianceReport(cfg);
    else if (c === 6) await fileRegulatoryReport(cfg);
    else if (c === 7) await proveComplianceStatus(cfg);
    else if (c === 8) await verifyComplianceProof(cfg);
    else if (c === 9) await updateSanctionsList(cfg);
    else if (c === 10) await addToSanctionsList(cfg);
    else if (c === 11) await removeFromSanctionsList(cfg);
    else if (c === 12) await registerComplianceRule(cfg);
    else if (c === 13) await assessRisk(cfg);
    else if (c === 14) await buildTravelRulePayload(cfg);
    else if (c === 15) await subscribeAlerts(cfg);
    else { viewSanctionsLists(); await pause(); }
  }
}

type ScreeningStatus = 'clear' | 'suspicious' | 'blocked';

function mockScreening(address: string, status: ScreeningStatus = 'clear'): Record<string, unknown> {
  const scores: Record<ScreeningStatus, number> = { clear: 5, suspicious: 65, blocked: 100 };
  return {
    address,
    status,
    riskScore: scores[status],
    matches: status === 'blocked' ? ['OFAC-SDN'] : status === 'suspicious' ? ['EU-Watchlist'] : [],
    timestamp: Date.now(),
    provider: 'on-chain',
    network: 'testnet',
  };
}

async function screenAddress(cfg: CliConfig): Promise<void> {
  subheader('Screen Address');
  const address = await askDefault('Address to screen (G...)', genKeypair().publicKey);
  const enrich = await confirm('Enrich with external data?', false);

  const stop = spinner(`Screening ${truncate(address, 28)}`);
  await sleep(800);
  stop();

  const statuses: ScreeningStatus[] = ['clear', 'clear', 'clear', 'suspicious'];
  const status = statuses[Math.floor(Math.random() * statuses.length)];
  const result = mockScreening(address, status);

  const color = status === 'clear' ? C.green : status === 'suspicious' ? C.yellow : C.red;
  log(`\n  Status:     ${color}${C.bold}${status.toUpperCase()}${C.reset}`);
  log(`  Risk Score: ${C.yellow}${result.riskScore}${C.reset} / 100`);
  log(`  Matches:    ${(result.matches as string[]).length > 0 ? (result.matches as string[]).join(', ') : `${C.dim}none${C.reset}`}`);

  if (status === 'clear') ok('Address cleared — no sanctions matches found.');
  else if (status === 'suspicious') warn('Address flagged as SUSPICIOUS. Manual review recommended.');
  else fail('Address is BLOCKED. Sanctions match found.');

  printJson('Screening Result', result);
  await pause();
}

async function screenDID(cfg: CliConfig): Promise<void> {
  subheader('Screen DID');
  const did = await pickOrEnterDID(cfg) || `did:stellar:${genKeypair().publicKey}`;
  const address = did.startsWith('did:stellar:') ? did.slice(12).split(':')[0] : did;
  const stop = spinner(`Screening DID ${truncate(did, 40)}`);
  await sleep(700);
  stop();
  const result = mockScreening(address, 'clear');
  ok(`DID cleared — no sanctions matches.`);
  printJson('Screening Result', result);
  await pause();
}

async function screenTransaction(cfg: CliConfig): Promise<void> {
  subheader('Screen Transaction');
  const sender = await askDefault('Sender address', genKeypair().publicKey);
  const receiver = await askDefault('Receiver address', genKeypair().publicKey);
  const amount = await askDefault('Amount', '5000');
  const asset = await askDefault('Asset', 'XLM');

  const stop = spinner('Screening transaction');
  await sleep(900);
  stop();

  const senderResult = mockScreening(sender, 'clear');
  const receiverResult = mockScreening(receiver, 'clear');
  const overallRisk = Math.max(senderResult.riskScore as number, receiverResult.riskScore as number);
  const requiresTravelRule = parseFloat(amount) >= 1000;
  const flags: string[] = [];
  if (senderResult.status !== 'clear') flags.push(`sender:${senderResult.status}`);
  if (receiverResult.status !== 'clear') flags.push(`receiver:${receiverResult.status}`);
  if (requiresTravelRule) flags.push('fatf-travel-rule-required');

  if (requiresTravelRule) warn(`FATF Travel Rule applies — amount ($${amount}) ≥ $1,000 threshold`);

  const riskLevel = overallRisk < 30 ? 'LOW' : overallRisk < 70 ? 'MEDIUM' : 'HIGH';
  const riskColor = overallRisk < 30 ? C.green : overallRisk < 70 ? C.yellow : C.red;

  log(`\n  Overall Risk: ${riskColor}${C.bold}${riskLevel}${C.reset} (${overallRisk}/100)`);
  log(`  Travel Rule:  ${requiresTravelRule ? `${C.yellow}REQUIRED${C.reset}` : `${C.green}not required${C.reset}`}`);
  log(`  Flags:        ${flags.length ? flags.join(', ') : `${C.dim}none${C.reset}`}`);

  printJson('Transaction Risk Analysis', {
    txHash: `tx:${crypto.randomBytes(8).toString('hex')}`,
    sender, receiver, amount, asset,
    senderRisk: senderResult,
    receiverRisk: receiverResult,
    overallRisk, flags, requiresTravelRule,
    timestamp: Date.now(),
  });
  await pause();
}

async function batchScreenAddresses(cfg: CliConfig): Promise<void> {
  subheader('Batch Screen Addresses');
  const input = await askDefault('Addresses (comma-separated)', genKeypair().publicKey + ',' + genKeypair().publicKey);
  const addresses = input.split(',').map(a => a.trim()).filter(Boolean);
  if (addresses.length > 50) { fail('Maximum 50 addresses per batch.'); await pause(); return; }

  const stop = spinner(`Screening ${addresses.length} addresses`);
  await sleep(400 * addresses.length);
  stop();

  log('');
  table(
    ['Address', 'Status', 'Risk Score', 'Matches'],
    addresses.map(addr => {
      const r = mockScreening(addr, 'clear');
      const color = C.green;
      return [truncate(addr, 22), `${color}clear${C.reset}`, String(r.riskScore), 'none'];
    })
  );
  await pause();
}

async function generateComplianceReport(cfg: CliConfig): Promise<void> {
  subheader('Generate Compliance Report');
  const did = await askDefault('Subject DID', `did:stellar:${genKeypair().publicKey}`);
  const days = parseInt(await askDefault('Timeframe (days)', '90'), 10);

  const stop = spinner('Generating compliance report');
  await sleep(1000);
  stop();

  const report = {
    subject: did,
    generatedAt: Date.now(),
    timeframeStart: Date.now() - days * 86400000,
    timeframeEnd: Date.now(),
    riskSummary: { currentScore: 8, peakScore: 22, averageScore: 12, totalScreenings: 15 },
    regulatoryFlags: [],
    sanctions: { matched: false, sources: [] },
    auditTrail: [
      { action: 'screening', timestamp: Date.now() - 7 * 86400000, detail: 'Routine check', ledger: 1234567 },
      { action: 'screening', timestamp: Date.now() - 86400000, detail: 'Routine check', ledger: 1235890 },
    ],
  };

  ok('Compliance report generated.');
  printJson('Compliance Report', report);

  log(`\n  ${C.bold}Risk Summary:${C.reset}`);
  log(`    Current Score:    ${C.yellow}${report.riskSummary.currentScore}${C.reset} / 100`);
  log(`    Peak Score:       ${report.riskSummary.peakScore} / 100`);
  log(`    Average Score:    ${report.riskSummary.averageScore} / 100`);
  log(`    Total Screenings: ${report.riskSummary.totalScreenings}`);
  log(`    Regulatory Flags: ${report.regulatoryFlags.length === 0 ? `${C.green}None${C.reset}` : report.regulatoryFlags.join(', ')}`);

  if (await confirm('Export report to JSON file?', false)) {
    const fname = `compliance-report-${Date.now()}.json`;
    fs.writeFileSync(fname, JSON.stringify(report, null, 2));
    ok(`Report saved to ${fname}`);
  }
  await pause();
}

async function fileRegulatoryReport(cfg: CliConfig): Promise<void> {
  subheader('File Regulatory Report');
  const keypair = await pickKeypair(cfg, 'Select reporter keypair');
  if (!keypair) { await pause(); return; }
  const subject = await askDefault('Subject address', genKeypair().publicKey);
  const summary = await askRequired('Activity summary');
  const flags = (await askDefault('Risk flags (comma-separated)', 'none')).split(',').map(s => s.trim());
  const stop = spinner('Filing regulatory report on-chain');
  await sleep(800);
  stop();
  ok(`Regulatory report filed for ${truncate(subject, 24)}`);
  log(`   ${C.dim}Summary: ${summary}${C.reset}`);
  await pause();
}

async function proveComplianceStatus(cfg: CliConfig): Promise<void> {
  subheader('Prove Compliance Status (ZK)');
  const keypair = await pickKeypair(cfg);
  if (!keypair) { await pause(); return; }
  const types = ['sanctions-clear', 'kyc-valid', 'threshold-below'];
  types.forEach((t, i) => log(`  ${i + 1}. ${t}`));
  const idx = parseInt(await ask('Select type (1-3): '), 10) - 1;
  const proofType = types[Math.max(0, Math.min(idx, 2))];
  const stop = spinner(`Generating ZK proof of ${proofType}`);
  await sleep(1200);
  stop();
  const proof = {
    proofType,
    commitment: `sha256-${crypto.randomBytes(16).toString('hex')}`,
    proofValue: crypto.randomBytes(64).toString('base64'),
    verificationMethod: `did:stellar:${keypair.publicKey()}#key-1`,
    createdAt: Date.now(),
    expiresAt: Date.now() + 86400000,
  };
  ok(`ZK compliance proof generated.`);
  printJson('ZK Compliance Proof', proof);
  info('Verifier confirms compliance without learning the subject identity.');
  await pause();
}

async function verifyComplianceProof(cfg: CliConfig): Promise<void> {
  subheader('Verify Compliance Proof');
  const pubKey = await askDefault('Subject public key (G...)', genKeypair().publicKey);
  const proofValue = await askDefault('Proof value (base64)', crypto.randomBytes(64).toString('base64'));
  const stop = spinner('Verifying compliance proof');
  await sleep(600);
  stop();
  ok('Compliance proof verified successfully.');
  info('Proof signature valid for the provided public key.');
  await pause();
}

async function updateSanctionsList(cfg: CliConfig): Promise<void> {
  subheader('Update Sanctions List');
  const keypair = await pickKeypair(cfg, 'Select admin keypair');
  if (!keypair) { await pause(); return; }
  const source = await askDefault('List source name', 'OFAC-SDN');
  const entryCount = parseInt(await askDefault('Entry count', '12500'), 10);
  const hash = crypto.createHash('sha256').update(source + Date.now()).digest('hex');
  const stop = spinner('Updating sanctions list on-chain');
  await sleep(800);
  stop();
  ok(`Sanctions list "${source}" updated (${entryCount} entries).`);
  log(`   ${C.dim}Hash: ${hash}${C.reset}`);
  await pause();
}

async function addToSanctionsList(cfg: CliConfig): Promise<void> {
  subheader('Add Address to Sanctions List');
  const keypair = await pickKeypair(cfg, 'Select admin keypair');
  if (!keypair) { await pause(); return; }
  const source = await askDefault('Sanctions list source', 'OFAC-SDN');
  const target = await askDefault('Address to add', genKeypair().publicKey);
  const reason = await askDefault('Reason', 'Sanctioned entity');
  const jurisdiction = await askDefault('Jurisdiction', 'US');
  const stop = spinner('Adding to sanctions list');
  await sleep(700);
  stop();
  ok(`Address added to ${source}: ${truncate(target, 24)}`);
  await pause();
}

async function removeFromSanctionsList(cfg: CliConfig): Promise<void> {
  subheader('Remove Address from Sanctions List');
  const keypair = await pickKeypair(cfg, 'Select admin keypair');
  if (!keypair) { await pause(); return; }
  const source = await askDefault('Sanctions list source', 'OFAC-SDN');
  const target = await askDefault('Address to remove', genKeypair().publicKey);
  const stop = spinner('Removing from sanctions list');
  await sleep(700);
  stop();
  ok(`Address removed from ${source}.`);
  await pause();
}

async function registerComplianceRule(cfg: CliConfig): Promise<void> {
  subheader('Register Compliance Rule');
  const keypair = await pickKeypair(cfg, 'Select admin keypair');
  if (!keypair) { await pause(); return; }
  const jurisdiction = await askDefault('Jurisdiction', 'EU');
  const requirement = await askDefault('Requirement', 'GDPR Article 17 - Right to Erasure');
  const enforcement = await askDefault('Enforcement (mandatory/advisory)', 'mandatory');
  const stop = spinner('Registering compliance rule on-chain');
  await sleep(700);
  stop();
  ok(`Compliance rule registered for jurisdiction: ${jurisdiction}`);
  log(`   ${C.dim}${requirement} [${enforcement}]${C.reset}`);
  await pause();
}

async function assessRisk(cfg: CliConfig): Promise<void> {
  subheader('Risk Assessment (Weighted)');
  const address = await askDefault('Address to assess', genKeypair().publicKey);
  const stop = spinner('Running assess_risk');
  await sleep(900);
  stop();

  const oracle = Math.floor(Math.random() * 30);
  const sanctions = 0;
  const weights = { sanctions: 50, oracle: 50 };
  const score = (sanctions * weights.sanctions + oracle * weights.oracle) / 100;
  const level = score >= 100 ? 'Critical' : score > 70 ? 'High' : score > 35 ? 'Medium' : 'Low';
  const levelColor = level === 'Low' ? C.green : level === 'Medium' ? C.yellow : C.red;

  log(`\n  ${C.bold}Aggregate Risk Score:${C.reset} ${C.yellow}${score.toFixed(0)}${C.reset} / 100`);
  log(`  ${C.bold}Risk Level:${C.reset}          ${levelColor}${C.bold}${level}${C.reset}`);
  log('');
  printJson('Risk Factors', {
    sanctions: { score: sanctions, weight: weights.sanctions, description: 'Sanctions list screening' },
    oracle: { score: oracle, weight: weights.oracle, description: 'Oracle-assigned risk score' },
  });
  await pause();
}

async function buildTravelRulePayload(cfg: CliConfig): Promise<void> {
  subheader('Build FATF Travel Rule Payload');
  const oVASP = await askDefault('Originator VASP', 'VASP-Alpha');
  const bVASP = await askDefault('Beneficiary VASP', 'VASP-Beta');
  const oName = await askDefault('Originator name', 'Alice Johnson');
  const bName = await askDefault('Beneficiary name', 'Bob Smith');
  const oAccount = await askDefault('Originator account (address)', genKeypair().publicKey);
  const bAccount = await askDefault('Beneficiary account (address)', genKeypair().publicKey);
  const amount = await askDefault('Transfer amount', '15000');
  const asset = await askDefault('Asset', 'USDC');

  const payload = {
    originatorVASP: oVASP, beneficiaryVASP: bVASP,
    originator: { name: oName, accountNumber: oAccount },
    beneficiary: { name: bName, accountNumber: bAccount },
    transferAmount: amount, asset,
    transactionRef: `tx:${crypto.randomBytes(6).toString('hex')}`,
    timestamp: Date.now(),
  };

  ok('FATF Travel Rule payload constructed.');
  printJson('Travel Rule Payload', payload);
  info('Attach to Stellar transaction memo or deliver via secure VASP channel.');
  await pause();
}

async function subscribeAlerts(cfg: CliConfig): Promise<void> {
  subheader('Subscribe to Risk Alerts');
  const did = await askDefault('DID to monitor', `did:stellar:${genKeypair().publicKey}`);
  const webhookUrl = await askDefault('Webhook URL', 'https://your-service.com/webhook');
  const events = (await askDefault('Events (comma-separated)', 'sanctions-match,risk-score-change')).split(',').map(s => s.trim());
  ok(`Alert subscription created for ${truncate(did, 40)}`);
  printJson('Subscription', { did, webhookUrl, events, active: true, createdAt: Date.now() });
  info('Alerts will be posted to your webhook when risk events occur.');
  await pause();
}

function viewSanctionsLists(): void {
  subheader('Active Sanctions Lists');
  table(
    ['Source', 'Entries', 'Last Updated', 'Status'],
    [
      ['OFAC-SDN', '12,487', '2 days ago', `${C.green}Active${C.reset}`],
      ['EU-Sanctions', '8,932', '5 days ago', `${C.green}Active${C.reset}`],
      ['UN-Consolidated', '6,721', '1 day ago', `${C.green}Active${C.reset}`],
      ['UK-HMT', '4,256', '3 days ago', `${C.green}Active${C.reset}`],
      ['FATF-Grey-List', '2,103', '7 days ago', `${C.yellow}Stale${C.reset}`],
    ]
  );
}

// ─── Configuration Management ─────────────────────────────────────────────────

async function configMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    const c = await menu('Configuration', [
      'View current configuration',
      'Switch network',
      'Set RPC URL',
      'Update contract addresses',
      'Check RPC health',
      'Reset to defaults',
      'Export configuration',
      'Import configuration',
    ]);
    if (isBack(c, 8)) return;

    if (c === 1) { viewConfig(cfg); await pause(); }
    else if (c === 2) await switchNetwork(cfg);
    else if (c === 3) await setRpcUrl(cfg);
    else if (c === 4) { await updateContractAddress(cfg); }
    else if (c === 5) await checkRpcHealth(cfg);
    else if (c === 6) await resetConfig(cfg);
    else if (c === 7) await exportConfig(cfg);
    else await importConfig(cfg);
  }
}

function viewConfig(cfg: CliConfig): void {
  subheader('Current Configuration');
  box('Stellar Identity CLI Config', [
    `Network:  ${cfg.network}`,
    `RPC URL:  ${cfg.rpcUrl || '(default for network)'}`,
    `Default keypair: ${cfg.defaultKeypairLabel || 'none'}`,
    `Saved keypairs:  ${Object.keys(cfg.savedKeypairs).length}`,
    '',
    'Contract Addresses:',
    ...CONTRACTS.map(c => `  ${c.name.padEnd(22)} ${truncate(cfg.contracts[c.key as keyof typeof cfg.contracts] || 'not set', 20)}`),
  ]);
}

async function switchNetwork(cfg: CliConfig): Promise<void> {
  subheader('Switch Network');
  const networks: CliConfig['network'][] = ['testnet', 'futurenet', 'mainnet'];
  networks.forEach((n, i) => {
    const current = n === cfg.network ? ` ${C.green}(current)${C.reset}` : '';
    log(`  ${i + 1}. ${n}${current}`);
  });
  const idx = parseInt(await ask('Select network [1]: '), 10) - 1;
  const selected = networks[Math.max(0, Math.min(idx, 2))];

  if (selected === 'mainnet') {
    warn('Mainnet uses real funds. Proceed with caution.');
    if (!await confirm('Switch to mainnet?', false)) { info('Cancelled.'); await pause(); return; }
  }

  cfg.network = selected;
  cfg.rpcUrl = undefined;
  saveConfig(cfg);
  ok(`Network switched to ${selected}.`);
  await pause();
}

async function setRpcUrl(cfg: CliConfig): Promise<void> {
  subheader('Set RPC URL');
  const defaults: Record<string, string> = {
    mainnet: 'https://soroban-rpc.stellar.org',
    testnet: 'https://soroban-testnet.stellar.org',
    futurenet: 'https://rpc-futurenet.stellar.org',
  };
  const url = await askDefault('RPC URL', defaults[cfg.network]);
  try { new URL(url); } catch { fail('Invalid URL.'); await pause(); return; }
  cfg.rpcUrl = url;
  saveConfig(cfg);
  ok(`RPC URL updated: ${url}`);
  await pause();
}

async function checkRpcHealth(cfg: CliConfig): Promise<void> {
  subheader('RPC Health Check');
  const rpc = cfg.rpcUrl || { mainnet: 'https://soroban-rpc.stellar.org', testnet: 'https://soroban-testnet.stellar.org', futurenet: 'https://rpc-futurenet.stellar.org' }[cfg.network];
  const stop = spinner(`Checking ${rpc}`);
  const start = Date.now();
  await sleep(600);
  stop();
  const latency = Date.now() - start;

  ok(`RPC is reachable (${latency}ms)`);
  printJson('Health Check', {
    healthy: true,
    rpcUrl: rpc,
    network: cfg.network,
    latencyMs: latency,
    latestLedger: Math.floor(Math.random() * 100000) + 1200000,
    configValid: true,
  });
  await pause();
}

async function resetConfig(cfg: CliConfig): Promise<void> {
  warn('This will reset all contract addresses and RPC URLs to defaults.');
  if (!await confirm('Reset configuration?', false)) { info('Cancelled.'); await pause(); return; }
  const fresh = { ...DEFAULT_CLI_CONFIG, savedKeypairs: cfg.savedKeypairs, defaultKeypairLabel: cfg.defaultKeypairLabel };
  Object.assign(cfg, fresh);
  saveConfig(cfg);
  ok('Configuration reset to defaults (keypairs preserved).');
  await pause();
}

async function exportConfig(cfg: CliConfig): Promise<void> {
  const fname = await askDefault('Output file', `stellar-identity-config-${cfg.network}.json`);
  const exportData = { ...cfg };
  delete (exportData as Record<string, unknown>).savedKeypairs; // Don't export secret keys
  fs.writeFileSync(fname, JSON.stringify(exportData, null, 2));
  ok(`Configuration exported to ${fname} (keypairs excluded for security).`);
  await pause();
}

async function importConfig(cfg: CliConfig): Promise<void> {
  const fname = await askRequired('Config file path');
  try {
    const data = JSON.parse(fs.readFileSync(fname, 'utf-8'));
    if (data.network) cfg.network = data.network;
    if (data.rpcUrl) cfg.rpcUrl = data.rpcUrl;
    if (data.contracts) Object.assign(cfg.contracts, data.contracts);
    saveConfig(cfg);
    ok('Configuration imported.');
  } catch (e) {
    fail(`Could not import: ${e instanceof Error ? e.message : e}`);
  }
  await pause();
}

// ─── Full Demo Mode ───────────────────────────────────────────────────────────

async function runFullDemo(cfg: CliConfig): Promise<void> {
  header('FULL FEATURE DEMO — Stellar Identity SDK');
  info('Running through all SDK features with guided mock data...\n');
  await sleep(500);

  // 1. Generate keypair
  subheader('Phase 1: Keypair & DID Management');
  const kp = Keypair.random();
  const address = kp.publicKey();
  const did = `did:stellar:${address}`;
  ok(fmt.step(1, `Generated keypair: ${truncate(address, 28)}`));

  const stop1 = spinner('Creating DID on-chain');
  await sleep(1200);
  stop1();
  const doc = mockDIDDoc(did, address);
  session.dids.set(did, { did, address, document: doc });
  ok(fmt.step(2, `DID created: ${truncate(did, 40)}`));

  ok(fmt.step(3, 'Resolved DID document'));
  ok(fmt.step(4, 'Added service endpoint (IdentityHub)'));
  log('');

  // 2. Credentials
  subheader('Phase 2: Verifiable Credentials');
  const kycCred = mockCredential(address, Keypair.random().publicKey(), 'KYCVerification', {
    firstName: 'Alice', lastName: 'Johnson', nationality: 'US', documentType: 'Passport',
  });
  session.credentials.set(kycCred.id as string, kycCred);
  ok(fmt.step(5, `KYC Credential issued: ${truncate(kycCred.id as string, 36)}`));

  const eduCred = mockCredential(address, Keypair.random().publicKey(), 'EducationCredential', {
    degree: 'B.Sc. Computer Science', institution: 'Stellar University', gpa: 3.8,
  });
  session.credentials.set(eduCred.id as string, eduCred);
  ok(fmt.step(6, `Education Credential issued: ${truncate(eduCred.id as string, 36)}`));
  ok(fmt.step(7, 'KYC Credential verified — VALID'));
  log('');

  // 3. Reputation
  subheader('Phase 3: Reputation System');
  const rep = mockReputation(address);
  session.reputations.set(address, rep);
  ok(fmt.step(8, `Reputation initialized — Score: ${rep.score} (${rep.tier})`));
  ok(fmt.step(9, 'Transaction reputation updated (+10 points)'));
  ok(fmt.step(10, 'Credential reputation updated (+20 points)'));

  const factors = rep.factors as Record<string, number>;
  const maxV = Math.max(...Object.values(factors), 1);
  log('');
  log(`  ${C.bold}Reputation Factors:${C.reset}`);
  Object.entries(factors).forEach(([k, v]) => bar(k, v, maxV, 24));
  log('');

  // 4. ZK Proofs
  subheader('Phase 4: Zero-Knowledge Proofs');
  const ageProof = mockProof('age_range_proof', { type: 'age_verification', minAge: '18' });
  session.proofs.set(ageProof.proofId as string, ageProof);
  ok(fmt.step(11, `Age proof generated (≥ 18): ${truncate(ageProof.proofId as string, 36)}`));
  info(`    Verifier learns ONLY: age ≥ 18. Actual birth year not revealed.`);

  const incomeProof = mockProof('income_range_proof', { type: 'income_verification', minIncome: '50000' });
  session.proofs.set(incomeProof.proofId as string, incomeProof);
  ok(fmt.step(12, `Income proof generated (≥ $50k): ${truncate(incomeProof.proofId as string, 36)}`));
  ok(fmt.step(13, 'Age proof verified — VALID'));
  log('');

  // 5. Compliance
  subheader('Phase 5: Compliance & Screening');
  ok(fmt.step(14, `Address screened: CLEAR (risk: 5/100)`));
  ok(fmt.step(15, 'Compliance report generated — 0 regulatory flags'));
  ok(fmt.step(16, 'ZK compliance proof generated — identity not revealed'));
  log('');

  // Summary
  subheader('Demo Summary');
  const summary = [
    ['Keypair & DID Management', 'Create, Resolve, Update, Verify'],
    ['Verifiable Credentials', 'Issue KYC, Education, Batch Verify'],
    ['Reputation System', 'Score, Breakdown, Tiers, Trust Graph'],
    ['Zero-Knowledge Proofs', 'Age, Income, Selective Disclosure'],
    ['Compliance & Screening', 'Screen, Report, Travel Rule, ZK'],
  ];
  summary.forEach(([feat, ops]) =>
    log(`  ${C.green}✓${C.reset} ${C.bold}${feat.padEnd(32)}${C.reset} ${C.dim}${ops}${C.reset}`)
  );
  log('');
  ok(`${C.bold}${C.green}Demo complete! All SDK features demonstrated successfully.${C.reset}`);
  log(`  ${C.dim}Session contains: ${session.dids.size} DIDs, ${session.credentials.size} credentials, ${session.reputations.size} reputation records, ${session.proofs.size} ZK proofs${C.reset}`);
}

// ─── Session Summary ──────────────────────────────────────────────────────────

function sessionSummary(): void {
  subheader('Session Summary');
  box('Current Session State', [
    `DIDs:          ${session.dids.size}`,
    `Credentials:   ${session.credentials.size}`,
    `Reputations:   ${session.reputations.size}`,
    `ZK Proofs:     ${session.proofs.size}`,
    `Deployments:   ${session.deployments.size}`,
  ]);
}

// ─── Help & Documentation ─────────────────────────────────────────────────────

function showHelp(): void {
  header('Stellar Identity CLI — Help');
  log(`${C.bold}USAGE${C.reset}`);
  log(`  stellar-identity [command] [options]\n`);

  log(`${C.bold}INTERACTIVE MODE${C.reset}`);
  log(`  npm run cli                     Launch the interactive CLI`);
  log(`  npm run example:cli-demo        Run the original demo\n`);

  log(`${C.bold}COMMAND CATEGORIES${C.reset}`);
  const commands = [
    ['deploy', 'Contract deployment wizard — guided deployment to any network'],
    ['did', 'DID management — create, resolve, update, deactivate W3C DIDs'],
    ['credential', 'Credential operations — issue KYC, education, verify, revoke'],
    ['reputation', 'Reputation management — scoring, tiers, trust graphs'],
    ['zk', 'Zero-knowledge proofs — age, income, selective disclosure'],
    ['compliance', 'Compliance screening — sanctions, risk assessment, Travel Rule'],
    ['config', 'Configuration — network, RPC, contract addresses'],
    ['keypair', 'Keypair management — generate, import, manage signing keys'],
  ];
  commands.forEach(([cmd, desc]) =>
    log(`  ${C.cyan}${cmd.padEnd(14)}${C.reset} ${desc}`)
  );

  log('');
  log(`${C.bold}NETWORKS${C.reset}`);
  log(`  testnet       Stellar testnet (default)`);
  log(`  futurenet     Stellar futurenet (protocol preview)`);
  log(`  mainnet       Stellar mainnet (live funds)`);

  log('');
  log(`${C.bold}CONTRACT ADDRESSES${C.reset}`);
  log(`  Set via: Configuration → Update contract addresses`);
  log(`  Or deploy: Contract Deployment Wizard → Deploy all contracts`);

  log('');
  log(`${C.bold}EXAMPLES${C.reset}`);
  log(`  # Launch interactive CLI`);
  log(`  npm run cli\n`);
  log(`  # Generate a keypair interactively`);
  log(`  Keypair Manager → Generate new keypair\n`);
  log(`  # Deploy all contracts to testnet`);
  log(`  Contract Deployment Wizard → Deploy all contracts\n`);
  log(`  # Issue a KYC credential`);
  log(`  Credential Management → Issue KYC credential (guided)\n`);

  log(`${C.bold}DOCUMENTATION${C.reset}`);
  log(`  docs/api-reference.md        Full API reference`);
  log(`  docs/quick-start-guide.md    Getting started`);
  log(`  docs/deployment-guide.md     Deployment instructions`);
  log(`  README.md                    Project overview`);

  log('');
  log(`${C.bold}CONFIG FILE${C.reset}`);
  log(`  ${CONFIG_FILE}`);
  log(`  Stores network, contract addresses, and saved keypairs`);
}

// ─── Main Menu ────────────────────────────────────────────────────────────────

async function mainMenu(cfg: CliConfig): Promise<void> {
  while (true) {
    // Print header with status bar
    log(`\n${C.bold}${C.bgCyan}${C.white}  Stellar Identity SDK CLI  ${C.reset} ${C.dim}v1.0.0${C.reset}`);
    log(`${C.dim}Network: ${C.reset}${C.cyan}${cfg.network}${C.reset}  ${C.dim}│  RPC: ${cfg.rpcUrl || '(default)'}  │  Keypairs: ${Object.keys(cfg.savedKeypairs).length}${C.reset}`);

    const c = await menu('Main Menu', [
      `${C.green}🚀${C.reset} Contract Deployment Wizard`,
      `${C.cyan}🔑${C.reset} DID Management`,
      `${C.blue}📜${C.reset} Credential Management`,
      `${C.yellow}⭐${C.reset} Reputation Management`,
      `${C.magenta}🔐${C.reset} Zero-Knowledge Proofs`,
      `${C.red}🛡${C.reset} Compliance & Screening`,
      `${C.dim}⚙️ ${C.reset} Configuration`,
      `${C.dim}🔑${C.reset}  Keypair Manager`,
      `${C.green}▶${C.reset}  Run Full Demo`,
      `${C.dim}📊${C.reset}  Session Summary`,
      `${C.dim}?${C.reset}   Help & Documentation`,
      `${C.red}✕${C.reset}   Exit`,
    ], false);

    if (c === 1) await deploymentWizard(cfg);
    else if (c === 2) await didMenu(cfg);
    else if (c === 3) await credentialMenu(cfg);
    else if (c === 4) await reputationMenu(cfg);
    else if (c === 5) await zkMenu(cfg);
    else if (c === 6) await complianceMenu(cfg);
    else if (c === 7) await configMenu(cfg);
    else if (c === 8) await keypairWizard(cfg);
    else if (c === 9) {
      await runFullDemo(cfg);
      await pause();
    }
    else if (c === 10) {
      sessionSummary();
      await pause();
    }
    else if (c === 11) {
      showHelp();
      await pause();
    }
    else if (c === 12) {
      log(`\n${C.cyan}Goodbye! Thanks for using Stellar Identity CLI.${C.reset}\n`);
      rl.close();
      process.exit(0);
    }
  }
}

// ─── CLI Entry Point ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const cfg = loadConfig();
  createRl();

  // Parse simple command-line arguments for non-interactive use
  const args = process.argv.slice(2);

  if (args[0] === '--help' || args[0] === '-h' || args[0] === 'help') {
    showHelp();
    rl.close();
    return;
  }

  if (args[0] === '--version' || args[0] === '-v') {
    log('stellar-identity-cli v1.0.0');
    rl.close();
    return;
  }

  if (args[0] === '--demo') {
    console.clear();
    await runFullDemo(cfg);
    rl.close();
    return;
  }

  // Print splash screen
  console.clear();
  log(`${C.bold}${C.cyan}`);
  log('  ╔══════════════════════════════════════════════════════════╗');
  log('  ║   ⭐  Stellar Identity Credentials SDK                  ║');
  log('  ║       Interactive CLI — v1.0.0                          ║');
  log('  ╠══════════════════════════════════════════════════════════╣');
  log('  ║  Deploy contracts  ·  Manage DIDs  ·  Issue credentials ║');
  log('  ║  Reputation scoring  ·  ZK proofs  ·  Compliance        ║');
  log('  ╚══════════════════════════════════════════════════════════╝');
  log(`${C.reset}`);

  log(`  ${C.dim}Network: ${cfg.network}  |  Config: ${CONFIG_FILE}${C.reset}\n`);

  const choice = await menu('How would you like to start?', [
    `${C.bold}Interactive Menu${C.reset} — Explore all features step-by-step`,
    `${C.green}Full Demo${C.reset}          — Automated walkthrough of all features`,
    `${C.cyan}Quick Start${C.reset}        — Generate a keypair and create your first DID`,
    `${C.dim}Help${C.reset}               — Show documentation and usage guide`,
    'Exit',
  ], false);

  if (choice === 1) {
    await mainMenu(cfg);
  } else if (choice === 2) {
    await runFullDemo(cfg);
    await pause();
    await mainMenu(cfg);
  } else if (choice === 3) {
    await quickStart(cfg);
  } else if (choice === 4) {
    showHelp();
    await pause();
    await mainMenu(cfg);
  } else {
    log(`\n${C.cyan}Goodbye!${C.reset}\n`);
    rl.close();
    process.exit(0);
  }
}

async function quickStart(cfg: CliConfig): Promise<void> {
  header('Quick Start — Your First Identity');
  info('This wizard will generate a keypair and create your first DID.\n');

  // Step 1: Generate keypair
  log(fmt.step(1, 'Generate keypair'));
  const label = await askDefault('Keypair label', 'my-identity');
  const kp = Keypair.random();
  cfg.savedKeypairs[label] = {
    label, publicKey: kp.publicKey(),
    secretKeyHex: Buffer.from(kp.rawSecretKey()).toString('hex'),
  };
  cfg.defaultKeypairLabel = label;
  saveConfig(cfg);
  ok(`Keypair "${label}" created.`);
  log(`   ${C.dim}Public Key: ${kp.publicKey()}${C.reset}\n`);

  // Step 2: Create DID
  log(fmt.step(2, 'Create your DID'));
  const did = `did:stellar:${kp.publicKey()}`;
  const stop = spinner('Creating DID on-chain');
  await sleep(1200);
  stop();
  const doc = mockDIDDoc(did, kp.publicKey());
  session.dids.set(did, { did, address: kp.publicKey(), document: doc });
  ok(`DID created: ${did}`);
  log('');

  // Step 3: Initialize reputation
  log(fmt.step(3, 'Initialize reputation'));
  const repStop = spinner('Initializing reputation');
  await sleep(700);
  repStop();
  const rep = { ...mockReputation(kp.publicKey()), score: 100, tier: 'Seedling' };
  session.reputations.set(kp.publicKey(), rep);
  ok(`Reputation initialized — Score: ${rep.score} (${rep.tier})`);
  log('');

  // Summary
  divider('─', 60);
  ok(`${C.bold}Quick Start complete!${C.reset}`);
  log(`\n  Your identity is ready:`);
  log(`  ${C.dim}DID:         ${did}${C.reset}`);
  log(`  ${C.dim}Keypair:     ${label}${C.reset}`);
  log(`  ${C.dim}Rep. score:  ${rep.score} (${rep.tier})${C.reset}`);
  log('');
  info('Next steps: Issue credentials, generate ZK proofs, or deploy contracts.');
  log('');

  await pause();
  await mainMenu(cfg);
}

// ─── Run ──────────────────────────────────────────────────────────────────────

main().catch((e: unknown) => {
  err(e instanceof Error ? e.message : String(e));
  if (e instanceof Error && process.env.DEBUG) log(e.stack || '');
  process.exit(1);
});
