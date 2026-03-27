/**
 * exchange-compliance.ts
 *
 * Full exchange integration demonstrating:
 *   1. Oracle-driven daily sanctions list update (OFAC, UN, EU)
 *   2. Real-time address screening on deposit/withdrawal
 *   3. Transaction risk analysis with aggregate scoring
 *   4. Automated regulatory report filing (immutable audit trail)
 *   5. Alert subscription for ongoing monitoring
 *   6. ZK proof of sanctions-clear status for privacy-preserving KYC
 *   7. Compliance rule registration (MiCA, FATF)
 */

import { Keypair } from 'stellar-sdk';
import { ComplianceClient, TravelRulePayload } from '../sdk/src/compliance';
import { StellarIdentityConfig } from '../sdk/src/types';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const config: StellarIdentityConfig = {
  network: 'testnet',
  contracts: {
    didRegistry:      process.env.DID_REGISTRY_CONTRACT      ?? 'PLACEHOLDER_DID_REGISTRY',
    credentialIssuer: process.env.CREDENTIAL_ISSUER_CONTRACT ?? 'PLACEHOLDER_CREDENTIAL_ISSUER',
    reputationScore:  process.env.REPUTATION_SCORE_CONTRACT  ?? 'PLACEHOLDER_REPUTATION_SCORE',
    zkAttestation:    process.env.ZK_ATTESTATION_CONTRACT    ?? 'PLACEHOLDER_ZK_ATTESTATION',
    complianceFilter: process.env.COMPLIANCE_FILTER_CONTRACT ?? 'PLACEHOLDER_COMPLIANCE_FILTER',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

// Exchange compliance officer — authorized oracle
const oracleKeypair = Keypair.fromSecret(
  process.env.ORACLE_SECRET ?? Keypair.random().secret(),
);

// Exchange hot wallet
const exchangeKeypair = Keypair.fromSecret(
  process.env.EXCHANGE_SECRET ?? Keypair.random().secret(),
);

// Customer depositing funds
const customerKeypair = Keypair.fromSecret(
  process.env.CUSTOMER_SECRET ?? Keypair.random().secret(),
);

const client = new ComplianceClient(config);

// ---------------------------------------------------------------------------
// Step 1 — Daily oracle-driven sanctions list update
// ---------------------------------------------------------------------------

async function updateSanctionsLists(): Promise<void> {
  console.log('\n[1] Updating sanctions lists via oracle...');

  // In production these hashes come from Band Protocol / DIA oracle feeds
  const lists = [
    {
      source: 'OFAC_SDN',
      hash: 'a'.repeat(64),   // placeholder SHA-256 hex
      entryCount: 12_847,
    },
    {
      source: 'UN_CONSOLIDATED',
      hash: 'b'.repeat(64),
      entryCount: 3_421,
    },
    {
      source: 'EU_FINANCIAL',
      hash: 'c'.repeat(64),
      entryCount: 2_109,
    },
  ];

  for (const list of lists) {
    await client.updateSanctionsList(oracleKeypair, list.source, list.hash, list.entryCount);
    console.log(`   Updated ${list.source}: ${list.entryCount} entries, hash=${list.hash.slice(0, 8)}...`);
  }
}

// ---------------------------------------------------------------------------
// Step 2 — Register compliance rules (MiCA, FATF)
// ---------------------------------------------------------------------------

async function registerComplianceRules(): Promise<void> {
  console.log('\n[2] Registering compliance rules...');

  const rules = [
    {
      jurisdiction: 'MiCA',
      requirement: JSON.stringify({
        description: 'EU MiCA — CASP must screen all transactions',
        threshold: 1000,
        currency: 'EUR',
      }),
      enforcement: 'mandatory' as const,
    },
    {
      jurisdiction: 'FATF',
      requirement: JSON.stringify({
        description: 'FATF Travel Rule — share originator/beneficiary info ≥ 1000 USD',
        threshold: 1000,
        currency: 'USD',
      }),
      enforcement: 'mandatory' as const,
    },
    {
      jurisdiction: 'GDPR',
      requirement: JSON.stringify({
        description: 'Right to erasure — off-chain PII must be deletable',
        dataRetentionDays: 365,
      }),
      enforcement: 'mandatory' as const,
    },
    {
      jurisdiction: 'CCPA',
      requirement: JSON.stringify({
        description: 'California privacy rights — opt-out of data sale',
      }),
      enforcement: 'advisory' as const,
    },
  ];

  for (const rule of rules) {
    await client.registerComplianceRule(
      oracleKeypair,
      rule.jurisdiction,
      rule.requirement,
      rule.enforcement,
    );
    console.log(`   Registered ${rule.jurisdiction} (${rule.enforcement})`);
  }
}

// ---------------------------------------------------------------------------
// Step 3 — Real-time address screening on deposit
// ---------------------------------------------------------------------------

async function screenDeposit(): Promise<void> {
  console.log('\n[3] Screening customer deposit address...');

  const customerAddress = customerKeypair.publicKey();
  const result = await client.screenAddress(customerAddress, { enrichWithExternal: false });

  console.log(`   Address:    ${customerAddress.slice(0, 12)}...`);
  console.log(`   Status:     ${result.status}`);
  console.log(`   Risk score: ${result.riskScore}/100`);
  console.log(`   Matches:    ${result.matches.length > 0 ? result.matches.join(', ') : 'none'}`);

  if (result.status === 'blocked') {
    console.log('   ⛔ Deposit REJECTED — address on sanctions list');
    return;
  }
  if (result.status === 'suspicious') {
    console.log('   ⚠️  Deposit FLAGGED — manual review required');
    return;
  }
  console.log('   ✅ Deposit APPROVED');
}

// ---------------------------------------------------------------------------
// Step 4 — Transaction risk analysis
// ---------------------------------------------------------------------------

async function analyzeTransaction(): Promise<void> {
  console.log('\n[4] Analyzing transaction risk...');

  const txRisk = await client.screenTransaction({
    hash: 'abc123def456',
    sender: customerKeypair.publicKey(),
    receiver: exchangeKeypair.publicKey(),
    amount: '5000',
    asset: 'USDC',
  });

  console.log(`   Tx hash:          ${txRisk.txHash}`);
  console.log(`   Overall risk:     ${txRisk.overallRisk}/100`);
  console.log(`   Sender status:    ${txRisk.senderRisk.status}`);
  console.log(`   Receiver status:  ${txRisk.receiverRisk.status}`);
  console.log(`   Travel Rule req:  ${txRisk.requiresTravelRule}`);
  console.log(`   Flags:            ${txRisk.flags.length > 0 ? txRisk.flags.join(', ') : 'none'}`);
}

// ---------------------------------------------------------------------------
// Step 5 — File immutable regulatory report
// ---------------------------------------------------------------------------

async function fileReport(): Promise<void> {
  console.log('\n[5] Filing regulatory report (immutable audit trail)...');

  const reportKey = await client.fileRegulatoryReport(
    oracleKeypair,
    customerKeypair.publicKey(),
    'Customer deposit screening — automated daily check',
    ['OFAC_SCREENED', 'UN_SCREENED', 'EU_SCREENED'],
  );

  console.log(`   Report key: ${reportKey}`);

  // Generate full compliance report
  const report = await client.generateComplianceReport(
    `did:stellar:${customerKeypair.publicKey()}`,
    { start: Date.now() - 30 * 24 * 60 * 60 * 1000, end: Date.now() },
  );

  console.log(`   Subject:          ${report.subject.slice(0, 30)}...`);
  console.log(`   Current score:    ${report.riskSummary.currentScore}/100`);
  console.log(`   Total screenings: ${report.riskSummary.totalScreenings}`);
  console.log(`   Regulatory flags: ${report.regulatoryFlags.join(', ') || 'none'}`);
  console.log(`   Audit entries:    ${report.auditTrail.length}`);
}

// ---------------------------------------------------------------------------
// Step 6 — Alert subscription for ongoing monitoring
// ---------------------------------------------------------------------------

async function setupAlerts(): Promise<void> {
  console.log('\n[6] Setting up real-time risk monitoring alerts...');

  const sub = client.subscribeToAlerts(
    `did:stellar:${customerKeypair.publicKey()}`,
    'https://exchange.example.com/webhooks/compliance',
    ['sanctions-match', 'risk-score-change', 'travel-rule-trigger'],
  );

  console.log(`   DID:      ${sub.did.slice(0, 30)}...`);
  console.log(`   Webhook:  ${sub.webhookUrl}`);
  console.log(`   Events:   ${sub.events.join(', ')}`);
  console.log(`   Active:   ${sub.active}`);
}

// ---------------------------------------------------------------------------
// Step 7 — ZK proof of sanctions-clear (privacy-preserving KYC)
// ---------------------------------------------------------------------------

async function generateZKProof(): Promise<void> {
  console.log('\n[7] Generating ZK proof of sanctions-clear status...');

  const proof = await client.proveComplianceStatus(customerKeypair, 'sanctions-clear', {
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h
  });

  console.log(`   Proof type:   ${proof.proofType}`);
  console.log(`   Commitment:   ${proof.commitment.slice(0, 16)}...`);
  console.log(`   Proof value:  ${proof.proofValue.slice(0, 16)}...`);
  console.log(`   Expires:      ${new Date(proof.expiresAt!).toISOString()}`);

  // Verify the proof (exchange side — no address revealed)
  const valid = client.verifyComplianceProof(proof, customerKeypair.publicKey());
  console.log(`   Verified:     ${valid}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('=== Exchange Compliance — Full Integration Flow ===');
  console.log(`Oracle:   ${oracleKeypair.publicKey().slice(0, 12)}...`);
  console.log(`Exchange: ${exchangeKeypair.publicKey().slice(0, 12)}...`);
  console.log(`Customer: ${customerKeypair.publicKey().slice(0, 12)}...`);

  try {
    await updateSanctionsLists();
    await registerComplianceRules();
    await screenDeposit();
    await analyzeTransaction();
    await fileReport();
    await setupAlerts();
    await generateZKProof();
    console.log('\n=== Flow complete ===');
  } catch (err) {
    console.error('Error (expected in dry-run without deployed contracts):', err);
  }
}

main();
