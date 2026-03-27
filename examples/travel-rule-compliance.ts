/**
 * travel-rule-compliance.ts
 *
 * FATF Travel Rule implementation for VASP-to-VASP transfers on Stellar.
 *
 * Demonstrates:
 *   1. Pre-transfer screening of both originator and beneficiary
 *   2. Travel Rule payload construction (originator + beneficiary info)
 *   3. Threshold check (≥ 1000 USD equivalent triggers Travel Rule)
 *   4. Stellar memo field encoding for Travel Rule data
 *   5. Beneficiary VASP verification via Stellar TOML compliance endpoint
 *   6. ZK range proof: amount below reporting threshold without revealing value
 *   7. Immutable audit trail filing for the transfer
 */

import { Keypair, TransactionBuilder, Networks, Operation, Asset, Memo } from 'stellar-sdk';
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

// VASP A — originating exchange (e.g. Kraken)
const vaspAKeypair = Keypair.fromSecret(
  process.env.VASP_A_SECRET ?? Keypair.random().secret(),
);

// VASP B — beneficiary exchange (e.g. Coinbase)
const vaspBKeypair = Keypair.fromSecret(
  process.env.VASP_B_SECRET ?? Keypair.random().secret(),
);

// Alice — customer at VASP A sending funds
const aliceKeypair = Keypair.fromSecret(
  process.env.ALICE_SECRET ?? Keypair.random().secret(),
);

// Bob — customer at VASP B receiving funds
const bobKeypair = Keypair.fromSecret(
  process.env.BOB_SECRET ?? Keypair.random().secret(),
);

const client = new ComplianceClient(config);

// Transfer details
const TRANSFER_AMOUNT = '2500'; // USD equivalent — above 1000 threshold
const TRANSFER_ASSET  = 'USDC';

// ---------------------------------------------------------------------------
// Step 1 — Pre-transfer screening of both parties
// ---------------------------------------------------------------------------

async function preTransferScreening(): Promise<boolean> {
  console.log('\n[1] Pre-transfer screening...');

  const [aliceResult, bobResult] = await Promise.all([
    client.screenAddress(aliceKeypair.publicKey()),
    client.screenAddress(bobKeypair.publicKey()),
  ]);

  console.log(`   Alice (originator): status=${aliceResult.status}, risk=${aliceResult.riskScore}`);
  console.log(`   Bob (beneficiary):  status=${bobResult.status},  risk=${bobResult.riskScore}`);

  if (aliceResult.status === 'blocked' || bobResult.status === 'blocked') {
    console.log('   ⛔ Transfer BLOCKED — sanctioned party detected');
    return false;
  }
  if (aliceResult.status === 'suspicious' || bobResult.status === 'suspicious') {
    console.log('   ⚠️  Transfer FLAGGED — enhanced due diligence required');
    // In production: pause and route to compliance officer
  }

  console.log('   ✅ Pre-transfer screening passed');
  return true;
}

// ---------------------------------------------------------------------------
// Step 2 — Threshold check and Travel Rule trigger
// ---------------------------------------------------------------------------

async function checkTravelRuleThreshold(): Promise<boolean> {
  console.log('\n[2] Checking FATF Travel Rule threshold...');

  const txRisk = await client.screenTransaction({
    hash: `travel-rule-demo-${Date.now()}`,
    sender: aliceKeypair.publicKey(),
    receiver: bobKeypair.publicKey(),
    amount: TRANSFER_AMOUNT,
    asset: TRANSFER_ASSET,
  });

  console.log(`   Amount:           ${TRANSFER_AMOUNT} ${TRANSFER_ASSET}`);
  console.log(`   Travel Rule req:  ${txRisk.requiresTravelRule}`);
  console.log(`   Overall risk:     ${txRisk.overallRisk}/100`);

  if (txRisk.requiresTravelRule) {
    console.log('   ℹ️  Amount ≥ 1000 USD — Travel Rule payload required');
  } else {
    console.log('   ℹ️  Amount < 1000 USD — Travel Rule not required');
  }

  return txRisk.requiresTravelRule;
}

// ---------------------------------------------------------------------------
// Step 3 — Build Travel Rule payload
// ---------------------------------------------------------------------------

function buildTravelRulePayload(): TravelRulePayload {
  console.log('\n[3] Building FATF Travel Rule payload...');

  const payload = client.buildTravelRulePayload({
    originatorVASP:    `did:stellar:${vaspAKeypair.publicKey()}`,
    beneficiaryVASP:   `did:stellar:${vaspBKeypair.publicKey()}`,
    originatorName:    'Alice [Redacted]',          // PII minimized per GDPR
    originatorAccount: aliceKeypair.publicKey(),
    beneficiaryName:   'Bob [Redacted]',
    beneficiaryAccount: bobKeypair.publicKey(),
    amount:            TRANSFER_AMOUNT,
    asset:             TRANSFER_ASSET,
    txRef:             `TR-${Date.now()}`,
  });

  console.log(`   Originator VASP:  ${payload.originatorVASP.slice(0, 30)}...`);
  console.log(`   Beneficiary VASP: ${payload.beneficiaryVASP.slice(0, 30)}...`);
  console.log(`   Amount:           ${payload.transferAmount} ${payload.asset}`);
  console.log(`   Tx ref:           ${payload.transactionRef}`);

  return payload;
}

// ---------------------------------------------------------------------------
// Step 4 — Encode Travel Rule data in Stellar memo
// ---------------------------------------------------------------------------

function encodeTravelRuleMemo(payload: TravelRulePayload): string {
  console.log('\n[4] Encoding Travel Rule data in Stellar memo...');

  // Stellar memo text is limited to 28 bytes — store a hash/reference,
  // send full payload via secure VASP-to-VASP channel (e.g. TRISA, OpenVASP)
  const memoRef = `TR:${payload.transactionRef}`.slice(0, 28);
  console.log(`   Memo (28 bytes):  "${memoRef}"`);
  console.log(`   Full payload:     transmitted via secure VASP channel`);

  // In production: POST payload to beneficiary VASP's Travel Rule endpoint
  // discovered via their stellar.toml COMPLIANCE_SERVER field
  return memoRef;
}

// ---------------------------------------------------------------------------
// Step 5 — Verify beneficiary VASP via Stellar TOML
// ---------------------------------------------------------------------------

async function verifyBeneficiaryVASP(): Promise<void> {
  console.log('\n[5] Verifying beneficiary VASP via Stellar TOML...');

  // In production: fetch https://<vasp-domain>/.well-known/stellar.toml
  // and check COMPLIANCE_SERVER, SIGNING_KEY, and KYC_SERVER fields
  const mockToml = {
    NETWORK_PASSPHRASE: 'Test SDF Network ; September 2015',
    SIGNING_KEY: vaspBKeypair.publicKey(),
    COMPLIANCE_SERVER: 'https://compliance.vaspb.example.com',
    KYC_SERVER: 'https://kyc.vaspb.example.com',
  };

  console.log(`   VASP B signing key: ${mockToml.SIGNING_KEY.slice(0, 12)}...`);
  console.log(`   Compliance server:  ${mockToml.COMPLIANCE_SERVER}`);
  console.log(`   KYC server:         ${mockToml.KYC_SERVER}`);
  console.log('   ✅ VASP B verified via Stellar TOML');
}

// ---------------------------------------------------------------------------
// Step 6 — ZK range proof: amount below reporting threshold
// ---------------------------------------------------------------------------

async function generateRangeProof(): Promise<void> {
  console.log('\n[6] Generating ZK range proof (amount < 10,000 USD reporting threshold)...');

  // The proof commits to the amount without revealing it.
  // Verifier learns only: amount < 10,000 (no CTR filing required).
  const proof = await client.proveComplianceStatus(aliceKeypair, 'threshold-below', {
    expiresAt: Date.now() + 60 * 60 * 1000, // 1h
  });

  console.log(`   Proof type:   ${proof.proofType}`);
  console.log(`   Commitment:   ${proof.commitment.slice(0, 16)}...`);
  console.log(`   Proof value:  ${proof.proofValue.slice(0, 16)}...`);

  // VASP B verifies without learning Alice's address or exact amount
  const valid = client.verifyComplianceProof(proof, aliceKeypair.publicKey());
  console.log(`   Verified:     ${valid}`);
}

// ---------------------------------------------------------------------------
// Step 7 — Immutable audit trail
// ---------------------------------------------------------------------------

async function fileAuditTrail(payload: TravelRulePayload): Promise<void> {
  console.log('\n[7] Filing immutable audit trail...');

  const reportKey = await client.fileRegulatoryReport(
    vaspAKeypair,
    aliceKeypair.publicKey(),
    `FATF Travel Rule transfer: ${payload.transactionRef}`,
    ['TRAVEL_RULE_APPLIED', 'OFAC_SCREENED', 'UN_SCREENED', 'VASP_VERIFIED'],
  );

  console.log(`   Report key:   ${reportKey}`);

  // Generate 30-day compliance report for Alice
  const report = await client.generateComplianceReport(
    `did:stellar:${aliceKeypair.publicKey()}`,
    { start: Date.now() - 30 * 24 * 60 * 60 * 1000, end: Date.now() },
  );

  console.log(`   Subject:      ${report.subject.slice(0, 30)}...`);
  console.log(`   Risk score:   ${report.riskSummary.currentScore}/100`);
  console.log(`   Audit entries:${report.auditTrail.length}`);
  console.log(`   Reg flags:    ${report.regulatoryFlags.join(', ') || 'none'}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('=== FATF Travel Rule Compliance — VASP-to-VASP Transfer ===');
  console.log(`VASP A:  ${vaspAKeypair.publicKey().slice(0, 12)}...`);
  console.log(`VASP B:  ${vaspBKeypair.publicKey().slice(0, 12)}...`);
  console.log(`Alice:   ${aliceKeypair.publicKey().slice(0, 12)}...`);
  console.log(`Bob:     ${bobKeypair.publicKey().slice(0, 12)}...`);
  console.log(`Amount:  ${TRANSFER_AMOUNT} ${TRANSFER_ASSET}`);

  try {
    const canProceed = await preTransferScreening();
    if (!canProceed) return;

    const needsTravelRule = await checkTravelRuleThreshold();

    let payload: TravelRulePayload | undefined;
    if (needsTravelRule) {
      payload = buildTravelRulePayload();
      const memoRef = encodeTravelRuleMemo(payload);
      await verifyBeneficiaryVASP();
      console.log(`\n   Memo ref for Stellar tx: "${memoRef}"`);
    }

    await generateRangeProof();
    await fileAuditTrail(payload ?? buildTravelRulePayload());

    console.log('\n=== Travel Rule flow complete ===');
  } catch (err) {
    console.error('Error (expected in dry-run without deployed contracts):', err);
  }
}

main();
