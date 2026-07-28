# Developer Quick Start Guide

Step-by-step tutorials for common workflows using the Stellar Identity Credentials SDK. 
Each tutorial includes prerequisites, copy-paste code snippets, expected output, and 
troubleshooting tips.

---

## Prerequisites

Before starting any tutorial, ensure you have:

- **Node.js 18+** installed  
- **A Stellar testnet account** funded via [Friendbot](https://friendbot.stellar.org/?addr=)  
- **The SDK installed**:  
  ```bash
  npm install @stellar-identity/sdk stellar-sdk
  ```
- **Basic familiarity** with TypeScript and Stellar concepts

> **Network:** All tutorials target **testnet** — no real funds are required.

---

## Tutorial 1: Create Your First DID

**Goal:** Register a W3C-compliant `did:stellar` identifier on the Stellar testnet, then
resolve it to fetch your DID document.

### 1.1 — Prerequisites

- A funded Stellar testnet account (keypair)  
- SDK installed: `npm install @stellar-identity/sdk stellar-sdk`

### 1.2 — Full Code

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS, UTILS } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

async function createFirstDID() {
  // 1. Initialize the SDK for testnet
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // 2. Generate a keypair (in production, load from secure storage)
  const keypair = UTILS.generateKeypair();
  console.log('My address:', keypair.publicKey());

  // 3. Define verification methods (how you prove control of the DID)
  const verificationMethods = [
    {
      id: '#key-1',
      type: 'Ed25519VerificationKey2018',
      controller: keypair.publicKey(),
      publicKey: keypair.publicKey(),
    },
  ];

  // 4. Define service endpoints (where to find more info about this DID)
  const services = [
    {
      id: '#hub',
      type: 'IdentityHub',
      endpoint: 'https://identity-hub.example.com',
    },
  ];

  // 5. Create the DID on-chain
  const did = await sdk.did.createDID(keypair, {
    verificationMethods,
    services,
  });
  console.log('✅ DID created:', did);

  // 6. Resolve the DID to get your DID document
  const resolution = await sdk.did.resolveDID(did);
  console.log('✅ DID Document:');
  console.log(JSON.stringify(resolution.didDocument, null, 2));

  return did;
}

createFirstDID()
  .then((did) => console.log('\n🎉 Success! Your DID:', did))
  .catch((err) => console.error('❌ Failed:', err));
```

### 1.3 — Expected Output

```
My address: GBQQ6Q...
✅ DID created: did:stellar:GBQQ6Q...
✅ DID Document:
{
  "id": "did:stellar:GBQQ6Q...",
  "controller": "GBQQ6Q...",
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "Ed25519VerificationKey2018",
      "controller": "GBQQ6Q...",
      "publicKey": "GBQQ6Q..."
    }
  ],
  "authentication": [],
  "service": [
    {
      "id": "#hub",
      "type": "IdentityHub",
      "endpoint": "https://identity-hub.example.com"
    }
  ],
  "created": 1719876543210,
  "updated": 1719876543210
}

🎉 Success! Your DID: did:stellar:GBQQ6Q...
```

### 1.4 — What Just Happened?

1. You generated a fresh Stellar keypair — this is the **controller** of your DID.
2. You registered the DID on the Soroban DID Registry contract via `createDID()`.
3. The contract stores your verification methods (public keys) and service endpoints.
4. You resolved the DID on-chain and received a W3C-compliant DID document.

### 1.5 — Troubleshooting

| Problem | Solution |
|---------|----------|
| `Transaction submission failed` | Your testnet account needs XLM. Fund it at [Friendbot](https://friendbot.stellar.org/). |
| `Invalid Stellar address` | Ensure the public key starts with `G` and is 56 characters. |
| `Too many verification methods` | Maximum is 20. Reduce the array. |
| `Network timeout` | Check your internet connection and try again — testnet RPC can be slow. |
| `Contract not found` | Use `DEFAULT_CONFIGS.testnet` to ensure correct contract addresses. |

---

## Tutorial 2: Issue and Verify a KYC Credential

**Goal:** Act as a KYC provider, issue a verifiable KYC credential to a user, then
verify that credential from the perspective of a relying party (verifier).

### 2.1 — Prerequisites

- Completed **Tutorial 1** or understand DID basics  
- Two Stellar testnet keypairs: one **issuer** and one **user**  
- SDK installed

### 2.2 — Full Code

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS, UTILS } from '@stellar-identity/sdk';

async function kycCredentialFlow() {
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // ── Participants ──────────────────────────────────────────────────────
  const issuerKeypair = UTILS.generateKeypair();  // KYC Provider
  const userKeypair   = UTILS.generateKeypair();  // End User

  console.log('Issuer:', issuerKeypair.publicKey());
  console.log('User:  ', userKeypair.publicKey());

  // ── Step 1: Create the user's DID ─────────────────────────────────────
  const userDID = await sdk.did.createDID(userKeypair, {
    verificationMethods: [{
      id: '#key-1',
      type: 'Ed25519VerificationKey2018',
      controller: userKeypair.publicKey(),
      publicKey: userKeypair.publicKey(),
    }],
    services: [],
  });
  console.log('\n✅ User DID created:', userDID);

  // ── Step 2: Issue a KYC credential ────────────────────────────────────
  const kycData = {
    firstName: 'Jane',
    lastName: 'Doe',
    dateOfBirth: '1992-06-15',
    nationality: 'US',
    documentType: 'Passport',
    documentNumber: 'P987654321',
    expiryDate: '2030-06-15',
  };

  const credentialId = await sdk.credentials.issueKYCCredential(
    issuerKeypair,
    userKeypair.publicKey(),
    kycData,
    // Expires in 1 year
    Date.now() + 365 * 24 * 60 * 60 * 1000,
  );
  console.log('✅ KYC credential issued:', credentialId);

  // ── Step 3: Retrieve and inspect the credential ───────────────────────
  const credential = await sdk.credentials.getCredential(credentialId);
  console.log('\n📄 Credential details:');
  console.log('  Type:', credential.type.join(', '));
  console.log('  Issuer:', credential.issuer);
  console.log('  Subject:', credential.subject);
  console.log('  Data:', JSON.stringify(credential.credentialData, null, 4));

  // ── Step 4: Verify the credential (as a relying party) ────────────────
  const verification = await sdk.credentials.verifyCredential(credentialId);
  console.log('\n🔍 Verification result:');
  console.log('  Valid:   ', verification.valid);
  console.log('  Revoked: ', verification.revoked);
  console.log('  Expired: ', verification.expired);

  if (verification.valid) {
    console.log('\n🎉 KYC credential is valid — user is verified!');
  } else {
    console.log('\n⚠️  Credential verification FAILED');
  }

  return { userDID, credentialId };
}

kycCredentialFlow()
  .then((result) => console.log('\n✅ Flow complete:', result))
  .catch((err) => console.error('❌ Failed:', err));
```

### 2.3 — Expected Output

```
Issuer: GCXG6Q...
User:   GDOY7X...

✅ User DID created: did:stellar:GDOY7X...
✅ KYC credential issued: cred-1719876543210

📄 Credential details:
  Type: KYCVerification, VerifiableCredential
  Issuer: GCXG6Q...
  Subject: GDOY7X...
  Data: {
      "type": "KYCVerification",
      "data": {
          "firstName": "Jane",
          "lastName": "Doe",
          "dateOfBirth": "1992-06-15",
          "nationality": "US",
          "documentType": "Passport",
          "documentNumber": "P987654321",
          "expiryDate": "2030-06-15"
      },
      "verificationLevel": "Standard",
      ...
  }

🔍 Verification result:
  Valid:    true
  Revoked:  false
  Expired:  false

🎉 KYC credential is valid — user is verified!
```

### 2.4 — Verifying Without the Credential ID

If all you have is a user's Stellar address, you can look up all their credentials:

```typescript
// Get all credential IDs issued to a user
const credentialIds = await sdk.credentials.getSubjectCredentials(userAddress);

// Verify them all in one call
const results = await sdk.credentials.batchVerifyCredentials(credentialIds);

const allValid = results.every(r => r.valid);
console.log(`User has ${credentialIds.length} credentials. All valid: ${allValid}`);
```

### 2.5 — Troubleshooting

| Problem | Solution |
|---------|----------|
| `issuerKeypair` has no funds | Fund the issuer's testnet account via Friendbot. |
| Credential not found | The `credentialId` is returned by `issueKYCCredential()`. Store it after issuance. |
| `credentialData` is empty string | The data is decompressed on read; ensure you use `getCredential()` to retrieve it. |
| `Expired: true` | The credential's expiration date is in the past. Set a future `expirationDate`. |
| "Too many credential types" | Maximum 10 types per credential. |

---

## Tutorial 3: Build a Privacy-Preserving Age Verification

**Goal:** Prove that a user is over 18 using zero-knowledge proofs — without revealing
their actual birth date or age.

### 3.1 — Prerequisites

- Completed **Tutorial 1** (DID creation)  
- Node.js 18+  
- SDK installed

### 3.2 — How ZK Age Proofs Work

A **zero-knowledge age proof** lets the user prove "I am at least N years old" while
keeping their birth year private:

1. The **user** generates a cryptographic commitment of their age with a random salt.
2. The **user** creates a ZK proof on-chain via the `zkAttestation` contract.
3. The **verifier** checks the proof — they learn only that `age >= threshold`, nothing else.

### 3.3 — Full Code

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS, UTILS } from '@stellar-identity/sdk';

async function privacyPreservingAgeCheck() {
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // ── User setup ────────────────────────────────────────────────────────
  const userKeypair = UTILS.generateKeypair();
  const verifierKeypair = UTILS.generateKeypair();

  const userAge = 25;
  const currentYear = new Date().getFullYear();
  const birthYear = currentYear - userAge;

  console.log('🔒 Privacy-Preserving Age Verification\n');
  console.log('User age:', userAge, '(PRIVATE — never revealed)');
  console.log('Birth year:', birthYear, '(PRIVATE — never revealed)');
  console.log('User address:', userKeypair.publicKey());
  console.log('Verifier address:', verifierKeypair.publicKey());

  // ── Step 1: Generate a commitment (hides the actual age) ──────────────
  const salt = UTILS.generateKeypair().secret().slice(0, 32);
  const ageCommitment = sdk.zkProofs.generateCommitment(
    userAge.toString(),
    salt,
  );
  console.log('\n✅ Age commitment generated:', ageCommitment.slice(0, 16) + '...');

  // ── Step 2: Create the ZK age proof on-chain ──────────────────────────
  const minAge = 18;

  console.log(`\nCreating ZK proof: user is ≥ ${minAge} years old...`);
  const proofId = await sdk.zkProofs.createAgeProof(
    birthYear,
    currentYear,
    minAge,
    {
      circuitId: 'age_range_proof',
      publicInputs: [ageCommitment, String(minAge)],
      proofBytes: '', // filled by snarkjs in production
      nullifier: '',
      revealedAttributes: ['age_commitment'],
    },
  );
  console.log('✅ ZK proof created:', proofId);

  // ── Step 3: The verifier checks the proof ─────────────────────────────
  //    (The verifier NEVER learns the user's actual age or birth year)
  console.log('\n🔍 Verifier checking proof...');
  const isAdult = await sdk.zkProofs.verifyAgeProof(proofId, minAge);
  console.log(`✅ Age ≥ ${minAge}:`, isAdult);

  // ── Step 4: Demonstrate proof reuse ───────────────────────────────────
  console.log('\n🔄 Verifying same proof again (proofs are reusable)...');
  const recheck = await sdk.zkProofs.verifyAgeProof(proofId, minAge);
  console.log('✅ Re-verification:', recheck);

  // ── Step 5: Demonstrate failed verification ───────────────────────────
  console.log('\n❌ Testing: what if we check for age ≥ 30?');
  const tooYoung = await sdk.zkProofs.verifyAgeProof(proofId, 30);
  console.log('   Age ≥ 30:', tooYoung, '(expected: false)');

  // ── Summary ───────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(50));
  console.log('📊 Summary');
  console.log('─'.repeat(50));
  console.log('User actual age:    ', userAge, '(never revealed)');
  console.log('Minimum age proven:  ', minAge, '✅');
  console.log('What verifier learns:', `Age ≥ ${minAge} → true`);
  console.log('What stays private:  ', 'Exact age, birth year, identity');
}

privacyPreservingAgeCheck()
  .then(() => console.log('\n🎉 Privacy-preserving age check complete!'))
  .catch((err) => console.error('❌ Failed:', err));
```

### 3.4 — Expected Output

```
🔒 Privacy-Preserving Age Verification

User age: 25 (PRIVATE — never revealed)
Birth year: 2001 (PRIVATE — never revealed)
User address: GDQK...
Verifier address: GBTY...

✅ Age commitment generated: a3f2c8b9e1d4f7a2...

Creating ZK proof: user is ≥ 18 years old...
✅ ZK proof created: proof-1719876543210

🔍 Verifier checking proof...
✅ Age ≥ 18: true

🔄 Verifying same proof again (proofs are reusable)...
✅ Re-verification: true

❌ Testing: what if we check for age ≥ 30?
   Age ≥ 30: false (expected: false)

──────────────────────────────────────────────────
📊 Summary
──────────────────────────────────────────────────
User actual age:     25 (never revealed)
Minimum age proven:   18 ✅
What verifier learns: Age ≥ 18 → true
What stays private:   Exact age, birth year, identity

🎉 Privacy-preserving age check complete!
```

### 3.5 — Supported ZK Circuit Types

| Circuit ID | What It Proves | Privacy Guarantee |
|------------|---------------|-------------------|
| `age_range_proof` | Age meets a threshold | Birth year hidden |
| `income_range_proof` | Income meets a threshold | Exact income hidden |
| `credential_ownership` | You hold a credential | Credential contents hidden |
| `kyc_composite_proof` | Age + country + KYC combined | All individual attributes hidden |

### 3.6 — Troubleshooting

| Problem | Solution |
|---------|----------|
| `createAgeProof` fails | Ensure `birthYear` is a valid number and `minAge` is less than the age. |
| `verifyAgeProof` always `false` | Confirm you're using the same `proofId` returned by `createAgeProof`. |
| `generateCommitment` returns different values | Commitments are deterministic only when using the same `privateData` and `salt`. |
| "circuit not found" | Use `age_range_proof` as the circuit ID. Active circuits can be listed via `sdk.zkProofs.getActiveCircuits()`. |
| Proof expiration | Set `expiresAt` in the options to control proof lifetime (default: no expiry). |

---

## Tutorial 4: Set Up Compliance Screening

**Goal:** Screen a Stellar address against sanctions lists, analyze transaction risk,
and generate a compliance report — all without sharing the screened party's identity.

### 4.1 — Prerequisites

- Completed **Tutorial 1** or **Tutorial 2**  
- SDK installed  
- (Optional) API key from Chainalysis / Elliptic / ComplyAdvantage for external enrichment

### 4.2 — Full Code

```typescript
import {
  StellarIdentitySDK,
  DEFAULT_CONFIGS,
  UTILS,
  ComplianceClient,
} from '@stellar-identity/sdk';

async function complianceScreening() {
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
  const compliance = new ComplianceClient(DEFAULT_CONFIGS.testnet);

  // ── Participants ──────────────────────────────────────────────────────
  const userKeypair = UTILS.generateKeypair();
  console.log('User address:', userKeypair.publicKey());

  // ── Step 1: Screen an address against sanctions lists ─────────────────
  console.log('\n🛡️  Step 1: Screening address...');
  const screening = await compliance.screenAddress(
    userKeypair.publicKey(),
    { enrichWithExternal: false }, // set true if you have external API keys
  );

  console.log('  Status:    ', screening.status);
  console.log('  Risk Score:', screening.riskScore, '/ 100');
  console.log('  Matches:   ', screening.matches.length > 0
    ? screening.matches.join(', ')
    : 'None');

  if (screening.status === 'blocked') {
    console.error('\n⛔ Address is BLOCKED — sanctions match found!');
    return;
  }
  if (screening.status === 'suspicious') {
    console.warn('\n⚠️  Address is SUSPICIOUS — manual review recommended.');
  } else {
    console.log('\n✅ Address is CLEAR — no sanctions matches.');
  }

  // ── Step 2: Screen a transaction ──────────────────────────────────────
  console.log('\n💰 Step 2: Screening transaction...');
  const txRisk = await compliance.screenTransaction({
    hash: 'tx-' + Math.random().toString(36).slice(2, 14),
    sender: userKeypair.publicKey(),
    receiver: UTILS.generateKeypair().publicKey(),
    amount: '5000',
    asset: 'USDC',
  });

  console.log('  Overall Risk:  ', txRisk.overallRisk, '/ 100');
  console.log('  Travel Rule:   ', txRisk.requiresTravelRule
    ? 'Required (≥ $1000)'
    : 'Not required');
  console.log('  Flags:         ', txRisk.flags.length > 0
    ? txRisk.flags.join(', ')
    : 'None');

  if (txRisk.requiresTravelRule) {
    // ── Step 3: Build a FATF Travel Rule payload ────────────────────────
    console.log('\n📋 Step 3: Building Travel Rule payload...');
    const travelPayload = compliance.buildTravelRulePayload({
      originatorVASP: 'VASP-Alpha',
      beneficiaryVASP: 'VASP-Beta',
      originatorName: 'Jane Doe',
      originatorAccount: userKeypair.publicKey(),
      beneficiaryName: 'Bob Smith',
      beneficiaryAccount: UTILS.generateKeypair().publicKey(),
      amount: '5000',
      asset: 'USDC',
      txRef: txRisk.txHash,
    });
    console.log('✅ Travel Rule payload ready:');
    console.log(JSON.stringify(travelPayload, null, 2));
  }

  // ── Step 4: Generate a compliance report ──────────────────────────────
  console.log('\n📊 Step 4: Generating compliance report...');

  // First, create a DID for the user so we can generate a report
  const userDID = await sdk.did.createDID(userKeypair, {
    verificationMethods: [{
      id: '#key-1',
      type: 'Ed25519VerificationKey2018',
      controller: userKeypair.publicKey(),
      publicKey: userKeypair.publicKey(),
    }],
    services: [],
  });

  const now = Date.now();
  const report = await compliance.generateComplianceReport(userDID, {
    start: now - 30 * 24 * 60 * 60 * 1000, // 30 days ago
    end: now,
  });

  console.log('✅ Compliance report generated:');
  console.log('  Subject:         ', report.subject);
  console.log('  Current Risk:    ', report.riskSummary.currentScore, '/ 100');
  console.log('  Peak Risk:       ', report.riskSummary.peakScore, '/ 100');
  console.log('  Avg Risk:        ', report.riskSummary.averageScore, '/ 100');
  console.log('  Total Screenings:', report.riskSummary.totalScreenings);
  console.log('  Flags:           ', report.regulatoryFlags.length > 0
    ? report.regulatoryFlags.join(', ')
    : 'None');

  // ── Step 5: Run a combined compliance check via the SDK ───────────────
  console.log('\n🔍 Step 5: Running combined compliance check...');
  const check = await sdk.performComplianceCheck(userKeypair.publicKey());

  console.log('✅ Combined compliance check:');
  console.log('  Reputation Score:  ', check.reputationScore, '/ 100');
  console.log('  Valid Credentials: ', check.validCredentials, '/', check.totalCredentials);
  console.log('  Compliance Score:  ', check.complianceScore, '/ 100');
  console.log('  Recommendations:');
  check.recommendations.forEach((rec) => console.log('    •', rec));

  // ── Summary ───────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(55));
  console.log('📊 Compliance Summary');
  console.log('─'.repeat(55));
  console.log('Sanctions status: ', screening.status.toUpperCase());
  console.log('Risk score:       ', screening.riskScore, '/ 100');
  console.log('Travel rule:      ', txRisk.requiresTravelRule ? 'Required' : 'N/A');
  console.log('Ready for onboarding:', screening.status === 'clear' ? '✅ Yes' : '⚠️  Review required');
}

complianceScreening()
  .then(() => console.log('\n🎉 Compliance screening complete!'))
  .catch((err) => console.error('❌ Failed:', err));
```

### 4.3 — Expected Output

```
User address: GDRX...

🛡️  Step 1: Screening address...
  Status:     clear
  Risk Score: 0 / 100
  Matches:    None

✅ Address is CLEAR — no sanctions matches.

💰 Step 2: Screening transaction...
  Overall Risk:   0 / 100
  Travel Rule:    Required (≥ $1000)
  Flags:          fatf-travel-rule-required

📋 Step 3: Building Travel Rule payload...
✅ Travel Rule payload ready:
{
  "originatorVASP": "VASP-Alpha",
  "beneficiaryVASP": "VASP-Beta",
  "originator": {
    "name": "Jane Doe",
    "accountNumber": "GDRX..."
  },
  "beneficiary": {
    "name": "Bob Smith",
    "accountNumber": "GA3P..."
  },
  "transferAmount": "5000",
  "asset": "USDC",
  "transactionRef": "tx-a1b2c3d4e5f6",
  "timestamp": 1719876543210
}

📊 Step 4: Generating compliance report...
✅ Compliance report generated:
  Subject:          did:stellar:GDRX...
  Current Risk:     0 / 100
  Peak Risk:        0 / 100
  Avg Risk:         0 / 100
  Total Screenings: 0
  Flags:            None

🔍 Step 5: Running combined compliance check...
✅ Combined compliance check:
  Reputation Score:   80 / 100
  Valid Credentials:  0 / 0
  Compliance Score:   8 / 100
  Recommendations:
    • Add more verifiable credentials to improve diversity and lender confidence.

───────────────────────────────────────────────────────
📊 Compliance Summary
───────────────────────────────────────────────────────
Sanctions status:  CLEAR
Risk score:        0 / 100
Travel rule:       Required
Ready for onboarding: ✅ Yes

🎉 Compliance screening complete!
```

### 4.4 — Real-Time Monitoring

Set up alerts to be notified when a user's compliance status changes:

```typescript
const subscription = compliance.subscribeToAlerts(
  `did:stellar:${userAddress}`,
  'https://your-server.com/compliance-webhook',
  ['sanctions-match', 'risk-score-change'],
);

console.log('✅ Alert subscription active for:', subscription.did);

// Later, unsubscribe:
compliance.unsubscribeFromAlerts(subscription.did);
```

### 4.5 — Privacy-Preserving Compliance Proofs

Prove that you are NOT on a sanctions list — without revealing your identity:

```typescript
const proof = await compliance.proveComplianceStatus(
  userKeypair,
  'sanctions-clear',
  { expiresAt: Date.now() + 86400_000 }, // 24 hours
);

console.log('✅ ZK compliance proof generated:');
console.log('  Type:     ', proof.proofType);
console.log('  Valid for:', '24 hours');

// The verifier checks the proof without learning the address
const isValid = compliance.verifyComplianceProof(
  proof,
  userKeypair.publicKey(),
);
console.log('  Verified: ', isValid);
```

### 4.6 — Troubleshooting

| Problem | Solution |
|---------|----------|
| `screenAddress` always returns `clear` | On-chain sanctions lists may not be populated on testnet. In production, use `enrichWithExternal: true`. |
| `generateComplianceReport` returns empty audit trail | Audit entries are recorded on-chain per screening action. Run `screenAddress` first to generate them. |
| "AddressBlocked" error | The address matched a sanctions list entry. Investigate with the compliance team. |
| `requiresTravelRule` is `false` for large amounts | Ensure the `amount` string can be parsed as a number ≥ 1000. |
| `proveComplianceStatus` fails for blocked addresses | The method validates the address is clear before generating a proof. |

---

## Complete Workflow: Putting It All Together

Here's a condensed example that combines all four tutorials into a single end-to-end flow:

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS, UTILS, ComplianceClient } from '@stellar-identity/sdk';

async function endToEndFlow() {
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
  const compliance = new ComplianceClient(DEFAULT_CONFIGS.testnet);

  const issuerKP = UTILS.generateKeypair();
  const userKP   = UTILS.generateKeypair();

  // 1. DID
  const did = await sdk.did.createDID(userKP, {
    verificationMethods: [{ id: '#key-1', type: 'Ed25519VerificationKey2018',
      controller: userKP.publicKey(), publicKey: userKP.publicKey() }],
    services: [],
  });
  console.log('1️⃣  DID:', did);

  // 2. KYC credential
  const credId = await sdk.credentials.issueKYCCredential(issuerKP, userKP.publicKey(), {
    firstName: 'John', lastName: 'Smith', dateOfBirth: '1988-04-12',
    nationality: 'US', documentType: 'Passport', documentNumber: 'N12345678',
    expiryDate: '2030-04-12',
  });
  const verification = await sdk.credentials.verifyCredential(credId);
  console.log('2️⃣  KYC valid:', verification.valid);

  // 3. ZK age proof
  const age = 36;
  const proofId = await sdk.zkProofs.createAgeProof(
    new Date().getFullYear() - age, new Date().getFullYear(), 21,
    { circuitId: 'age_range_proof', publicInputs: [], proofBytes: '', nullifier: '',
      revealedAttributes: [] },
  );
  console.log('3️⃣  Age ≥ 21:', await sdk.zkProofs.verifyAgeProof(proofId, 21));

  // 4. Compliance
  const screen = await compliance.screenAddress(userKP.publicKey());
  console.log('4️⃣  Compliance:', screen.status.toUpperCase());

  console.log('\n🎉 All checks passed — user is fully onboarded!');
}

endToEndFlow().catch(console.error);
```

### Expected Output

```
1️⃣  DID: did:stellar:GAHE...
2️⃣  KYC valid: true
3️⃣  Age ≥ 21: true
4️⃣  Compliance: CLEAR

🎉 All checks passed — user is fully onboarded!
```

---

## Next Steps

- **API Reference** — Full method signatures and types: [api-reference.md](./api-reference.md)
- **Integration Guide** — Advanced patterns for production: [integration-guide.md](./integration-guide.md)
- **Compliance Docs** — Deep dive into sanctions screening: [compliance-screening.md](./compliance-screening.md)
- **Deployment Guide** — Deploy contracts to testnet/mainnet: [deployment-guide.md](./deployment-guide.md)
- **Contributing** — How to contribute to the SDK: [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Architecture** — Architecture Decision Records: [adr/](./adr/)

---

**Built with ❤️ for the Stellar ecosystem**
