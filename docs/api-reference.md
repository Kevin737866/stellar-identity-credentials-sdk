# SDK API Reference

Comprehensive reference for all client classes in `@stellar-identity/sdk`.

## Table of Contents

- [StellarIdentitySDK](#stellaridentitysdk)
- [DIDClient](#didclient)
- [CredentialClient](#credentialclient)
- [ReputationClient](#reputationclient)
- [ZKProofsClient](#zkproofsclient)
- [ComplianceClient](#complianceclient)
- [DIDResolver](#didresolver)
- [Configuration](#configuration)

---

## StellarIdentitySDK

Top-level facade that instantiates all sub-clients.

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';

const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
```

### `sdk.initializeUserIdentity(keypair, verificationMethods, services)`

Creates a DID and initialises on-chain reputation for a new user.

```typescript
const { did, address } = await sdk.initializeUserIdentity(keypair, [], []);
```

### `sdk.getIdentityProfile(address)`

Returns the full identity profile: DID document, reputation data, and credentials.

```typescript
const profile = await sdk.getIdentityProfile(address);
// { address, didDocument, reputationData, credentialCount, credentials }
```

### `sdk.performComplianceCheck(address)`

Runs a combined reputation + credential validity compliance check.

```typescript
const check = await sdk.performComplianceCheck(address);
// { reputationScore, validCredentials, complianceScore, recommendations }
```

---

## DIDClient

Manages `did:stellar` identifiers on the Soroban DID Registry contract.

```typescript
const did = sdk.did; // or: new DIDClient(config)
```

### `createDID(keypair, options)`

Creates a new DID on-chain.

```typescript
const didId = await did.createDID(keypair, {
  verificationMethods: [{
    id: '#key-1',
    type: 'Ed25519VerificationKey2018',
    controller: keypair.publicKey(),
    publicKey: keypair.publicKey(),
  }],
  services: [{
    id: '#hub',
    type: 'IdentityHub',
    endpoint: 'https://hub.example.com',
  }],
});
```

### `resolveDID(did)`

Resolves a DID document.

```typescript
const result = await did.resolveDID('did:stellar:GABC...');
// W3CResolutionResult
```

### `updateDID(keypair, options)`

Updates verification methods and/or services.

```typescript
await did.updateDID(keypair, {
  verificationMethods: [...],
  services: [...],
});
```

### `deactivateDID(keypair)`

Permanently deactivates a DID.

```typescript
await did.deactivateDID(keypair);
```

### `addAuthentication(keypair, methodId)` / `removeAuthentication(keypair, methodId)`

Manages the authentication method list.

```typescript
await did.addAuthentication(keypair, '#key-2');
await did.removeAuthentication(keypair, '#key-1');
```

### `generateDID(address)`

Derives the `did:stellar` string for a Stellar address (no network call).

```typescript
const didStr = did.generateDID(keypair.publicKey());
// "did:stellar:GABC..."
```

---

## CredentialClient

Issues, verifies, and manages Verifiable Credentials.

```typescript
const creds = sdk.credentials; // or: new CredentialClient(config)
```

### `issueCredential(issuer, options)`

Issues a generic verifiable credential.

```typescript
const credId = await creds.issueCredential(issuerKeypair, {
  subject: subjectAddress,
  credentialType: ['VerifiableCredential', 'KYCCredential'],
  credentialData: { level: 2, country: 'US' },
  expirationDate: Date.now() + 365 * 86400 * 1000,
});
```

### `issueKYCCredential(issuer, subject, kycData)`

Convenience method for KYC credentials.

```typescript
const credId = await creds.issueKYCCredential(issuerKeypair, subjectAddress, {
  firstName: 'Alice', lastName: 'Smith',
  dateOfBirth: '1990-01-01', nationality: 'US',
  documentType: 'Passport', documentNumber: 'X1234567',
});
```

### `verifyCredential(credentialId)`

Verifies a credential (not revoked, not expired, valid proof).

```typescript
const result = await creds.verifyCredential(credId);
// { valid, revoked, expired, credentialId }
```

### `batchVerifyCredentials(credentialIds)`

Verifies multiple credentials in one call.

```typescript
const results = await creds.batchVerifyCredentials([id1, id2, id3]);
```

### `revokeCredential(issuer, credentialId, reason?)`

Revokes a credential.

```typescript
await creds.revokeCredential(issuerKeypair, credId, 'Data outdated');
```

### `getCredential(credentialId)`

Retrieves a full credential object.

```typescript
const vc = await creds.getCredential(credId);
```

### `getSubjectCredentials(address)`

Lists all credential IDs issued to a subject address.

```typescript
const ids = await creds.getSubjectCredentials(subjectAddress);
```

### `createPresentation(credentials, holder)` / `verifyPresentation(presentation)`

Creates and verifies a Verifiable Presentation.

```typescript
const vp = await creds.createPresentation([vc1, vc2], holderKeypair);
const valid = await creds.verifyPresentation(vp);
```

---

## ReputationClient

Reads and updates on-chain reputation scores.

```typescript
const rep = sdk.reputation; // or: new ReputationClient(config)
```

### `initializeReputation(keypair)`

Creates an on-chain reputation profile for a new address.

```typescript
await rep.initializeReputation(keypair);
```

### `getReputationScore(address)`

Returns the current score object.

```typescript
const score = await rep.getReputationScore(address);
// { score: 650, tier: 'established', ... }
```

### `getReputationData(address)`

Returns full reputation data including history.

```typescript
const data = await rep.getReputationData(address);
// { score, tier, factors, history }
```

### `updateTransactionReputation(address, success, amount)`

Records a transaction outcome and returns the updated score.

```typescript
const newScore = await rep.updateTransactionReputation(address, true, 1000);
```

### `updateCredentialReputation(address, valid, credentialType)`

Updates score based on credential validity.

```typescript
const newScore = await rep.updateCredentialReputation(address, true, 'KYCCredential');
```

### `getReputationTier(score)` (synchronous)

Maps a numeric score to a tier label.

```typescript
const tier = rep.getReputationTier(650); // 'established'
```

Tiers: `new` (< 300) · `emerging` (300–549) · `established` (550–749) · `trusted` (750–899) · `elite` (≥ 900)

---

## ZKProofsClient

Creates and verifies zero-knowledge proofs.

```typescript
const zk = sdk.zkProofs; // or: new ZKProofsClient(config)
```

### `createAgeProof(circuitId, commitment, minAge, proof)`

Submits a ZK age proof on-chain.

```typescript
const proofId = await zk.createAgeProof(
  'age_verification', commitment, 18, proofBytes
);
```

### `verifyAgeProof(proofId, minAge)`

Verifies that a subject has met the minimum age threshold.

```typescript
const isAdult = await zk.verifyAgeProof(proofId, 18);
```

### `createIncomeProof(circuitId, commitment, minIncome, proof)`

Submits a ZK income threshold proof.

```typescript
const proofId = await zk.createIncomeProof('income_check', commitment, 50000, proof);
```

### `verifyProof(proofId)`

Verifies any ZK proof by ID.

```typescript
const result = await zk.verifyProof(proofId);
// { valid, proofId, circuitId, verifiedAt }
```

### `generateCommitment(data, salt?)` (synchronous)

Generates a commitment hash for private data.

```typescript
const commitment = zk.generateCommitment('1990-01-01', randomSalt);
```

---

## ComplianceClient

Regulatory compliance screening and reporting.

```typescript
import { compliance } from '@stellar-identity/sdk';
// or access via sdk if configured
```

### `screenAddress(address, options?)`

Screens an address against sanctions, PEP, and adverse media lists.

```typescript
const result = await compliance.screenAddress(address);
// { address, status, riskScore, matches, timestamp }
```

### `screenTransaction(txData)`

Screens both parties and assesses transaction risk.

```typescript
const risk = await compliance.screenTransaction({ txHash, sender, receiver, amount, asset });
// { overallRisk, requiresTravelRule, flags, senderRisk, receiverRisk }
```

### `generateComplianceReport(address, keypair, options?)`

Generates a regulatory report.

```typescript
const report = await compliance.generateComplianceReport(address, keypair);
```

### `subscribeToAlerts(address, keypair, options)`

Registers a webhook for real-time compliance alerts.

```typescript
await compliance.subscribeToAlerts(address, keypair, { webhookUrl: 'https://...' });
```

### `proveComplianceStatus(address, keypair, options)`

Generates a ZK proof of compliance status.

```typescript
const proof = await compliance.proveComplianceStatus(address, keypair, { minKycLevel: 1 });
```

---

## DIDResolver

Cross-method DID resolver supporting `did:stellar`, `did:key`, `did:web`, `did:ethr`.

```typescript
import { DIDResolver } from '@stellar-identity/sdk';
const resolver = new DIDResolver(config);
```

### `resolve(did, options?)`

Resolves a DID document from any supported method.

```typescript
const result = await resolver.resolve('did:key:z6Mk...');
```

### `dereference(didUrl)`

Dereferences a DID URL to a specific resource (verification method or service).

```typescript
const vm = await resolver.dereference('did:stellar:GABC...#key-1');
```

---

## Configuration

```typescript
interface StellarIdentityConfig {
  network: 'testnet' | 'mainnet' | 'futurenet';
  rpcUrl: string;
  contracts: {
    didRegistry: string;
    credentialIssuer: string;
    reputationScore: string;
    zkAttestation: string;
    complianceFilter: string;
  };
}
```

### Preset Configs

```typescript
import { DEFAULT_CONFIGS } from '@stellar-identity/sdk';

DEFAULT_CONFIGS.testnet  // pre-configured for Stellar testnet
```

### Custom Config

```typescript
const config: StellarIdentityConfig = {
  network: 'mainnet',
  rpcUrl: 'https://soroban-rpc.stellar.org',
  contracts: {
    didRegistry: 'CONTRACT_ADDRESS',
    credentialIssuer: 'CONTRACT_ADDRESS',
    reputationScore: 'CONTRACT_ADDRESS',
    zkAttestation: 'CONTRACT_ADDRESS',
    complianceFilter: 'CONTRACT_ADDRESS',
  },
};
```
