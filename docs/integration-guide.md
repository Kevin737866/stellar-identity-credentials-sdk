# Integration Guide for Third-Party Developers

This guide walks you through common integration patterns with the Stellar Identity Credentials SDK.

## Prerequisites

- Node.js 18+
- A Stellar account (testnet or mainnet)
- Basic familiarity with Stellar transactions

## Installation

```bash
npm install @stellar-identity/sdk stellar-sdk
```

---

## 1. Quickstart: Basic Integration

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);
const keypair = Keypair.random();

// Fund the testnet account
// https://laboratory.stellar.org/#account-creator?network=test

// Create identity
const { did } = await sdk.initializeUserIdentity(keypair, [], []);
console.log('DID:', did);
```

---

## 2. Wallet Integration

Connect a Stellar wallet (Freighter, xBull, Albedo) instead of using a raw keypair:

```typescript
import { connectWallet, detectInstalledWallets } from '@stellar-identity/sdk';

// Detect available wallets
const wallets = detectInstalledWallets();
console.log('Available:', wallets.map(w => w.name));

// Connect Freighter
const connector = await connectWallet('freighter');
const address = await connector.getPublicKey();

// Use address with SDK (read operations)
const profile = await sdk.getIdentityProfile(address);
```

For signing, use the wallet connector's `signTransaction` method:

```typescript
const signed = await connector.signTransaction(xdr, { network: 'testnet' });
```

---

## 3. Tutorial: Issuing Credentials

Your app needs an **issuer keypair** with admin rights on the `CredentialIssuer` contract.

```typescript
const issuerKeypair = Keypair.fromSecret('SXXX...');  // store securely

// Issue a KYC credential after verifying the user off-chain
const credId = await sdk.credentials.issueKYCCredential(
  issuerKeypair,
  userAddress,
  {
    firstName: 'Alice',
    lastName: 'Smith',
    dateOfBirth: '1985-03-20',
    nationality: 'DE',
    documentType: 'Passport',
    documentNumber: 'C01X00T47',
  }
);

console.log('Issued credential:', credId);
```

Store the `credId` in your database to allow future verification and revocation.

---

## 4. Tutorial: Verifying Credentials

A verifier (e.g. an exchange or DeFi protocol) checks that a credential is valid before granting access:

```typescript
// Verify a single credential
const result = await sdk.credentials.verifyCredential(credId);

if (!result.valid) {
  if (result.revoked) throw new Error('Credential has been revoked');
  if (result.expired) throw new Error('Credential has expired');
  throw new Error('Invalid credential');
}

// Batch verify multiple credentials
const results = await sdk.credentials.batchVerifyCredentials([id1, id2, id3]);
const allValid = results.every(r => r.valid);
```

### Verifying a Presentation

When a user presents credentials via a Verifiable Presentation:

```typescript
const isValid = await sdk.credentials.verifyPresentation(presentationObject);
```

---

## 5. Tutorial: Building Reputation-Based Systems

Use on-chain reputation scores to make access control decisions.

### Read a reputation score

```typescript
const score = await sdk.reputation.getReputationScore(userAddress);

// Tier thresholds
// < 300   → new
// 300–549 → emerging
// 550–749 → established
// 750–899 → trusted
// ≥ 900   → elite

if (score.score < 550) {
  throw new Error('Minimum reputation tier: established');
}
```

### Record transaction outcomes (as a DeFi protocol)

```typescript
// On successful transaction
await sdk.reputation.updateTransactionReputation(userAddress, true, amountLumens);

// On failed transaction
await sdk.reputation.updateTransactionReputation(userAddress, false, amountLumens);
```

### Require a reputation tier for feature access

```typescript
const tier = sdk.reputation.getReputationTier(score.score);

const ALLOWED_TIERS = ['established', 'trusted', 'elite'];
if (!ALLOWED_TIERS.includes(tier)) {
  return res.status(403).json({ error: 'Insufficient reputation tier' });
}
```

---

## 6. Tutorial: Implementing KYC/AML Compliance

Combine credential issuance, sanctions screening, and ZK proofs for a full KYC/AML flow.

### Step 1 — Screen the address before onboarding

```typescript
import { compliance } from '@stellar-identity/sdk/compliance';

const screen = await compliance.screenAddress(userAddress);

if (screen.status === 'blocked') {
  return res.status(403).json({ error: 'Address on sanctions list' });
}
if (screen.status === 'suspicious') {
  // Route to manual review
}
```

### Step 2 — Issue KYC credential after identity verification

```typescript
const credId = await sdk.credentials.issueKYCCredential(issuerKeypair, userAddress, kycData);
```

### Step 3 — Create a ZK age proof (optional, for privacy)

```typescript
const commitment = sdk.zkProofs.generateCommitment(userDob, salt);
const proofId = await sdk.zkProofs.createAgeProof('age_v1', commitment, 18, zkProofBytes);
const isAdult = await sdk.zkProofs.verifyAgeProof(proofId, 18);
```

### Step 4 — Generate a compliance report

```typescript
const report = await compliance.generateComplianceReport(userAddress, issuerKeypair);
```

---

## 7. Cross-Domain DID Resolution

Resolve DIDs from any supported method in your application:

```typescript
import { DIDResolver } from '@stellar-identity/sdk';

const resolver = new DIDResolver(config);

// Works for did:stellar, did:key, did:web, did:ethr
const { didDocument, didResolutionMetadata } = await resolver.resolve(didString);

if (didResolutionMetadata.error) {
  console.error('Resolution failed:', didResolutionMetadata.error);
}
```

---

## 8. Code Examples in Other Languages

### Python (via Stellar SDK + HTTP)

```python
import requests

# Resolve DID via your deployed API endpoint
resp = requests.get(f"https://your-api.com/did/{did_string}")
did_document = resp.json()
```

### Go

```go
resp, err := http.Get("https://your-api.com/did/" + didString)
// parse JSON response into DIDDocument struct
```

### Java

```java
HttpClient client = HttpClient.newHttpClient();
HttpRequest req = HttpRequest.newBuilder()
    .uri(URI.create("https://your-api.com/did/" + didString))
    .build();
HttpResponse<String> resp = client.send(req, BodyHandlers.ofString());
```

---

## Error Handling

All SDK methods throw `StellarIdentityError` subclasses:

```typescript
import { DIDError, CredentialError, ComplianceError } from '@stellar-identity/sdk';

try {
  await sdk.credentials.verifyCredential(credId);
} catch (err) {
  if (err instanceof CredentialError) {
    console.error('Credential error:', err.code, err.message);
  }
}
```

| Error class | When thrown |
|-------------|-------------|
| `DIDError` | DID creation, resolution, or update failures |
| `CredentialError` | Issuance, verification, or revocation failures |
| `ReputationError` | Reputation read/write failures |
| `ZKProofError` | ZK circuit or proof failures |
| `ComplianceError` | Screening or reporting failures |
| `NetworkError` | RPC or HTTP connectivity issues |

---

## Support

- **Docs**: see other files in `docs/`
- **Issues**: https://github.com/Kevin737866/stellar-identity-credentials-sdk/issues
- **API Reference**: [docs/api-reference.md](./api-reference.md)
