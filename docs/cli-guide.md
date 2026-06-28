# Stellar Identity CLI — Installation & Usage Guide

The interactive CLI tool lets developers deploy, manage, and interact with all Stellar Identity contracts without writing any code.

## Installation

```bash
# Install dependencies (only needed once)
npm install

# Install ts-node for running the CLI directly
npm install --save-dev ts-node@10.9.2
```

## Running the CLI

```bash
# Launch interactive mode (recommended)
npm run cli

# Run the automated full demo
npm run cli:demo

# Show help and documentation
npm run cli:help

# Run the original example demo
npm run example:cli-demo
```

## Command Overview

When you launch `npm run cli`, you will see a main menu with these categories:

| Category | Description |
|---|---|
| **Contract Deployment Wizard** | Guided deployment of all 5 contracts to any network |
| **DID Management** | Create, resolve, update, and deactivate W3C DIDs |
| **Credential Management** | Issue KYC/education/employment credentials, verify, revoke |
| **Reputation Management** | View scores, update transaction/credential reputation, trust graphs |
| **Zero-Knowledge Proofs** | Generate age/income/range proofs, selective disclosure |
| **Compliance & Screening** | Screen addresses, generate reports, FATF Travel Rule |
| **Configuration** | Network, RPC URL, contract addresses |
| **Keypair Manager** | Generate, import, and manage signing keypairs |

---

## Quick Start

### 1. Choose "Quick Start" from the opening menu

The Quick Start wizard:
1. Generates a new keypair for you
2. Creates your first DID (`did:stellar:<address>`)
3. Initializes your on-chain reputation

### 2. Deploy contracts (for a fresh network)

1. Open **Contract Deployment Wizard**
2. Choose **Deploy all contracts (guided wizard)**
3. Select your target network (`testnet` recommended for development)
4. Select your deployer keypair (generated in step 1)
5. Review the deployment plan and confirm

After deployment, contract addresses are automatically saved to your config file.

### 3. Issue your first credential

1. Open **Credential Management**
2. Choose **Issue KYC credential (guided)**
3. Fill in the KYC details step by step
4. The credential is issued and stored in your session

---

## Detailed Feature Reference

### Contract Deployment Wizard

| Option | Description |
|---|---|
| Deploy all contracts | Full guided deployment of all 5 Soroban contracts |
| Deploy individual contract | Deploy a single contract by selection |
| Check deployment status | View which contracts are deployed with addresses |
| Update contract address | Manually set a contract address |
| View contract addresses | Display all current addresses |
| Simulate deployment | Dry run with fee estimation (no broadcast) |
| Export deployment manifest | Save deployment info to a JSON file |

**Contracts deployed:**
- DID Registry (`did_registry`) — W3C DID lifecycle
- Credential Issuer (`credential_issuer`) — VC issuance and revocation
- Reputation Score (`reputation_score`) — On-chain scoring engine
- ZK Attestation (`zk_attestation`) — ZK proof storage
- Compliance Filter (`compliance_filter`) — Sanctions screening

---

### DID Management

| Option | Description |
|---|---|
| Create DID | Generate a `did:stellar:<address>` with verification methods and services |
| Resolve DID | Fetch and display the full DID Document |
| Update DID | Add/replace verification methods or service endpoints |
| Deactivate DID | Permanently tombstone a DID (irreversible) |
| Add/Remove authentication | Manage authentication method references |
| Check DID exists | Query on-chain existence |
| Get DID by controller | Look up DID from a Stellar address |
| Configure multi-sig | Set up m-of-n multi-signature control |
| Batch resolve DIDs | Resolve multiple DIDs in parallel |
| Validate DID format | Local format check without network call |

**DID format:** `did:stellar:G<base32-address>`

---

### Credential Management

| Option | Description |
|---|---|
| Issue credential | Generic credential with custom type and data |
| Issue KYC credential | Guided KYC form (name, DOB, nationality, document) |
| Issue education credential | Degree, institution, field of study, GPA |
| Issue employment credential | Employer, title, dates, optional salary |
| Verify credential | Check validity, revocation, and expiration |
| Revoke credential | Permanently mark as revoked with reason |
| Renew credential | Issue a new credential with updated expiry |
| Get credential details | Full credential data |
| Get credential status | `active` / `revoked` / `unknown` |
| Batch verify | Verify multiple credentials at once |
| Create presentation | Build a W3C Verifiable Presentation |

---

### Reputation Management

**Score range:** 0–1000

**Tiers:**
| Score | Tier | Description |
|---|---|---|
| 900+ | Prime | Deep history, verified credentials, strong network trust |
| 750–899 | Strong | Reliable profile suitable for governance and lending |
| 550–749 | Established | Moderate trust with room to grow |
| 300–549 | Emerging | Early-stage reputation |
| 0–299 | Seedling | New or lightly-used accounts |

| Option | Description |
|---|---|
| Initialize reputation | Create on-chain record with base score |
| Get score | Current score, tier, and percentile |
| Get breakdown | Full factor analysis with ASCII bar chart |
| Get history | Score timeline (configurable timeframe) |
| Update transaction reputation | +10 success / -5 failure |
| Update credential reputation | +20 valid / -15 invalid |
| Attest trust | Directional trust attestation (1–1000 weight) |
| Get trust graph | Aggregated trust at depth 1–4 |
| Compare reputations | Side-by-side comparison of two addresses |
| Check threshold | Boolean meets-threshold query |
| Calculate trend | Up/stable/down based on recent history |

---

### Zero-Knowledge Proofs

Proofs are generated locally using snarkjs circuits and submitted to the ZK Attestation contract on-chain.

| Option | Description |
|---|---|
| Age proof | Prove `age ≥ N` without revealing birth year |
| Income proof | Prove `income ≥ N` without revealing salary |
| Credential ownership | Prove you hold a credential without revealing contents |
| Range proof | Prove `min ≤ value ≤ max` |
| Greater-than proof | Prove `value > threshold` |
| Equality disclosure | Selectively reveal an exact attribute |
| KYC composite | Combined age + country + credential proof |
| Selective disclosure | Reveal specific fields, hide others with predicates |
| Combine disclosures | Merge multiple proofs into one |
| Register circuit | Register a custom Circom circuit on-chain |

**Privacy guarantee:** Verifiers learn only what is explicitly proven. Private inputs (birth year, income, etc.) are never revealed.

---

### Compliance & Screening

| Option | Description |
|---|---|
| Screen address | Single address against all active sanctions lists |
| Screen DID | Screen via DID (resolves to Stellar address) |
| Screen transaction | Full risk analysis including FATF Travel Rule check |
| Batch screen | Up to 50 addresses in one call |
| Compliance report | Full risk report for a DID over a timeframe |
| File regulatory report | Submit an immutable on-chain audit record |
| Prove compliance (ZK) | Generate ZK proof of `sanctions-clear` or `kyc-valid` |
| Update sanctions list | Register/update a list (admin only) |
| Manage list entries | Add/remove individual addresses |
| Register compliance rule | Set jurisdiction-specific rules (EU GDPR, FATF, etc.) |
| Risk assessment | Weighted score combining sanctions + oracle data |
| FATF Travel Rule | Build VASP-to-VASP information sharing payload |
| Subscribe alerts | Webhook for real-time risk monitoring |

**Travel Rule threshold:** $1,000 USD equivalent triggers FATF reporting requirements.

---

## Configuration

The CLI stores configuration at:
- **Linux/Mac:** `~/.stellar-identity-cli.json`
- **Windows:** `%USERPROFILE%\.stellar-identity-cli.json`

### Config file structure

```json
{
  "network": "testnet",
  "rpcUrl": "https://soroban-testnet.stellar.org",
  "contracts": {
    "didRegistry": "<64-char hex contract ID>",
    "credentialIssuer": "<64-char hex contract ID>",
    "reputationScore": "<64-char hex contract ID>",
    "zkAttestation": "<64-char hex contract ID>",
    "complianceFilter": "<64-char hex contract ID>"
  },
  "defaultKeypairLabel": "my-identity",
  "savedKeypairs": {
    "my-identity": {
      "label": "my-identity",
      "publicKey": "G...",
      "secretKeyHex": "<hex-encoded secret>"
    }
  }
}
```

> **Security note:** The config file contains secret key material. Keep it protected and never commit it to version control.

---

## Networks

| Network | RPC URL | Use case |
|---|---|---|
| testnet | `https://soroban-testnet.stellar.org` | Development and testing |
| futurenet | `https://rpc-futurenet.stellar.org` | Protocol preview features |
| mainnet | `https://soroban-rpc.stellar.org` | Production (real funds) |

Switch networks via **Configuration → Switch network**.

---

## Troubleshooting

### "No keypairs saved"
Use **Keypair Manager → Generate new keypair** before performing any signed operations.

### "Contract address not configured"
Either run the **Contract Deployment Wizard** or manually set addresses via **Configuration → Update contract addresses**.

### "RPC not reachable"
Check **Configuration → Check RPC health**. Verify your internet connection and the selected RPC URL.

### Running without ts-node
If `ts-node` is not installed, add it first:
```bash
npm install --save-dev ts-node@10.9.2
```

---

## Architecture

```
cli/
├── index.ts           Main CLI entry point
│   ├── mainMenu()     Top-level navigation
│   ├── deploymentWizard()   Contract deployment
│   ├── didMenu()      DID management commands
│   ├── credentialMenu()     Credential operations
│   ├── reputationMenu()     Reputation management
│   ├── zkMenu()       Zero-knowledge proofs
│   ├── complianceMenu()     Compliance screening
│   ├── configMenu()   Configuration management
│   └── keypairWizard()      Keypair management
└── tsconfig.json      CLI-specific TypeScript config
```

The CLI uses:
- Node.js built-in `readline` for interactive prompts (no extra dependencies)
- ANSI escape codes for colors, tables, and progress indicators
- `stellar-sdk` for keypair generation
- Local JSON config file for persistence
- In-memory session state for demo/test operations
