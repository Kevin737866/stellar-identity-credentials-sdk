# Compliance Screening Automation

This document describes the automated compliance screening system that checks identities and credentials against sanctions lists, PEP lists, and adverse media.

## Overview

The compliance module (`sdk/src/compliance.ts` + `src/compliance_filter.rs`) provides:

- **Sanctions screening** — OFAC, EU, UN, and custom list checks
- **PEP screening** — Politically Exposed Persons detection
- **Adverse media screening** — negative news and risk signals
- **Configurable rules engine** — custom scoring thresholds and policies
- **Automated risk scoring** — aggregate 0–100 risk scores
- **Screening audit trail** — on-chain and off-chain audit logs
- **Result caching** — TTL-based caching to reduce redundant checks

## Quick Start

```typescript
import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';

const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

// Screen a single address
const result = await sdk.compliance.screenAddress(address);
console.log(result.status);    // 'clear' | 'suspicious' | 'blocked'
console.log(result.riskScore); // 0–100
console.log(result.matches);   // matched sanctions list sources
```

## Screening a Transaction

```typescript
const risk = await sdk.compliance.screenTransaction({
  txHash: '...',
  sender: senderAddress,
  receiver: receiverAddress,
  amount: '1000',
  asset: 'USDC',
});

if (risk.requiresTravelRule) {
  // Collect Travel Rule data per FATF guidelines
}

if (risk.overallRisk > 70) {
  // Block or escalate
}
```

## Compliance Reports

Generate a regulatory filing report for an address:

```typescript
const report = await sdk.compliance.generateComplianceReport(
  address,
  keypair,
  { includeHistory: true, format: 'json' }
);
```

## Real-Time Alerts

Subscribe to live risk alerts via webhook:

```typescript
const subscription = await sdk.compliance.subscribeToAlerts(
  address,
  keypair,
  { webhookUrl: 'https://your-app.com/compliance-webhook' }
);
```

## ZK Compliance Proofs

Prove compliance status without revealing the underlying data:

```typescript
const proof = await sdk.compliance.proveComplianceStatus(
  address,
  keypair,
  { minKycLevel: 1, maxRiskScore: 50 }
);
// Share proof with counterparty without revealing personal data
```

## On-Chain Screening Contract

The `ComplianceFilter` Soroban contract (`src/compliance_filter.rs`) provides:

### Sanctions List Management

```rust
// Add entries to a sanctions list (admin only)
ComplianceFilter::update_sanctions_list(env, admin, source, entries, jurisdiction)

// Screen an address on-chain
ComplianceFilter::screen_address(env, address)

// Get full screening result
ComplianceFilter::get_screening_result(env, address)
```

### Screening Rules Engine

Configure custom rules via the admin interface:

```rust
ComplianceFilter::set_screening_config(env, admin, config)
```

Where `config` controls:
- Risk score thresholds for each status tier
- Which list sources are active
- Cache TTL for screening results
- Jurisdictional filters

### Audit Trail

Every screening action is recorded on-chain:

```rust
// Get audit log for an address
ComplianceFilter::get_audit_log(env, address, page, page_size)
```

## Risk Scoring

The automated risk score (0–100) aggregates:

| Signal | Weight |
|--------|--------|
| Sanctions list match | High (immediate block) |
| PEP designation | Medium–High |
| Adverse media | Medium |
| Transaction pattern anomaly | Low–Medium |
| Credential validity | Low |

## Supported Data Providers

| Provider | Data Type |
|----------|-----------|
| OFAC SDN | Sanctions |
| EU Consolidated List | Sanctions |
| UN Security Council | Sanctions |
| World-Check (configurable) | PEP + Adverse Media |
| Chainalysis (configurable) | On-chain risk |
| Elliptic (configurable) | On-chain risk |

## Caching

Screening results are cached to avoid redundant checks:

```typescript
// Default TTL: 1 hour. Override per call:
const result = await sdk.compliance.screenAddress(address, { cacheTtlMs: 0 }); // bypass cache
```

## Testing

```bash
cargo test compliance  # on-chain contract tests
npm test -- compliance # SDK-level tests
```
