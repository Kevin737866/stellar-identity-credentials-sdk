# ADR-006: Compliance Screening Approach

**Status**: Accepted  
**Date**: 2024-01-15

## Context

DeFi and identity systems operating in regulated markets must screen participants against sanctions lists, perform risk assessments, and produce audit trails. This must integrate with the credential system without introducing censorship at the protocol level.

## Decision

The `ComplianceFilter` contract provides:
- **Sanctions screening**: Maintain an on-chain deny-list (admin-controlled) of sanctioned addresses. `is_sanctioned(address)` returns bool.
- **Risk scoring**: Composite risk score `[0–100]` derived from transaction patterns, jurisdiction, and credential status.
- **Compliance status**: Per-address `ComplianceStatus` (Approved / Pending / Rejected) set by authorized compliance officers.
- **Audit trail**: All compliance decisions are emitted as contract events and stored via `AuditTrail`.

**Integration**: Credential issuers can optionally call `ComplianceFilter::check_compliance` before issuing credentials. This is advisory; enforcement is left to the application layer to avoid protocol-level censorship.

## Alternatives Considered

- **Hard-block at credential issuance**: Too restrictive; legitimate use cases may require issuing credentials to entities under review.
- **Off-chain compliance only**: Provides no on-chain auditability; defeats the purpose of on-chain identity.
- **Oracle-fed sanctions list**: Better freshness but adds external dependencies and latency.

## Consequences

- ✅ On-chain audit trail provides non-repudiation.
- ✅ Compliance checks are advisory, preserving protocol neutrality.
- ✅ Risk scores enable nuanced decisions beyond binary allow/deny.
- ⚠️ Deny-list updates require admin transactions; there is a window between sanctions designation and on-chain update.
- ⚠️ Applications must actively call compliance checks; the contract does not enforce them automatically.
