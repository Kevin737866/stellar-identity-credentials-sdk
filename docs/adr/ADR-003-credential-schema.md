# ADR-003: Credential Schema and Data Model

**Status**: Accepted  
**Date**: 2024-01-15

## Context

Verifiable Credentials require a schema definition so issuers, holders, and verifiers share a common understanding of credential fields. Schemas must be discoverable on-chain and versioned.

## Decision

Store schemas in a dedicated `CredentialSchemaRegistry` contract. Each schema is identified by a `Bytes` ID (SHA-256 of schema content) and contains:
- `id`: content-addressed identifier
- `issuer`: the Address that registered the schema
- `version`: monotonically increasing `u32`
- `definition`: JSON Schema encoded as `Bytes`
- `created` / `updated`: ledger timestamps

The `VerifiableCredential` struct (in `lib.rs`) holds an optional `schema_id` reference. `CredentialIssuer::issue_credential_with_schema` validates `credential_data` against the schema before storing.

**Credential data** is stored as opaque `Bytes` (JSON-encoded) to remain forward-compatible with new credential types without contract upgrades.

## Alternatives Considered

- **Embed schema in credential**: Bloats storage; every credential carries redundant schema data.
- **Off-chain schema registry**: Creates an external dependency that could become unavailable.

## Consequences

- ✅ Schema validation happens at issuance time, not verification time, reducing compute at queries.
- ✅ Content-addressed IDs make schema tampering detectable.
- ✅ Optional schema reference keeps the system backward-compatible.
- ⚠️ Schema updates require a new version; existing credentials reference the old schema ID.
