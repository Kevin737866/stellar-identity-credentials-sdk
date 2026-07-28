# Security Policy

## Reporting a Vulnerability

The Stellar Identity team takes security seriously. We appreciate your efforts to responsibly disclose vulnerabilities.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@stellar-identity.org** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component(s) and version(s)
- Any suggested mitigations

You will receive an acknowledgement within **24 hours**. Updates on the investigation will be provided every 48 hours until the issue is resolved.

## Vulnerability Remediation SLA

| Severity | Acknowledgement | Remediation |
|---|---|---|
| Critical | 24 hours | 24 hours |
| High | 24 hours | 7 days |
| Medium | 48 hours | 30 days |
| Low | 48 hours | Next release |

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Disclosure Policy

1. Reporter submits vulnerability to security@stellar-identity.org
2. Team acknowledges receipt within 24 hours
3. Team validates and assesses the severity (Critical / High / Medium / Low)
4. A fix is developed, tested, and reviewed
5. A patch release is published along with a security advisory on GitHub
6. Credit is given to the reporter (unless anonymity is requested)
7. A post-mortem is published for Critical and High vulnerabilities within 30 days

## Security Audit Checklist

A comprehensive security audit checklist covering all five Soroban contracts is maintained at [`docs/security-audit-checklist.md`](docs/security-audit-checklist.md). This checklist must be reviewed and signed off by two security team members before any mainnet deployment.

## Automated Security Scanning

Security scanning runs automatically on every pull request via the [`security.yml`](.github/workflows/security.yml) CI workflow:

- **cargo audit** — Rust dependency vulnerability scanning
- **npm audit** — Node.js dependency vulnerability scanning
- **GitHub CodeQL** — Static analysis for TypeScript and Rust
- **Clippy** — Rust linting with `-D warnings`

Vulnerability reports are published as CI artifacts for every run.

## Security Considerations

### Key Management
- Never commit private keys to the repository
- Use environment variables or secure key stores for sensitive data
- Rotate keys regularly in production environments
- Use hardware wallets for high-value accounts

### Contract Security
- All contracts include access controls and input validation
- Reentrancy protection is implemented where applicable
- Contract upgrades follow the governance process with a minimum 48-hour timelock

### Privacy
- Zero-knowledge proofs are used for sensitive data
- Selective disclosure mechanisms protect user privacy
- GDPR compliance features are built into the SDK

### Dependency Management
- Dependencies are scanned with `npm audit` and `cargo audit` on every PR
- Lock files are committed to ensure reproducible builds

## Scope

Security vulnerabilities in the following areas are in scope:

- Smart contracts (Rust/Soroban): `src/did_registry.rs`, `src/credential_issuer.rs`, `src/reputation_score.rs`, `src/zk_attestation.rs`, `src/compliance_filter.rs`
- TypeScript SDK (`sdk/src/`)
- React UI components (`ui/src/`)
- Zero-knowledge circuits (`circuits/`)
- CI/CD pipeline and deployment configurations (`.github/workflows/`)

## Out of Scope

- Vulnerabilities in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Physical security issues
- Denial-of-service attacks against public infrastructure
