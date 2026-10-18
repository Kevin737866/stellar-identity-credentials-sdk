# Security Policy

## Reporting a Vulnerability

The Stellar Identity team takes security seriously. We appreciate your efforts to responsibly disclose vulnerabilities.

**Please do not report security vulnerabilities through public GitHub issues.**

### Preferred channel: GitHub Private Vulnerability Reporting

The primary reporting path is **[GitHub Private Vulnerability Reporting](https://github.com/Kevin737866/stellar-identity-credentials-sdk/security/advisories/new)** on this repository. Use the "Report a vulnerability" button on the Security tab to open a private advisory thread with the maintainers. This channel is hosted by GitHub and does not depend on any third-party infrastructure, so it is the path we can guarantee is monitored as long as the repository is active.

> **Maintainer note:** if the advisory form is not visible, enable
> *Settings → Security → Private vulnerability reporting* on the
> repository. A quarterly check (tracked alongside the release checklist)
> must confirm the form is still available and that a test advisory is
> received and acknowledged.

### Secondary channel: email

If you cannot use GitHub advisories, email **security@stellar-identity.org**.
This mailbox is provided for convenience; its availability has **not** been
independently verified by the current maintainers, so prefer the GitHub
channel above. If you receive no acknowledgement within 5 business days,
open a public GitHub issue asking for maintainer contact **without
disclosing vulnerability details**.

In either channel, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Affected component(s) and version(s)
- Any suggested mitigations

Acknowledgement targets (best-effort, volunteer-maintained — see below):

| Channel | Acknowledgement target |
|---|---|
| GitHub Private Vulnerability Reporting | 5 business days |
| Email (security@stellar-identity.org) | 5 business days (if delivered) |

Reports are triaged in the order received. You will receive status updates
as the investigation progresses; a report that is not acknowledged within
the target above should be re-sent through the other channel.

## Vulnerability Remediation Targets

The following are **targets**, not contractual SLAs; this project is
volunteer-maintained and remediation timing depends on severity,
availability of maintainers and the complexity of a fix.

| Severity | Acknowledgement target | Remediation target |
|---|---|---|
| Critical | 5 business days | Best effort — fix or mitigation first, advisory after |
| High | 5 business days | 30 days |
| Medium | 10 business days | Next minor release |
| Low | 10 business days | Best effort |

## Supported Versions

This project has **not yet published a tagged release**. There is therefore
no version range that receives security fixes today:

| Version | Supported |
|---|---|
| unreleased (master) | ⚠️ best effort only |

Once a release is tagged, this table will list concrete supported ranges
(for example `>= 0.2 < 0.3`) and the deprecation policy for older lines.

## Disclosure Policy

1. Reporter submits a vulnerability via GitHub Private Vulnerability Reporting (preferred) or email
2. Team acknowledges receipt (target: 5 business days)
3. Team validates and assesses the severity (Critical / High / Medium / Low)
4. A fix is developed, tested, and reviewed
5. A patch or mitigation is published along with a security advisory on GitHub
6. Credit is given to the reporter (unless anonymity is requested)
7. A post-mortem is published for Critical and High vulnerabilities when capacity allows

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
