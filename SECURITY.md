# Security Policy

## Reporting a Vulnerability

The Stellar Identity team takes security seriously. We appreciate your efforts to responsibly disclose vulnerabilities.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to **security@stellar-identity.org**.

You should receive a response within 48 hours. If the issue is confirmed, we will release a patch as soon as possible depending on complexity.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Considerations

### Key Management
- **Never commit private keys** to the repository
- Use environment variables or secure key stores for sensitive data
- Rotate keys regularly in production environments
- Use hardware wallets for high-value accounts

### Contract Security
- All contracts include access controls and input validation
- Reentrancy protection is implemented where applicable
- Contract upgrades follow the governance process

### Privacy
- Zero-knowledge proofs are used for sensitive data
- Selective disclosure mechanisms protect user privacy
- GDPR compliance features are built into the SDK

### Dependency Management
- Dependencies are regularly audited with `npm audit` and `cargo audit`
- Critical vulnerabilities are patched within 7 days
- Lock files are committed to ensure reproducible builds

## Disclosure Policy

1. Reporter submits vulnerability to security@stellar-identity.org
2. Team acknowledges receipt within 48 hours
3. Team validates and assesses the vulnerability
4. A fix is developed and tested
5. A security advisory is published along with the patch
6. Credit is given to the reporter (unless anonymity is requested)

## Scope

Security vulnerabilities in the following areas are in scope:
- Smart contracts (Rust/Soroban)
- TypeScript SDK
- React UI components
- Zero-knowledge circuits
- CI/CD pipeline and deployment configurations

## Out of Scope
- Vulnerabilities in third-party dependencies (report to the upstream project)
- Social engineering attacks
- Physical security issues
- Denial of service attacks
