# Contributing to Stellar Identity SDK

Thank you for your interest in contributing to the Stellar Identity and Verifiable Credentials SDK! This guide will help you get started with development.

## Development Environment Prerequisites

- **Rust 1.70+**: Required for Soroban smart contract development
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js 18+**: Required for SDK and UI package development
  ```bash
  nvm install 18
  nvm use 18
  ```
- **Stellar CLI**: For contract deployment and testing
  ```bash
  cargo install --locked stellar-cli --features opt
  ```
- **Circom**: For zero-knowledge circuit compilation
  ```bash
  # Follow instructions at https://docs.circom.io/getting-started/installation/
  ```

## Local Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/Kevin737866/stellar-identity-credentials-sdk.git
cd stellar-identity-credentials-sdk

# 2. Install Rust dependencies
cargo build

# 3. Install Node.js dependencies
npm install
cd ui && npm install && cd ..

# 4. Build contracts
cargo build --target wasm32-unknown-unknown --release

# 5. Build SDK
npm run build

# 6. Build UI components
cd ui && npm run build && cd ..
```

## Available Scripts

### Root Level
| Script | Description |
|--------|-------------|
| `npm run build` | Build the TypeScript SDK |
| `npm test` | Run SDK tests |
| `npm run lint` | Lint TypeScript code |
| `cargo build` | Build Rust contracts |
| `cargo test` | Run contract tests |
| `cargo fmt` | Format Rust code |
| `cargo clippy` | Lint Rust code |

### UI Package (`ui/` directory)
| Script | Description |
|--------|-------------|
| `npm run build` | Build UI components |
| `npm test` | Run UI component tests |
| `npm run lint` | Lint UI component code |

### Circuits (`circuits/` directory)
| Script | Description |
|--------|-------------|
| `npm run build` | Compile Circom circuits |
| `npm test` | Run circuit tests |

## Coding Standards and Conventions

### TypeScript/JavaScript
- Use TypeScript for all SDK and UI code
- Follow existing patterns in the codebase
- Use `const` and `let` (never `var`)
- Prefer `async/await` over raw Promises
- Use explicit types (avoid `any` unless absolutely necessary)
- Use functional components and hooks for React code
- Run `npm run lint` before committing

### Rust
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `soroban-sdk` conventions for contract development
- All public functions must have documentation comments (`///`)
- Run `cargo fmt` and `cargo clippy` before committing

### Git
- Write clear, descriptive commit messages
- Reference issue numbers in commits when applicable

## Pull Request Workflow

1. **Fork the repository** and create a feature branch from `master`
2. **Branch naming convention**: `feat/issue-{number}-{short-description}` or `fix/issue-{number}-{short-description}`
3. **Make your changes** following the coding standards above
4. **Add tests** for new functionality
5. **Run all tests** to ensure nothing is broken:
   ```bash
   cargo test
   npm test
   cd ui && npm test && cd ..
   cd circuits && npm test && cd ..
   ```
6. **Commit** with a descriptive message
7. **Submit a pull request** against the `master` branch

### Commit Message Format
```
feat|fix|docs|test|refactor|chore: <description>

- Detailed bullet points for complex changes
```

### Pull Request Checklist
- [ ] Code follows project conventions
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated (if applicable)
- [ ] No linting or formatting errors

## Testing Guidelines

### SDK Tests
- Write unit tests in `sdk/src/__tests__/` directory
- Test both success and error cases
- Mock external dependencies (stellar-sdk, network calls)
- Aim for >80% coverage on new code

### UI Component Tests
- Write tests in `ui/src/components/__tests__/` directory
- Use `@testing-library/react` for component tests
- Test rendering, user interactions, and edge cases

### Contract Tests
- Write tests in `src/` directory (Rust integration tests)
- Use `soroban-sdk` test utilities
- Test all public contract functions

### Circuit Tests
- Test proof generation and verification
- Test edge cases and invalid inputs

## Code Quality Gates

To maintain high code quality, CI enforces the following automated gates:

| Gate                     | Threshold                | Enforcement Tool       |
|--------------------------|--------------------------|------------------------|
| Test coverage (Rust)     | ≥ 80%                    | `cargo-tarpaulin`      |
| Test coverage (TS SDK)   | ≥ 80%                    | Jest coverage          |
| Cyclomatic complexity    | ≤ 15 per function        | ESLint / Clippy        |
| Function length          | ≤ 100 lines per function | ESLint / `scripts/check-rust-fn-length.py` |

Failing any of these gates will block CI and prevent merging.

### Waiver Process

In exceptional cases where a code quality gate cannot be reasonably satisfied, a waiver may be requested:

1. **Open an issue** with the title `waiver: <gate-name> for <file/function>` (e.g., `waiver: complexity for zk_attestation::verify_proof`)
2. **Justify the exception** in the issue body:
   - Which specific gate is being waived and why it cannot be met
   - Why the code is still correct and maintainable despite the violation
   - What alternative safeguards (if any) are in place (e.g., extensive tests, peer review)
   - Proposed remediation plan (e.g., refactor in a future PR)
3. **Obtain approval** from at least one maintainer
4. **Reference the waiver** in the affected code using a comment:
   ```rust
   // WAIVER: complexity (#123) - ZK proof verification is inherently complex.
   // Approved by @maintainer on YYYY-MM-DD. Revisit by YYYY-MM-DD.
   ```
   ```typescript
   // WAIVER: max-lines-per-function (#456) - State machine transition logic.
   // Approved by @maintainer on YYYY-MM-DD. Revisit by YYYY-MM-DD.
   ```
5. **Add a waiver expiry date** (maximum 6 months). All waivers must be revisited before expiring.

### CI Bypass

Waivers do **not** mean the CI check is skipped. Instead:
- The lint error is suppressed via inline comment (e.g., `#[allow(clippy::cognitive_complexity)]` in Rust or `// eslint-disable-next-line complexity` in TypeScript)
- The inline suppression must reference the waiver issue number
- This keeps CI green while documenting the intentional exception

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.

## Questions?

- Open an issue on GitHub
- Join our [Discord](https://discord.gg/stellar-identity)
- Email: support@stellar-identity.org
# Contributing to Stellar Identity SDK

Thank you for your interest in contributing to the Stellar Identity and Verifiable Credentials SDK! This guide will help you get started with development.

## Development Environment Prerequisites

- **Rust 1.70+**: Required for Soroban smart contract development
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **Node.js 18+**: Required for SDK and UI package development
  ```bash
  nvm install 18
  nvm use 18
  ```
- **Stellar CLI**: For contract deployment and testing
  ```bash
  cargo install --locked stellar-cli --features opt
  ```
- **Circom**: For zero-knowledge circuit compilation
  ```bash
  # Follow instructions at https://docs.circom.io/getting-started/installation/
  ```

## Local Development Setup

```bash
# 1. Clone the repository
git clone https://github.com/Kevin737866/stellar-identity-credentials-sdk.git
cd stellar-identity-credentials-sdk

# 2. Install Rust dependencies
cargo build

# 3. Install Node.js dependencies
npm install
cd ui && npm install && cd ..

# 4. Build contracts
cargo build --target wasm32-unknown-unknown --release

# 5. Build SDK
npm run build

# 6. Build UI components
cd ui && npm run build && cd ..
```

## Available Scripts

### Root Level
| Script | Description |
|--------|-------------|
| `npm run build` | Build the TypeScript SDK |
| `npm test` | Run SDK tests |
| `npm run lint` | Lint TypeScript code |
| `cargo build` | Build Rust contracts |
| `cargo test` | Run contract tests |
| `cargo fmt` | Format Rust code |
| `cargo clippy` | Lint Rust code |

### UI Package (`ui/` directory)
| Script | Description |
|--------|-------------|
| `npm run build` | Build UI components |
| `npm test` | Run UI component tests |
| `npm run lint` | Lint UI component code |

### Circuits (`circuits/` directory)
| Script | Description |
|--------|-------------|
| `npm run build` | Compile Circom circuits |
| `npm test` | Run circuit tests |

## Coding Standards and Conventions

### TypeScript/JavaScript
- Use TypeScript for all SDK and UI code
- Follow existing patterns in the codebase
- Use `const` and `let` (never `var`)
- Prefer `async/await` over raw Promises
- Use explicit types (avoid `any` unless absolutely necessary)
- Use functional components and hooks for React code
- Run `npm run lint` before committing

### Rust
- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `soroban-sdk` conventions for contract development
- All public functions must have documentation comments (`///`)
- Run `cargo fmt` and `cargo clippy` before committing

### Git
- Write clear, descriptive commit messages
- Reference issue numbers in commits when applicable

## Pull Request Workflow

1. **Fork the repository** and create a feature branch from `master`
2. **Branch naming convention**: `feat/issue-{number}-{short-description}` or `fix/issue-{number}-{short-description}`
3. **Make your changes** following the coding standards above
4. **Add tests** for new functionality
5. **Run all tests** to ensure nothing is broken:
   ```bash
   cargo test
   npm test
   cd ui && npm test && cd ..
   cd circuits && npm test && cd ..
   ```
6. **Commit** with a descriptive message
7. **Submit a pull request** against the `master` branch

### Commit Message Format
```
feat|fix|docs|test|refactor|chore: <description>

- Detailed bullet points for complex changes
```

### Pull Request Checklist
- [ ] Code follows project conventions
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated (if applicable)
- [ ] No linting or formatting errors

## Testing Guidelines

### SDK Tests
- Write unit tests in `sdk/src/__tests__/` directory
- Test both success and error cases
- Mock external dependencies (stellar-sdk, network calls)
- Aim for >80% coverage on new code

### UI Component Tests
- Write tests in `ui/src/components/__tests__/` directory
- Use `@testing-library/react` for component tests
- Test rendering, user interactions, and edge cases

### Contract Tests
- Write tests in `src/` directory (Rust integration tests)
- Use `soroban-sdk` test utilities
- Test all public contract functions

### Circuit Tests
- Test proof generation and verification
- Test edge cases and invalid inputs

## Code Quality Gates

To maintain high code quality, CI enforces the following automated gates:

| Gate                     | Threshold                | Enforcement Tool       |
|--------------------------|--------------------------|------------------------|
| Test coverage (Rust)     | ≥ 80%                    | `cargo-tarpaulin`      |
| Test coverage (TS SDK)   | ≥ 80%                    | Jest coverage          |
| Cyclomatic complexity    | ≤ 15 per function        | ESLint / Clippy        |
| Function length          | ≤ 100 lines per function | ESLint / `scripts/check-rust-fn-length.py` |

Failing any of these gates will block CI and prevent merging.

### Waiver Process

In exceptional cases where a code quality gate cannot be reasonably satisfied, a waiver may be requested:

1. **Open an issue** with the title `waiver: <gate-name> for <file/function>` (e.g., `waiver: complexity for zk_attestation::verify_proof`)
2. **Justify the exception** in the issue body:
   - Which specific gate is being waived and why it cannot be met
   - Why the code is still correct and maintainable despite the violation
   - What alternative safeguards (if any) are in place (e.g., extensive tests, peer review)
   - Proposed remediation plan (e.g., refactor in a future PR)
3. **Obtain approval** from at least one maintainer
4. **Reference the waiver** in the affected code using a comment:
   ```rust
   // WAIVER: complexity (#123) - ZK proof verification is inherently complex.
   // Approved by @maintainer on YYYY-MM-DD. Revisit by YYYY-MM-DD.
   ```
   ```typescript
   // WAIVER: max-lines-per-function (#456) - State machine transition logic.
   // Approved by @maintainer on YYYY-MM-DD. Revisit by YYYY-MM-DD.
   ```
5. **Add a waiver expiry date** (maximum 6 months). All waivers must be revisited before expiring.

### CI Bypass

Waivers do **not** mean the CI check is skipped. Instead:
- The lint error is suppressed via inline comment (e.g., `#[allow(clippy::cognitive_complexity)]` in Rust or `// eslint-disable-next-line complexity` in TypeScript)
- The inline suppression must reference the waiver issue number
- This keeps CI green while documenting the intentional exception

## Code of Conduct

Please note that this project is released with a [Contributor Code of Conduct](CODE_OF_CONDUCT.md). By participating in this project, you agree to abide by its terms.

## Questions?

- Open an issue on GitHub
- Join our [Discord](https://discord.gg/stellar-identity)
- Email: support@stellar-identity.org
