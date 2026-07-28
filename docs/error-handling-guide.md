# Error Handling Guide — Stellar Identity SDK

This guide covers every aspect of error handling in the SDK: error codes, classifications, recovery hints, automatic retry, circuit breakers, and monitoring hooks.

---

## Table of contents

1. [Error anatomy](#1-error-anatomy)
2. [Error codes reference](#2-error-codes-reference)
3. [Error classification](#3-error-classification)
4. [Catching and inspecting errors](#4-catching-and-inspecting-errors)
5. [Type guards](#5-type-guards)
6. [Recovery hints](#6-recovery-hints)
7. [Automatic retry with exponential back-off](#7-automatic-retry-with-exponential-back-off)
8. [Circuit breaker](#8-circuit-breaker)
9. [Error monitoring hooks](#9-error-monitoring-hooks)
10. [External reporters (Sentry, Datadog, webhooks)](#10-external-reporters)
11. [Common scenarios and solutions](#11-common-scenarios-and-solutions)
12. [Convenience builders](#12-convenience-builders)
13. [Migrating from v0.x](#13-migrating-from-v0x)

---

## 1. Error anatomy

Every SDK error extends `StellarIdentityError`, which adds these properties on top of the standard `Error`:

```typescript
class StellarIdentityError extends Error {
  code: ErrorCode;          // Numeric code — use for programmatic branching
  errorClass: ErrorClass;   // 'network' | 'contract' | 'validation' | 'auth' | 'ratelimit' | 'unknown'
  retryable: boolean;       // true → safe to retry automatically
  retryDelayMs: number;     // minimum suggested delay before first retry (ms)
  recovery: string;         // human-readable hint about what to do next
  details: Record<string, unknown>; // structured debugging context
  timestamp: number;        // Unix ms when the error was created
  toJSON(): Record<string, unknown>; // serialize for logging
}
```

### Example

```typescript
try {
  await sdk.did.createDID(keypair, options);
} catch (err) {
  if (err instanceof StellarIdentityError) {
    console.error(`[${err.code}] ${err.message}`);
    console.info('Fix:', err.recovery);
    console.debug('Class:', err.errorClass, '| Retryable:', err.retryable);
    console.debug('Details:', JSON.stringify(err.details));
  }
}
```

---

## 2. Error codes reference

Codes are grouped by domain. Use the numeric code for programmatic matching, the class name for human-readable logs.

### DID errors (1xxx)

| Code | Name | Class | Retryable | Cause |
|------|------|-------|-----------|-------|
| 1001 | `DIDAlreadyExists` | contract | no | DID already on-chain |
| 1002 | `DIDNotFound` | contract | no | DID string not registered |
| 1003 | `DIDUnauthorized` | auth | no | Wrong keypair for controller |
| 1004 | `DIDInvalidFormat` | validation | no | DID does not start with `did:stellar:` |
| 1005 | `DIDDeactivated` | contract | no | DID has been tombstoned |
| 1006 | `DIDInvalidSignature` | auth | no | Ed25519 signature mismatch |
| 1007 | `DIDRateLimitExceeded` | ratelimit | **yes** | >5 creates per 300 s |
| 1008 | `DIDMultiSigThreshold` | contract | no | Not enough multi-sig approvals |

### Credential errors (2xxx)

| Code | Name | Class | Retryable | Cause |
|------|------|-------|-----------|-------|
| 2001 | `CredentialUnauthorized` | auth | no | Only issuer may revoke |
| 2002 | `CredentialNotFound` | contract | no | Bad credential ID |
| 2003 | `CredentialInvalid` | validation | no | Empty type or data >10 KB |
| 2004 | `CredentialAlreadyRevoked` | contract | no | Already revoked |
| 2005 | `CredentialExpired` | contract | no | Past `expirationDate` |
| 2006 | `CredentialInvalidSignature` | auth | no | Proof fails verification |
| 2007 | `CredentialInvalidIssuer` | auth | no | Issuer not authorised |
| 2008 | `CredentialSchemaNotFound` | contract | no | Schema ID not registered |
| 2009 | `CredentialSchemaInvalid` | validation | no | Data fails schema check |
| 2010 | `CredentialDelegationExpired` | contract | no | Delegation past `expires_at` |
| 2011 | `CredentialDelegationRevoked` | contract | no | Delegation revoked |
| 2012 | `CredentialLimitExceeded` | contract | no | Delegation issuance limit hit |
| 2013 | `CredentialRateLimitExceeded` | ratelimit | **yes** | >10 issues/min per issuer |

### Reputation errors (3xxx)

| Code | Name | Class | Retryable |
|------|------|-------|-----------|
| 3001 | `ReputationAlreadyExists` | contract | no |
| 3002 | `ReputationNotFound` | contract | no |
| 3003 | `ReputationUnauthorized` | auth | no |
| 3004 | `ReputationInvalidScore` | validation | no |
| 3005 | `ReputationInvalidDepth` | validation | no |
| 3006 | `ReputationNotInitialized` | contract | no |
| 3007 | `ReputationRateLimitExceeded` | ratelimit | **yes** |

### ZK Proof errors (4xxx) — codes 4001–4014

All ZK errors are `contract` class and non-retryable except where the underlying issue is transient. Re-generate the proof if verification fails.

### Compliance errors (5xxx)

| Code | Name | Class | Cause |
|------|------|-------|-------|
| 5001 | `ComplianceAddressBlocked` | contract | Address on active sanctions list |
| 5002 | `ComplianceHighRisk` | contract | Risk score >70 |
| 5008 | `ComplianceOracleNotRegistered` | auth | Oracle not in registered list |
| 5009 | `ComplianceBatchTooLarge` | validation | >50 addresses in one call |

### Network errors (7xxx) — retryable

| Code | Name | Retryable | Suggested delay |
|------|------|-----------|----------------|
| 7001 | `NetworkConnectionFailed` | **yes** | 1 s |
| 7002 | `NetworkTransactionFailed` | no | — |
| 7003 | `NetworkTimeout` | **yes** | 2 s |
| 7004 | `NetworkSimulationError` | no | — |
| 7005 | `NetworkInsufficientFunds` | no | — |
| 7006 | `NetworkSequenceMismatch` | **yes** | 0.5 s |
| 7007 | `NetworkLedgerClosed` | **yes** | 0.5 s |
| 7008 | `NetworkMaxRetriesExceeded` | no | — |

### Validation errors (8xxx) and Rate limit errors (9xxx)

Validation errors are never retryable — fix the input. Rate limit errors are retryable after the reset window.

---

## 3. Error classification

Use `errorClass` to route errors without pattern-matching individual codes:

```typescript
import { mapContractError, ErrorClass } from '@stellar-identity/sdk';

function handleSDKError(err: unknown): void {
  const error = mapContractError(err);

  switch (error.errorClass) {
    case 'network':
      // Transient — schedule retry
      scheduleRetry(error.retryDelayMs);
      break;
    case 'ratelimit':
      // Back off for the full window
      scheduleRetry(error.retryDelayMs);
      break;
    case 'auth':
      // Surface to user — check keypair
      showAuthError(error.message, error.recovery);
      break;
    case 'validation':
      // Fix input before retrying
      showValidationError(error.message, error.recovery);
      break;
    case 'contract':
      // Business logic error — inspect code
      handleContractError(error);
      break;
  }
}
```

---

## 4. Catching and inspecting errors

```typescript
import {
  StellarIdentityError,
  DIDError,
  CredentialError,
  NetworkError,
  ErrorCode,
  mapContractError,
} from '@stellar-identity/sdk';

try {
  const credId = await sdk.credentials.issueCredential(keypair, options);
} catch (raw) {
  // Normalise anything (plain Error, string, contract XDR) to a typed error
  const err = mapContractError(raw, { operation: 'issueCredential' });

  if (err.code === ErrorCode.CredentialInvalidIssuer) {
    // Specific code handling
    await sdk.credentials.authorizeIssuer(adminKeypair, keypair.publicKey());
    // retry...
  } else if (err.code === ErrorCode.CredentialExpired) {
    const newId = await sdk.credentials.renewCredential(keypair, expiredId, newExpiry, proof);
  } else {
    // Log full context and surface recovery hint
    logger.error('Credential issuance failed', err.toJSON());
    notifyUser(err.recovery);
    if (!err.retryable) throw err; // don't retry deterministic failures
  }
}
```

---

## 5. Type guards

Import domain-specific guards to narrow types without casting:

```typescript
import {
  isDIDError, isCredentialError, isNetworkError,
  isValidationError, isRateLimitError, isRetryableError,
} from '@stellar-identity/sdk';

catch (err) {
  if (isRetryableError(err)) {
    return retry(fn, { maxAttempts: 3, baseDelayMs: err.retryDelayMs });
  }
  if (isDIDError(err)) { /* DID-specific handling */ }
  if (isNetworkError(err)) { /* network-specific handling */ }
  if (isValidationError(err)) { /* show user the validation message */ }
  if (isRateLimitError(err)) { /* back off */ }
}
```

---

## 6. Recovery hints

Every error code has a detailed `recovery` string that explains exactly what to do next. Surface it in your UI or logs:

```typescript
catch (err) {
  if (err instanceof StellarIdentityError) {
    // For users
    showToast({ title: 'Operation failed', body: err.recovery });
    // For developers
    console.error(`[SDK ${err.code}] ${err.message}\n→ ${err.recovery}`);
  }
}
```

You can also access the full map directly:

```typescript
import { RECOVERY_HINTS, ErrorCode } from '@stellar-identity/sdk';
console.log(RECOVERY_HINTS[ErrorCode.DIDDeactivated]);
// "This DID has been permanently deactivated and cannot be updated.
//  Create a new DID for continued use."
```

---

## 7. Automatic retry with exponential back-off

`withRetry` wraps any async operation. It retries only when `error.retryable === true`, using exponential back-off with jitter.

### Basic usage

```typescript
import { withRetry } from '@stellar-identity/sdk';

const doc = await withRetry(
  () => sdk.did.resolveDID(did),
  {
    maxAttempts: 4,
    baseDelayMs: 1_000,
    operationName: 'resolveDID',
  },
);
```

### All options

```typescript
interface RetryOptions {
  maxAttempts?: number;       // Total attempts including first (default 3)
  baseDelayMs?: number;       // Delay before attempt 2 (default 500 ms)
  backoffMultiplier?: number; // Multiplier per attempt (default 2×)
  maxDelayMs?: number;        // Hard cap on delay (default 30 s)
  jitterFactor?: number;      // ±jitter as fraction of delay (default 0.25)
  operationName?: string;     // Used in error messages and onRetry callback
  onRetry?: (ctx: RetryContext) => void;  // Log / monitor each retry
  notifyOnNonRetryable?: boolean; // Call onRetry for non-retryable errors too
}
```

### Retry with logging

```typescript
import { withRetry, ErrorMonitor } from '@stellar-identity/sdk';

const result = await withRetry(
  () => sdk.reputation.getReputationScore(address),
  {
    maxAttempts: 3,
    operationName: 'getReputationScore',
    onRetry: ({ attempt, error, delayMs, operation }) => {
      console.warn(
        `[${operation}] attempt ${attempt} after ${delayMs}ms — ${error.message}`,
      );
      ErrorMonitor.global().capture(error, 'reputation', operation);
    },
  },
);
```

### Delay formula

```
delay = min(maxDelay, base × multiplier^(attempt-1)) ± jitter
delay = max(delay, error.retryDelayMs)   // honour error's suggested wait
```

Example with defaults (`base=500, mult=2, max=30 000`):

| Attempt | Computed delay |
|---------|---------------|
| 2 (after attempt 1 fails) | ~500 ms |
| 3 | ~1 000 ms |
| 4 | ~2 000 ms |
| 5+ | capped at 30 000 ms |

---

## 8. Circuit breaker

The circuit breaker prevents cascading failures when an RPC endpoint is persistently unavailable.

```typescript
import { CircuitBreaker, withRetryAndCircuitBreaker } from '@stellar-identity/sdk';

// Create once per RPC endpoint
const rpcBreaker = new CircuitBreaker('soroban-rpc', {
  failureThreshold: 5,     // Open after 5 consecutive failures
  successThreshold: 2,     // Close again after 2 consecutive successes
  resetTimeoutMs: 60_000,  // Try again after 60 s
  onStateChange: (from, to, name) => {
    metrics.gauge(`circuit.${name}`, to === 'open' ? 1 : 0);
  },
});

// Use with retry
const doc = await withRetryAndCircuitBreaker(
  () => sdk.did.resolveDID(did),
  rpcBreaker,
  { maxAttempts: 3, operationName: 'resolveDID' },
);
```

### Circuit states

| State | Behaviour |
|-------|-----------|
| `closed` | Normal operation — failures counted |
| `open` | All calls fail immediately with `NetworkConnectionFailed` |
| `half-open` | Trial call allowed — success closes circuit, failure re-opens it |

---

## 9. Error monitoring hooks

Subscribe to error events globally or by domain/code/class without modifying call sites.

### Global hook

```typescript
import { ErrorMonitor } from '@stellar-identity/sdk';

const monitor = ErrorMonitor.global();

// Subscribe to all errors
const unsub = monitor.onError(event => {
  myLogger.error('[SDK Error]', {
    code: event.code,
    class: event.errorClass,
    message: event.message,
    recovery: event.recovery,
    domain: event.domain,
    operation: event.operation,
  });
});

// Later, clean up
unsub();
```

### Per-class hook

```typescript
monitor.onErrorClass('network', event => {
  metrics.increment('sdk.network_errors', { code: event.code });
});

monitor.onErrorClass('ratelimit', event => {
  alertOncall('Rate limit hit', event.message);
});
```

### Per-code hook

```typescript
monitor.onErrorCode(ErrorCode.ComplianceAddressBlocked, event => {
  auditLog.warn('Blocked address detected', event.details);
});
```

### Per-domain hook

```typescript
monitor.onDomain('credentialClient', event => {
  credentialMetrics.increment(event.name);
});
```

### Capturing errors from SDK clients

Call `monitor.capture()` inside your `onRetry` or catch blocks:

```typescript
import { ErrorMonitor, mapContractError } from '@stellar-identity/sdk';

async function createDIDWithMonitoring(keypair, options) {
  try {
    return await sdk.did.createDID(keypair, options);
  } catch (raw) {
    const err = mapContractError(raw, { operation: 'createDID' });
    ErrorMonitor.global().capture(err, 'didClient', 'createDID');
    throw err;
  }
}
```

### Reading history and stats

```typescript
const monitor = ErrorMonitor.global();

// Recent 10 errors
monitor.getRecentErrors(10).forEach(e =>
  console.log(`[${e.id}] ${e.name}: ${e.message}`)
);

// Aggregated stats
const stats = monitor.getStats();
console.log('Total errors:',   stats.total);
console.log('By class:',       stats.byClass);
console.log('By domain:',      stats.byDomain);
```

---

## 10. External reporters

Implement `ErrorReporter` to send errors to an external service:

```typescript
import { ErrorReporter, ErrorEvent, ErrorMonitor } from '@stellar-identity/sdk';

class SentryReporter implements ErrorReporter {
  report(event: ErrorEvent): void {
    Sentry.captureException(new Error(event.message), {
      tags: { code: event.code, errorClass: event.errorClass },
      extra: event.details,
      fingerprint: [String(event.code)],
    });
  }
}

class DatadogReporter implements ErrorReporter {
  report(event: ErrorEvent): void {
    datadog.increment('sdk.errors', 1, [
      `code:${event.code}`,
      `class:${event.errorClass}`,
      `domain:${event.domain}`,
    ]);
  }
}

ErrorMonitor.global().addReporter(new SentryReporter());
ErrorMonitor.global().addReporter(new DatadogReporter());
```

---

## 11. Common scenarios and solutions

### DID not found

```typescript
import { isDIDError, ErrorCode } from '@stellar-identity/sdk';

catch (err) {
  if (isDIDError(err) && err.code === ErrorCode.DIDNotFound) {
    // Create a new DID instead
    const did = await sdk.did.createDID(keypair, defaultOptions);
  }
}
```

### Credential expired — auto-renew

```typescript
import { isCredentialError, ErrorCode } from '@stellar-identity/sdk';

catch (err) {
  if (isCredentialError(err) && err.code === ErrorCode.CredentialExpired) {
    const newExpiry = Date.now() + 365 * 24 * 60 * 60 * 1000;
    const newProof  = await generateProof(credentialData, keypair);
    const newId     = await sdk.credentials.renewCredential(
      keypair, expiredCredentialId, newExpiry, newProof,
    );
  }
}
```

### Sequence mismatch — refresh account and retry

```typescript
import { withRetry, isNetworkError, ErrorCode } from '@stellar-identity/sdk';

const result = await withRetry(
  () => sdk.did.createDID(freshKeypair, options),
  {
    maxAttempts: 3,
    operationName: 'createDID',
    onRetry: async ({ error }) => {
      if (isNetworkError(error) && error.code === ErrorCode.NetworkSequenceMismatch) {
        // Refresh account before next attempt
        await refreshAccount(keypair.publicKey());
      }
    },
  },
);
```

### Rate limit — respect the backoff window

```typescript
import { isRateLimitError } from '@stellar-identity/sdk';

catch (err) {
  if (isRateLimitError(err)) {
    const waitMs = err.retryDelayMs; // 60 000 ms typically
    console.warn(`Rate limited. Retrying in ${waitMs / 1000}s.`);
    await sleep(waitMs);
    return retry();
  }
}
```

### Compliance block — escalate to human review

```typescript
import { isComplianceError, ErrorCode } from '@stellar-identity/sdk';

catch (err) {
  if (isComplianceError(err)) {
    if (err.code === ErrorCode.ComplianceAddressBlocked) {
      await complianceQueue.escalate({
        address, reason: err.message, recovery: err.recovery,
      });
      return { status: 'blocked', message: err.recovery };
    }
    if (err.code === ErrorCode.ComplianceHighRisk) {
      return { status: 'review', message: err.recovery };
    }
  }
}
```

### Network error — retry with circuit breaker and monitoring

```typescript
import {
  CircuitBreaker, withRetryAndCircuitBreaker,
  ErrorMonitor, isNetworkError,
} from '@stellar-identity/sdk';

const rpcBreaker = new CircuitBreaker('rpc');
const monitor    = ErrorMonitor.global();

monitor.onErrorClass('network', e =>
  console.warn(`Network error [${e.code}]: ${e.message}`)
);

async function robustResolveDID(did: string) {
  return withRetryAndCircuitBreaker(
    () => sdk.did.resolveDID(did),
    rpcBreaker,
    {
      maxAttempts: 4,
      baseDelayMs: 1_000,
      operationName: 'resolveDID',
      onRetry: ({ attempt, error }) =>
        monitor.capture(error, 'didClient', 'resolveDID'),
    },
  );
}
```

---

## 12. Convenience builders

Create typed validation errors without constructing them manually:

```typescript
import { missingField, fieldTooLong, invalidAddress, invalidDID } from '@stellar-identity/sdk';

function validateCreateDIDInput(address: string, didStr: string, endpoint: string) {
  if (!address) throw missingField('address');
  if (!address.startsWith('G')) throw invalidAddress(address);
  if (!didStr.startsWith('did:stellar:')) throw invalidDID(didStr);
  if (endpoint.length > 512) throw fieldTooLong('endpoint', 512, endpoint.length);
}
```

---

## 13. Migrating from v0.x

### New exports

The following are new in v0.2 (issue #110):

```typescript
// New error classes
ValidationError, RateLimitError

// New type guards
isValidationError(), isRateLimitError(), isRetryableError()

// New error builders
missingField(), fieldTooLong(), invalidAddress(), invalidDID()

// New properties on all errors
error.errorClass    // 'network' | 'contract' | 'validation' | 'auth' | 'ratelimit' | 'unknown'
error.retryable     // boolean
error.retryDelayMs  // number
error.recovery      // string — recovery hint
error.timestamp     // number — Unix ms
error.toJSON()      // serializable snapshot

// Retry engine
withRetry(), calculateDelay(), CircuitBreaker, withRetryAndCircuitBreaker

// Monitoring
ErrorMonitor, ConsoleErrorReporter, NoOpErrorReporter
RECOVERY_HINTS
```

### Changed behaviour

- `mapContractError()` now accepts an optional second argument `context` attached to `error.details`.
- `StellarIdentityError` default message is now the first sentence of the recovery hint instead of a bare code name.
- New error codes added: `DIDRateLimitExceeded` (1007), `DIDMultiSigThreshold` (1008), `CredentialSchemaNotFound` (2008)–`CredentialRateLimitExceeded` (2013), `ReputationNotInitialized` (3006)–`ReputationRateLimitExceeded` (3007), `NetworkInsufficientFunds` (7005)–`NetworkMaxRetriesExceeded` (7008), all 8xxx validation codes, and 9xxx rate limit codes.

### Backward compatibility

- All existing error classes (`DIDError`, `CredentialError`, etc.) are unchanged.
- All existing `ErrorCode` values are unchanged — no existing codes were renumbered.
- `mapContractError(error)` still works without the second argument.
- `mapErrorCode(n)` still returns `null` for unknown codes.
- All existing type guards (`isDIDError`, `isCredentialError`, etc.) still work.
