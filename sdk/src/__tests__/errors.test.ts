/**
 * Comprehensive tests for the SDK error handling system (issue #110).
 *
 * Covers:
 *  - All error classes and their properties
 *  - Error classification (errorClass, retryable, retryDelayMs)
 *  - Recovery hints on every error code
 *  - mapContractError — all resolution paths
 *  - mapErrorCode — every numeric code
 *  - Type guards and convenience builders
 *  - toJSON serialisation
 */

import {
  StellarIdentityError,
  DIDError,
  CredentialError,
  ReputationError,
  ZKProofError,
  ComplianceError,
  ConfigurationError,
  NetworkError,
  ValidationError,
  RateLimitError,
  ErrorCode,
  mapContractError,
  mapErrorCode,
  isDIDError,
  isCredentialError,
  isReputationError,
  isZKProofError,
  isComplianceError,
  isConfigurationError,
  isNetworkError,
  isValidationError,
  isRateLimitError,
  isRetryableError,
  missingField,
  fieldTooLong,
  invalidAddress,
  invalidDID,
  RECOVERY_HINTS,
} from '../errors';

// ─── StellarIdentityError base ────────────────────────────────────────────────

describe('StellarIdentityError', () => {
  it('stores code, message, and details', () => {
    const err = new StellarIdentityError(ErrorCode.DIDNotFound, 'Custom msg', { did: 'did:stellar:G' });
    expect(err.code).toBe(ErrorCode.DIDNotFound);
    expect(err.message).toBe('Custom msg');
    expect(err.details).toEqual({ did: 'did:stellar:G' });
  });

  it('uses first sentence of recovery hint as default message', () => {
    const err = new StellarIdentityError(ErrorCode.DIDAlreadyExists);
    expect(err.message.length).toBeGreaterThan(0);
  });

  it('exposes errorClass classification', () => {
    expect(new StellarIdentityError(ErrorCode.DIDNotFound).errorClass).toBe('contract');
    expect(new StellarIdentityError(ErrorCode.NetworkTimeout).errorClass).toBe('network');
    expect(new StellarIdentityError(ErrorCode.DIDInvalidFormat).errorClass).toBe('validation');
    expect(new StellarIdentityError(ErrorCode.DIDUnauthorized).errorClass).toBe('auth');
    expect(new StellarIdentityError(ErrorCode.RateLimitExceeded).errorClass).toBe('ratelimit');
  });

  it('exposes retryable flag correctly', () => {
    expect(new StellarIdentityError(ErrorCode.NetworkTimeout).retryable).toBe(true);
    expect(new StellarIdentityError(ErrorCode.NetworkConnectionFailed).retryable).toBe(true);
    expect(new StellarIdentityError(ErrorCode.DIDNotFound).retryable).toBe(false);
    expect(new StellarIdentityError(ErrorCode.DIDInvalidFormat).retryable).toBe(false);
    expect(new StellarIdentityError(ErrorCode.RateLimitExceeded).retryable).toBe(true);
  });

  it('exposes retryDelayMs hint for retryable errors', () => {
    expect(new StellarIdentityError(ErrorCode.NetworkConnectionFailed).retryDelayMs).toBe(1_000);
    expect(new StellarIdentityError(ErrorCode.RateLimitExceeded).retryDelayMs).toBe(60_000);
    expect(new StellarIdentityError(ErrorCode.DIDNotFound).retryDelayMs).toBe(0);
  });

  it('exposes recovery hint string', () => {
    const err = new StellarIdentityError(ErrorCode.DIDNotFound);
    expect(err.recovery).toBe(RECOVERY_HINTS[ErrorCode.DIDNotFound]);
    expect(err.recovery.length).toBeGreaterThan(10);
  });

  it('records a timestamp', () => {
    const before = Date.now();
    const err = new StellarIdentityError(ErrorCode.DIDNotFound);
    expect(err.timestamp).toBeGreaterThanOrEqual(before);
    expect(err.timestamp).toBeLessThanOrEqual(Date.now());
  });

  it('serialises to JSON with all fields', () => {
    const err = new DIDError(ErrorCode.DIDNotFound, 'msg', { x: 1 });
    const json = err.toJSON();
    expect(json.code).toBe(ErrorCode.DIDNotFound);
    expect(json.errorClass).toBe('contract');
    expect(json.retryable).toBe(false);
    expect(json.recovery).toBeTruthy();
    expect(json.message).toBe('msg');
    expect((json.details as Record<string, unknown>).x).toBe(1);
    expect(json.timestamp).toBeDefined();
  });

  it('is a proper Error instance', () => {
    const err = new StellarIdentityError(ErrorCode.DIDNotFound);
    expect(err).toBeInstanceOf(Error);
    expect(err.stack).toBeDefined();
  });
});

// ─── Domain error classes ─────────────────────────────────────────────────────

describe('domain error subclasses', () => {
  it('DIDError is instanceof StellarIdentityError', () => {
    const err = new DIDError(ErrorCode.DIDAlreadyExists);
    expect(err).toBeInstanceOf(StellarIdentityError);
    expect(err).toBeInstanceOf(DIDError);
    expect(err.name).toBe('DIDError');
  });

  it('CredentialError has correct name and class', () => {
    const err = new CredentialError(ErrorCode.CredentialExpired);
    expect(err.name).toBe('CredentialError');
    expect(err.errorClass).toBe('contract');
  });

  it('ReputationError has correct name', () => {
    expect(new ReputationError(ErrorCode.ReputationNotFound).name).toBe('ReputationError');
  });

  it('ZKProofError has correct name', () => {
    expect(new ZKProofError(ErrorCode.ZKInvalidProof).name).toBe('ZKProofError');
  });

  it('ComplianceError has correct name', () => {
    expect(new ComplianceError(ErrorCode.ComplianceAddressBlocked).name).toBe('ComplianceError');
  });

  it('ConfigurationError has validation errorClass', () => {
    const err = new ConfigurationError(ErrorCode.ConfigInvalidNetwork);
    expect(err.name).toBe('ConfigurationError');
    expect(err.errorClass).toBe('validation');
  });

  it('NetworkError has network errorClass and retryable=true for timeout', () => {
    const err = new NetworkError(ErrorCode.NetworkTimeout);
    expect(err.name).toBe('NetworkError');
    expect(err.errorClass).toBe('network');
    expect(err.retryable).toBe(true);
  });

  it('ValidationError has validation errorClass and retryable=false', () => {
    const err = new ValidationError(ErrorCode.ValidationInvalidAddress);
    expect(err.name).toBe('ValidationError');
    expect(err.errorClass).toBe('validation');
    expect(err.retryable).toBe(false);
  });

  it('RateLimitError has ratelimit errorClass and retryable=true', () => {
    const err = new RateLimitError(ErrorCode.RateLimitExceeded);
    expect(err.name).toBe('RateLimitError');
    expect(err.errorClass).toBe('ratelimit');
    expect(err.retryable).toBe(true);
  });
});

// ─── Recovery hints completeness ──────────────────────────────────────────────

describe('RECOVERY_HINTS', () => {
  it('every ErrorCode has a non-empty recovery hint', () => {
    const numericCodes = Object.values(ErrorCode).filter(v => typeof v === 'number') as number[];
    numericCodes.forEach(code => {
      const hint = RECOVERY_HINTS[code as ErrorCode];
      expect(hint).toBeTruthy();
      expect(hint.length).toBeGreaterThan(10);
    });
  });

  it('DID hints reference actionable steps', () => {
    expect(RECOVERY_HINTS[ErrorCode.DIDNotFound]).toContain('resolveDID()');
    expect(RECOVERY_HINTS[ErrorCode.DIDDeactivated]).toContain('deactivated');
    expect(RECOVERY_HINTS[ErrorCode.DIDRateLimitExceeded]).toContain('300 seconds');
  });

  it('network hints mention connection and RPC', () => {
    expect(RECOVERY_HINTS[ErrorCode.NetworkConnectionFailed]).toContain('rpcUrl');
    expect(RECOVERY_HINTS[ErrorCode.NetworkTimeout]).toContain('timeout');
    expect(RECOVERY_HINTS[ErrorCode.NetworkInsufficientFunds]).toContain('XLM');
  });

  it('credential hints reference issuer operations', () => {
    expect(RECOVERY_HINTS[ErrorCode.CredentialExpired]).toContain('renewCredential()');
    expect(RECOVERY_HINTS[ErrorCode.CredentialInvalidIssuer]).toContain('authorizeIssuer()');
  });

  it('compliance hints describe remediation steps', () => {
    expect(RECOVERY_HINTS[ErrorCode.ComplianceAddressBlocked]).toContain('sanctions');
    expect(RECOVERY_HINTS[ErrorCode.ComplianceBatchTooLarge]).toContain('50');
  });
});

// ─── Type guards ──────────────────────────────────────────────────────────────

describe('type guards', () => {
  it('isDIDError identifies DIDError only', () => {
    expect(isDIDError(new DIDError(ErrorCode.DIDNotFound))).toBe(true);
    expect(isDIDError(new CredentialError(ErrorCode.CredentialNotFound))).toBe(false);
    expect(isDIDError(null)).toBe(false);
    expect(isDIDError(new Error('plain'))).toBe(false);
  });

  it('isCredentialError identifies CredentialError only', () => {
    expect(isCredentialError(new CredentialError(ErrorCode.CredentialExpired))).toBe(true);
    expect(isCredentialError(new DIDError(ErrorCode.DIDNotFound))).toBe(false);
  });

  it('isReputationError identifies ReputationError', () => {
    expect(isReputationError(new ReputationError(ErrorCode.ReputationNotFound))).toBe(true);
  });

  it('isZKProofError identifies ZKProofError', () => {
    expect(isZKProofError(new ZKProofError(ErrorCode.ZKExpired))).toBe(true);
  });

  it('isComplianceError identifies ComplianceError', () => {
    expect(isComplianceError(new ComplianceError(ErrorCode.ComplianceHighRisk))).toBe(true);
  });

  it('isConfigurationError identifies ConfigurationError', () => {
    expect(isConfigurationError(new ConfigurationError(ErrorCode.ConfigInvalidNetwork))).toBe(true);
  });

  it('isNetworkError identifies NetworkError', () => {
    expect(isNetworkError(new NetworkError(ErrorCode.NetworkTimeout))).toBe(true);
    expect(isNetworkError(new DIDError(ErrorCode.DIDNotFound))).toBe(false);
  });

  it('isValidationError identifies ValidationError', () => {
    expect(isValidationError(new ValidationError(ErrorCode.ValidationInvalidAddress))).toBe(true);
    expect(isValidationError(new NetworkError(ErrorCode.NetworkTimeout))).toBe(false);
  });

  it('isRateLimitError identifies RateLimitError', () => {
    expect(isRateLimitError(new RateLimitError(ErrorCode.RateLimitExceeded))).toBe(true);
    expect(isRateLimitError(new NetworkError(ErrorCode.NetworkTimeout))).toBe(false);
  });

  it('isRetryableError returns true only for retryable errors', () => {
    expect(isRetryableError(new NetworkError(ErrorCode.NetworkTimeout))).toBe(true);
    expect(isRetryableError(new NetworkError(ErrorCode.NetworkConnectionFailed))).toBe(true);
    expect(isRetryableError(new RateLimitError(ErrorCode.RateLimitExceeded))).toBe(true);
    expect(isRetryableError(new DIDError(ErrorCode.DIDNotFound))).toBe(false);
    expect(isRetryableError(new ValidationError(ErrorCode.ValidationInvalidAddress))).toBe(false);
    expect(isRetryableError(null)).toBe(false);
  });
});

// ─── Convenience builders ─────────────────────────────────────────────────────

describe('convenience error builders', () => {
  it('missingField creates ValidationError with field name', () => {
    const err = missingField('credentialType');
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe(ErrorCode.ValidationMissingField);
    expect(err.message).toContain('credentialType');
    expect(err.details.fieldName).toBe('credentialType');
  });

  it('fieldTooLong includes limits in message and details', () => {
    const err = fieldTooLong('serviceEndpoint', 512, 600);
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe(ErrorCode.ValidationFieldTooLong);
    expect(err.message).toContain('512');
    expect(err.message).toContain('600');
    expect(err.details.maxLength).toBe(512);
    expect(err.details.actual).toBe(600);
  });

  it('invalidAddress creates ValidationError with address in message', () => {
    const err = invalidAddress('INVALID');
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe(ErrorCode.ValidationInvalidAddress);
    expect(err.message).toContain('INVALID');
  });

  it('invalidDID creates ValidationError with DID in message', () => {
    const err = invalidDID('bad:format');
    expect(err).toBeInstanceOf(ValidationError);
    expect(err.code).toBe(ErrorCode.ValidationInvalidDID);
    expect(err.message).toContain('bad:format');
  });
});

// ─── mapContractError ─────────────────────────────────────────────────────────

describe('mapContractError', () => {
  it('passes through existing StellarIdentityError unchanged', () => {
    const original = new DIDError(ErrorCode.DIDNotFound);
    expect(mapContractError(original)).toBe(original);
  });

  it('maps Soroban contract error format Error(Contract, #2) → DIDNotFound', () => {
    const err = mapContractError(new Error('Error(Contract, #2)'));
    expect(err).toBeInstanceOf(DIDError);
    expect(err.code).toBe(ErrorCode.DIDNotFound);
  });

  it('maps Soroban contract error #5 → DIDDeactivated', () => {
    const err = mapContractError(new Error('Error(Contract, #5)'));
    expect(err).toBeInstanceOf(DIDError);
    expect(err.code).toBe(ErrorCode.DIDDeactivated);
  });

  it('maps DIDRegistryError:NotFound named variant', () => {
    const err = mapContractError(new Error('Call failed: DIDRegistryError:NotFound'));
    expect(err).toBeInstanceOf(DIDError);
    expect(err.code).toBe(ErrorCode.DIDNotFound);
  });

  it('maps DIDRegistryError:Unauthorized named variant', () => {
    const err = mapContractError(new Error('DIDRegistryError:Unauthorized'));
    expect(err).toBeInstanceOf(DIDError);
    expect(err.code).toBe(ErrorCode.DIDUnauthorized);
  });

  it('maps DIDRegistryError:InvalidFormat named variant', () => {
    const err = mapContractError(new Error('DIDRegistryError:InvalidFormat'));
    expect(err).toBeInstanceOf(DIDError);
    expect(err.code).toBe(ErrorCode.DIDInvalidFormat);
  });

  it('maps CredentialIssuerError:Expired named variant', () => {
    const err = mapContractError(new Error('CredentialIssuerError:Expired'));
    expect(err).toBeInstanceOf(CredentialError);
    expect(err.code).toBe(ErrorCode.CredentialExpired);
  });

  it('maps CredentialIssuerError:AlreadyRevoked named variant', () => {
    const err = mapContractError(new Error('CredentialIssuerError:AlreadyRevoked'));
    expect(err).toBeInstanceOf(CredentialError);
    expect(err.code).toBe(ErrorCode.CredentialAlreadyRevoked);
  });

  it('maps ReputationScoreError:NotFound named variant', () => {
    const err = mapContractError(new Error('ReputationScoreError:NotFound'));
    expect(err).toBeInstanceOf(ReputationError);
    expect(err.code).toBe(ErrorCode.ReputationNotFound);
  });

  it('maps ZKAttestationError:NullifierAlreadyUsed named variant', () => {
    const err = mapContractError(new Error('ZKAttestationError:NullifierAlreadyUsed'));
    expect(err).toBeInstanceOf(ZKProofError);
    expect(err.code).toBe(ErrorCode.ZKNullifierAlreadyUsed);
  });

  it('maps ComplianceFilterError:AddressBlocked named variant', () => {
    const err = mapContractError(new Error('ComplianceFilterError:AddressBlocked'));
    expect(err).toBeInstanceOf(ComplianceError);
    expect(err.code).toBe(ErrorCode.ComplianceAddressBlocked);
  });

  it('maps ComplianceFilterError:HighRisk named variant', () => {
    const err = mapContractError(new Error('ComplianceFilterError:HighRisk'));
    expect(err).toBeInstanceOf(ComplianceError);
    expect(err.code).toBe(ErrorCode.ComplianceHighRisk);
  });

  it('maps timeout message → NetworkTimeout (retryable)', () => {
    const err = mapContractError(new Error('Request timed out after 5000ms'));
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe(ErrorCode.NetworkTimeout);
    expect(err.retryable).toBe(true);
  });

  it('maps fetch failed → NetworkConnectionFailed (retryable)', () => {
    const err = mapContractError(new Error('fetch failed: ECONNREFUSED'));
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe(ErrorCode.NetworkConnectionFailed);
    expect(err.retryable).toBe(true);
  });

  it('maps insufficient balance → NetworkInsufficientFunds (not retryable)', () => {
    const err = mapContractError(new Error('op_no_source_account: insufficient balance'));
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe(ErrorCode.NetworkInsufficientFunds);
    expect(err.retryable).toBe(false);
  });

  it('maps tx_bad_seq → NetworkSequenceMismatch (retryable)', () => {
    const err = mapContractError(new Error('tx_bad_seq: sequence mismatch'));
    expect(err).toBeInstanceOf(NetworkError);
    expect(err.code).toBe(ErrorCode.NetworkSequenceMismatch);
    expect(err.retryable).toBe(true);
  });

  it('maps rate_limit message → RateLimitError (retryable)', () => {
    const err = mapContractError(new Error('rate_limit exceeded for this account'));
    expect(err).toBeInstanceOf(RateLimitError);
    expect(err.retryable).toBe(true);
  });

  it('maps class name in message with fallback code', () => {
    const err = mapContractError(new Error('DIDRegistryError: unexpected internal error'));
    expect(err).toBeInstanceOf(DIDError);
  });

  it('attaches context to details when provided', () => {
    const err = mapContractError(new Error('fetch failed'), { operation: 'resolveDID' });
    expect(err.details.operation).toBe('resolveDID');
    expect(err.details.rawMessage).toBe('fetch failed');
  });

  it('handles non-Error string input', () => {
    const err = mapContractError('something went wrong');
    expect(err).toBeInstanceOf(StellarIdentityError);
  });

  it('handles null input gracefully', () => {
    const err = mapContractError(null);
    expect(err).toBeInstanceOf(StellarIdentityError);
  });
});

// ─── mapErrorCode ─────────────────────────────────────────────────────────────

describe('mapErrorCode', () => {
  it.each([
    [1,   DIDError,         ErrorCode.DIDAlreadyExists],
    [2,   DIDError,         ErrorCode.DIDNotFound],
    [3,   DIDError,         ErrorCode.DIDUnauthorized],
    [4,   DIDError,         ErrorCode.DIDInvalidFormat],
    [5,   DIDError,         ErrorCode.DIDDeactivated],
    [6,   DIDError,         ErrorCode.DIDInvalidSignature],
    [8,   DIDError,         ErrorCode.DIDRateLimitExceeded],
    [101, CredentialError,  ErrorCode.CredentialUnauthorized],
    [102, CredentialError,  ErrorCode.CredentialNotFound],
    [103, CredentialError,  ErrorCode.CredentialInvalid],
    [104, CredentialError,  ErrorCode.CredentialAlreadyRevoked],
    [105, CredentialError,  ErrorCode.CredentialExpired],
    [106, CredentialError,  ErrorCode.CredentialInvalidSignature],
    [107, CredentialError,  ErrorCode.CredentialInvalidIssuer],
    [201, ReputationError,  ErrorCode.ReputationAlreadyExists],
    [202, ReputationError,  ErrorCode.ReputationNotFound],
    [204, ReputationError,  ErrorCode.ReputationInvalidScore],
    [205, ReputationError,  ErrorCode.ReputationInvalidDepth],
    [301, ZKProofError,     ErrorCode.ZKInvalidProof],
    [305, ZKProofError,     ErrorCode.ZKVerificationFailed],
    [307, ZKProofError,     ErrorCode.ZKNullifierAlreadyUsed],
    [314, ZKProofError,     ErrorCode.ZKCombiningFailed],
    [401, ComplianceError,  ErrorCode.ComplianceAddressBlocked],
    [402, ComplianceError,  ErrorCode.ComplianceHighRisk],
    [407, ComplianceError,  ErrorCode.ComplianceInvalidHash],
  ])('code %i → %s with code %i', (rawCode, ExpectedClass, expectedCode) => {
    const err = mapErrorCode(rawCode);
    expect(err).not.toBeNull();
    expect(err).toBeInstanceOf(ExpectedClass);
    expect(err!.code).toBe(expectedCode);
  });

  it('returns null for unknown codes', () => {
    expect(mapErrorCode(0)).toBeNull();
    expect(mapErrorCode(999)).toBeNull();
    expect(mapErrorCode(9999)).toBeNull();
  });
});

// ─── ErrorCode uniqueness & domain ranges ─────────────────────────────────────

describe('ErrorCode enum', () => {
  it('has unique values — no duplicates', () => {
    const values = Object.values(ErrorCode).filter(v => typeof v === 'number') as number[];
    expect(new Set(values).size).toBe(values.length);
  });

  it('DID codes are in 1000–1999', () => {
    [ErrorCode.DIDAlreadyExists, ErrorCode.DIDNotFound, ErrorCode.DIDRateLimitExceeded].forEach(c => {
      expect(c).toBeGreaterThanOrEqual(1000);
      expect(c).toBeLessThan(2000);
    });
  });

  it('Credential codes are in 2000–2999', () => {
    [ErrorCode.CredentialUnauthorized, ErrorCode.CredentialRateLimitExceeded].forEach(c => {
      expect(c).toBeGreaterThanOrEqual(2000);
      expect(c).toBeLessThan(3000);
    });
  });

  it('Network codes are in 7000–7999', () => {
    [ErrorCode.NetworkConnectionFailed, ErrorCode.NetworkMaxRetriesExceeded].forEach(c => {
      expect(c).toBeGreaterThanOrEqual(7000);
      expect(c).toBeLessThan(8000);
    });
  });

  it('Validation codes are in 8000–8999', () => {
    [ErrorCode.ValidationInvalidAddress, ErrorCode.ValidationFieldTooLong].forEach(c => {
      expect(c).toBeGreaterThanOrEqual(8000);
      expect(c).toBeLessThan(9000);
    });
  });

  it('RateLimit codes are in 9000–9999', () => {
    [ErrorCode.RateLimitExceeded, ErrorCode.RateLimitWindowExpired].forEach(c => {
      expect(c).toBeGreaterThanOrEqual(9000);
      expect(c).toBeLessThan(10000);
    });
  });
});
