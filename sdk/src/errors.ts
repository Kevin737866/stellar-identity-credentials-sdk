/**
 * Error handling for the Stellar Identity SDK.
 *
 * Organised by domain: DID (1xxx), Credential (2xxx), Reputation (3xxx),
 * ZK Proof (4xxx), Compliance (5xxx), Config (6xxx), Network (7xxx),
 * Validation (8xxx), RateLimit (9xxx).
 *
 * Every error carries:
 *  - a numeric `code` for programmatic handling
 *  - a human-readable `message`
 *  - an `errorClass` classification (network | contract | validation | auth | unknown)
 *  - a `recovery` hint so callers know what to do next
 *  - a boolean `retryable` flag consumed by the retry engine
 *  - optional `details` for structured debugging context
 *
 * @module errors
 * @category Errors
 */

// ── Error classification ──────────────────────────────────────────────────────

/**
 * High-level classification of every SDK error.
 * Used by the retry engine and monitoring layer to route errors correctly.
 */
export type ErrorClass =
  | 'network'     // Transient transport failures — safe to retry
  | 'contract'    // On-chain contract rejections — generally not retryable
  | 'validation'  // Bad input supplied by the caller — fix before retrying
  | 'auth'        // Authentication / authorisation failures
  | 'ratelimit'   // Rate limit exceeded — retry after backoff
  | 'unknown';    // Catch-all

// ── Error codes ───────────────────────────────────────────────────────────────

/**
 * Canonical numeric error codes for the Stellar Identity SDK.
 * @category Errors
 */
export enum ErrorCode {
  // ── DID errors (1xxx) ───────────────────────────────────────────────────
  DIDAlreadyExists      = 1001,
  DIDNotFound           = 1002,
  DIDUnauthorized       = 1003,
  DIDInvalidFormat      = 1004,
  DIDDeactivated        = 1005,
  DIDInvalidSignature   = 1006,
  DIDRateLimitExceeded  = 1007,
  DIDMultiSigThreshold  = 1008,

  // ── Credential errors (2xxx) ─────────────────────────────────────────────
  CredentialUnauthorized    = 2001,
  CredentialNotFound        = 2002,
  CredentialInvalid         = 2003,
  CredentialAlreadyRevoked  = 2004,
  CredentialExpired         = 2005,
  CredentialInvalidSignature = 2006,
  CredentialInvalidIssuer   = 2007,
  CredentialSchemaNotFound  = 2008,
  CredentialSchemaInvalid   = 2009,
  CredentialDelegationExpired = 2010,
  CredentialDelegationRevoked = 2011,
  CredentialLimitExceeded   = 2012,
  CredentialRateLimitExceeded = 2013,

  // ── Reputation errors (3xxx) ─────────────────────────────────────────────
  ReputationAlreadyExists   = 3001,
  ReputationNotFound        = 3002,
  ReputationUnauthorized    = 3003,
  ReputationInvalidScore    = 3004,
  ReputationInvalidDepth    = 3005,
  ReputationNotInitialized  = 3006,
  ReputationRateLimitExceeded = 3007,

  // ── ZK Proof errors (4xxx) ───────────────────────────────────────────────
  ZKInvalidProof         = 4001,
  ZKNotFound             = 4002,
  ZKUnauthorized         = 4003,
  ZKInvalidCircuit       = 4004,
  ZKVerificationFailed   = 4005,
  ZKExpired              = 4006,
  ZKNullifierAlreadyUsed = 4007,
  ZKInvalidPublicInputs  = 4008,
  ZKCircuitDeactivated   = 4009,
  ZKRevokedCredential    = 4010,
  ZKPredicateMismatch    = 4011,
  ZKAttributeNotFound    = 4012,
  ZKDisclosureConflict   = 4013,
  ZKCombiningFailed      = 4014,

  // ── Compliance errors (5xxx) ─────────────────────────────────────────────
  ComplianceAddressBlocked    = 5001,
  ComplianceHighRisk          = 5002,
  ComplianceUnauthorized      = 5003,
  ComplianceNotFound          = 5004,
  ComplianceInvalidRiskScore  = 5005,
  ComplianceOracleStale       = 5006,
  ComplianceInvalidHash       = 5007,
  ComplianceOracleNotRegistered = 5008,
  ComplianceBatchTooLarge     = 5009,

  // ── Configuration errors (6xxx) ──────────────────────────────────────────
  ConfigInvalidNetwork    = 6001,
  ConfigMissingContract   = 6002,
  ConfigInvalidRpcUrl     = 6003,
  ConfigMissingKeypair    = 6004,
  ConfigInvalidPassphrase = 6005,

  // ── Network errors (7xxx) ────────────────────────────────────────────────
  NetworkConnectionFailed   = 7001,
  NetworkTransactionFailed  = 7002,
  NetworkTimeout            = 7003,
  NetworkSimulationError    = 7004,
  NetworkInsufficientFunds  = 7005,
  NetworkSequenceMismatch   = 7006,
  NetworkLedgerClosed       = 7007,
  NetworkMaxRetriesExceeded = 7008,

  // ── Validation errors (8xxx) ─────────────────────────────────────────────
  ValidationInvalidAddress   = 8001,
  ValidationInvalidDID       = 8002,
  ValidationInvalidCredential = 8003,
  ValidationMissingField     = 8004,
  ValidationFieldTooLong     = 8005,
  ValidationInvalidProof     = 8006,

  // ── Rate limit errors (9xxx) ─────────────────────────────────────────────
  RateLimitExceeded       = 9001,
  RateLimitWindowExpired  = 9002,
}

// ── Recovery hints ────────────────────────────────────────────────────────────

/**
 * Human-readable recovery suggestions keyed by ErrorCode.
 * Surfaced in error messages to help developers diagnose and fix issues.
 */
export const RECOVERY_HINTS: Record<ErrorCode, string> = {
  // DID
  [ErrorCode.DIDAlreadyExists]:     'A DID for this address already exists. Resolve the existing DID with resolveDID() instead of creating a new one.',
  [ErrorCode.DIDNotFound]:          'The DID does not exist on-chain. Verify the DID string is correct or create it first with createDID().',
  [ErrorCode.DIDUnauthorized]:      'Only the DID controller may perform this operation. Ensure you are signing with the correct keypair.',
  [ErrorCode.DIDInvalidFormat]:     'DID must start with "did:stellar:" followed by a valid Stellar address (G...). Use DIDClient.generateDID() to construct a valid DID.',
  [ErrorCode.DIDDeactivated]:       'This DID has been permanently deactivated and cannot be updated. Create a new DID for continued use.',
  [ErrorCode.DIDInvalidSignature]:  'Signature verification failed. Check that the keypair matches the verification method stored on-chain.',
  [ErrorCode.DIDRateLimitExceeded]: 'DID creation rate limit exceeded. Wait 300 seconds before attempting another create_did call.',
  [ErrorCode.DIDMultiSigThreshold]: 'Multi-sig threshold not met. Collect more approvals with signMultiSigOperation() before executing.',

  // Credential
  [ErrorCode.CredentialUnauthorized]:    'Only the credential issuer may revoke or update this credential. Sign with the issuer keypair.',
  [ErrorCode.CredentialNotFound]:        'No credential found with this ID on-chain. Verify the credential ID returned by issueCredential().',
  [ErrorCode.CredentialInvalid]:         'Credential data failed validation. Ensure credentialType is non-empty and credentialData is under 10 KB.',
  [ErrorCode.CredentialAlreadyRevoked]:  'This credential has already been revoked and cannot be revoked again.',
  [ErrorCode.CredentialExpired]:         'The credential has passed its expirationDate. Renew it with renewCredential() or issue a new credential.',
  [ErrorCode.CredentialInvalidSignature]:'The credential proof signature is invalid. Re-generate the proof with the issuer keypair before issuing.',
  [ErrorCode.CredentialInvalidIssuer]:   'The issuer address is not authorised. Call authorizeIssuer() with an admin keypair first.',
  [ErrorCode.CredentialSchemaNotFound]:  'The referenced credential schema does not exist. Register it first with CredentialSchemaRegistry.',
  [ErrorCode.CredentialSchemaInvalid]:   'The credential data does not conform to the declared schema. Validate against the schema definition before issuing.',
  [ErrorCode.CredentialDelegationExpired]:'The delegation authorisation has expired. Request a new delegation with authorizeDelegation().',
  [ErrorCode.CredentialDelegationRevoked]:'The delegation has been revoked by the delegator. Obtain a new delegation before issuing.',
  [ErrorCode.CredentialLimitExceeded]:   'The delegation issuance limit has been reached. Ask the delegator to create a new delegation with a higher limit.',
  [ErrorCode.CredentialRateLimitExceeded]:'Credential issuance rate limit exceeded (10/min per issuer). Wait 60 seconds before retrying.',

  // Reputation
  [ErrorCode.ReputationAlreadyExists]:    'Reputation record already initialised for this address. Call getReputationScore() to read the existing record.',
  [ErrorCode.ReputationNotFound]:         'No reputation record found for this address. Initialise it first with initializeReputation().',
  [ErrorCode.ReputationUnauthorized]:     'Only the contract admin may update configuration. Sign with the admin keypair.',
  [ErrorCode.ReputationInvalidScore]:     'Score or weight must be between 0 and 10000. Check that your value is within the allowed range.',
  [ErrorCode.ReputationInvalidDepth]:     'Trust graph depth must be between 1 and 4 inclusive.',
  [ErrorCode.ReputationNotInitialized]:   'Reputation contract not initialised. Call ReputationScore.initialize() with an admin keypair first.',
  [ErrorCode.ReputationRateLimitExceeded]:'Reputation update rate limit exceeded (20/min). Wait 60 seconds before retrying.',

  // ZK Proof
  [ErrorCode.ZKInvalidProof]:         'The proof data is malformed or does not match the circuit. Re-generate the proof with generateProof().',
  [ErrorCode.ZKNotFound]:             'No ZK proof found with this ID. Check the proof ID returned by submitProof().',
  [ErrorCode.ZKUnauthorized]:         'Only the proof submitter may perform this operation.',
  [ErrorCode.ZKInvalidCircuit]:       'The circuit ID is not registered on-chain. Register it first with registerCircuit().',
  [ErrorCode.ZKVerificationFailed]:   'On-chain proof verification failed. The proof does not satisfy the verifying key. Re-generate with correct inputs.',
  [ErrorCode.ZKExpired]:              'The ZK proof has passed its expiry timestamp. Generate and submit a new proof.',
  [ErrorCode.ZKNullifierAlreadyUsed]: 'This nullifier has already been used — replay detected. Generate a new proof with a fresh salt/randomness.',
  [ErrorCode.ZKInvalidPublicInputs]:  'Public inputs do not match what the circuit expects. Check the input count and format against the circuit spec.',
  [ErrorCode.ZKCircuitDeactivated]:   'This circuit has been deactivated by an admin. Use an active circuit or request reactivation.',
  [ErrorCode.ZKRevokedCredential]:    'The underlying credential has been revoked. Obtain a valid credential before generating a new proof.',
  [ErrorCode.ZKPredicateMismatch]:    'The predicate type or threshold in the proof does not match the declared predicate. Re-generate with matching predicates.',
  [ErrorCode.ZKAttributeNotFound]:    'The requested attribute is not present in the credential. Check the credential schema for available attributes.',
  [ErrorCode.ZKDisclosureConflict]:   'An attribute appears in both the revealed and hidden sets. Move it to one list only.',
  [ErrorCode.ZKCombiningFailed]:      'Failed to combine selective disclosure proofs. Ensure all child proof IDs are valid and unexpired.',

  // Compliance
  [ErrorCode.ComplianceAddressBlocked]:     'This address is on an active sanctions list and cannot transact. Contact compliance@your-org.com for review.',
  [ErrorCode.ComplianceHighRisk]:           'Address risk score exceeds the high-risk threshold (>70). Perform enhanced due diligence before proceeding.',
  [ErrorCode.ComplianceUnauthorized]:       'Only a registered oracle or admin may perform this compliance operation.',
  [ErrorCode.ComplianceNotFound]:           'No compliance record found. Screen the address first with screenAddress().',
  [ErrorCode.ComplianceInvalidRiskScore]:   'Risk score must be between 0 and 100 inclusive.',
  [ErrorCode.ComplianceOracleStale]:        'Oracle data is older than 24 hours. Trigger a fresh oracle update before screening.',
  [ErrorCode.ComplianceInvalidHash]:        'The supplied hash does not match the stored sanctions list hash. Re-upload the list with the correct hash.',
  [ErrorCode.ComplianceOracleNotRegistered]:'Oracle address is not registered. Register it with registerOracle() using an admin keypair.',
  [ErrorCode.ComplianceBatchTooLarge]:      'Batch size exceeds the maximum of 50 addresses. Split your request into smaller batches.',

  // Config
  [ErrorCode.ConfigInvalidNetwork]:    'Network must be "mainnet", "testnet", or "futurenet". Update your StellarIdentityConfig.',
  [ErrorCode.ConfigMissingContract]:   'A required contract address is missing or empty. Deploy the contract and set its address in config.contracts.',
  [ErrorCode.ConfigInvalidRpcUrl]:     'The RPC URL is not a valid HTTPS URL. Use the canonical URLs from DEFAULT_CONFIGS or supply your own.',
  [ErrorCode.ConfigMissingKeypair]:    'This operation requires a keypair in the config. Pass config.keypair or provide it directly to the method call.',
  [ErrorCode.ConfigInvalidPassphrase]: 'The network passphrase does not match the configured network. Use getNetworkPassphrase() from the config module.',

  // Network
  [ErrorCode.NetworkConnectionFailed]:  'Cannot reach the Soroban RPC endpoint. Check your internet connection and verify the rpcUrl in your config.',
  [ErrorCode.NetworkTransactionFailed]: 'The transaction was rejected by the network. Inspect the error result XDR for the specific contract error code.',
  [ErrorCode.NetworkTimeout]:           'The RPC did not respond within the timeout window. Increase txOptions.timeout or retry with exponential backoff.',
  [ErrorCode.NetworkSimulationError]:   'Contract simulation returned an error. Check that all contract addresses are correct and the contract is deployed.',
  [ErrorCode.NetworkInsufficientFunds]: 'Account has insufficient XLM to pay the transaction fee. Fund the account via friendbot (testnet) or send XLM.',
  [ErrorCode.NetworkSequenceMismatch]:  'Account sequence number is stale. Fetch a fresh account object with rpc.getAccount() before building the transaction.',
  [ErrorCode.NetworkLedgerClosed]:      'The target ledger has already closed. Rebuild the transaction with a new sequence number and resubmit.',
  [ErrorCode.NetworkMaxRetriesExceeded]:'All retry attempts exhausted. The operation failed after the maximum number of retries. Check network health.',

  // Validation
  [ErrorCode.ValidationInvalidAddress]:   'The Stellar address is invalid. Addresses must start with "G" and be 56 characters (base32 encoded).',
  [ErrorCode.ValidationInvalidDID]:       'Invalid DID string. Expected format: "did:stellar:<G...address>".',
  [ErrorCode.ValidationInvalidCredential]:'Credential is missing required fields (type, credentialData, proof).',
  [ErrorCode.ValidationMissingField]:     'A required field is missing. Check the method signature and supply all required parameters.',
  [ErrorCode.ValidationFieldTooLong]:     'A field value exceeds the maximum allowed length. Refer to the contract limits in the API reference.',
  [ErrorCode.ValidationInvalidProof]:     'The proof value is empty or malformed. Generate a valid proof using the appropriate method.',

  // Rate limit
  [ErrorCode.RateLimitExceeded]:      'Request rate limit exceeded. Back off and retry after the reset window (typically 60 seconds).',
  [ErrorCode.RateLimitWindowExpired]: 'Rate limit window has expired. You may retry the operation now.',
};

// ── Error classification metadata ─────────────────────────────────────────────

interface ErrorMeta {
  errorClass: ErrorClass;
  /** Whether the retry engine should attempt this operation again. */
  retryable: boolean;
  /** Suggested base delay in milliseconds before the first retry. */
  retryDelayMs?: number;
}

const ERROR_META: Record<ErrorCode, ErrorMeta> = {
  // DID
  [ErrorCode.DIDAlreadyExists]:     { errorClass: 'contract',   retryable: false },
  [ErrorCode.DIDNotFound]:          { errorClass: 'contract',   retryable: false },
  [ErrorCode.DIDUnauthorized]:      { errorClass: 'auth',       retryable: false },
  [ErrorCode.DIDInvalidFormat]:     { errorClass: 'validation', retryable: false },
  [ErrorCode.DIDDeactivated]:       { errorClass: 'contract',   retryable: false },
  [ErrorCode.DIDInvalidSignature]:  { errorClass: 'auth',       retryable: false },
  [ErrorCode.DIDRateLimitExceeded]: { errorClass: 'ratelimit',  retryable: true,  retryDelayMs: 30_000 },
  [ErrorCode.DIDMultiSigThreshold]: { errorClass: 'contract',   retryable: false },

  // Credential
  [ErrorCode.CredentialUnauthorized]:     { errorClass: 'auth',       retryable: false },
  [ErrorCode.CredentialNotFound]:         { errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialInvalid]:          { errorClass: 'validation', retryable: false },
  [ErrorCode.CredentialAlreadyRevoked]:   { errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialExpired]:          { errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialInvalidSignature]: { errorClass: 'auth',       retryable: false },
  [ErrorCode.CredentialInvalidIssuer]:    { errorClass: 'auth',       retryable: false },
  [ErrorCode.CredentialSchemaNotFound]:   { errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialSchemaInvalid]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.CredentialDelegationExpired]:{ errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialDelegationRevoked]:{ errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialLimitExceeded]:    { errorClass: 'contract',   retryable: false },
  [ErrorCode.CredentialRateLimitExceeded]:{ errorClass: 'ratelimit',  retryable: true,  retryDelayMs: 60_000 },

  // Reputation
  [ErrorCode.ReputationAlreadyExists]:    { errorClass: 'contract',   retryable: false },
  [ErrorCode.ReputationNotFound]:         { errorClass: 'contract',   retryable: false },
  [ErrorCode.ReputationUnauthorized]:     { errorClass: 'auth',       retryable: false },
  [ErrorCode.ReputationInvalidScore]:     { errorClass: 'validation', retryable: false },
  [ErrorCode.ReputationInvalidDepth]:     { errorClass: 'validation', retryable: false },
  [ErrorCode.ReputationNotInitialized]:   { errorClass: 'contract',   retryable: false },
  [ErrorCode.ReputationRateLimitExceeded]:{ errorClass: 'ratelimit',  retryable: true,  retryDelayMs: 60_000 },

  // ZK
  [ErrorCode.ZKInvalidProof]:         { errorClass: 'validation', retryable: false },
  [ErrorCode.ZKNotFound]:             { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKUnauthorized]:         { errorClass: 'auth',       retryable: false },
  [ErrorCode.ZKInvalidCircuit]:       { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKVerificationFailed]:   { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKExpired]:              { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKNullifierAlreadyUsed]: { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKInvalidPublicInputs]:  { errorClass: 'validation', retryable: false },
  [ErrorCode.ZKCircuitDeactivated]:   { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKRevokedCredential]:    { errorClass: 'contract',   retryable: false },
  [ErrorCode.ZKPredicateMismatch]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.ZKAttributeNotFound]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.ZKDisclosureConflict]:   { errorClass: 'validation', retryable: false },
  [ErrorCode.ZKCombiningFailed]:      { errorClass: 'contract',   retryable: false },

  // Compliance
  [ErrorCode.ComplianceAddressBlocked]:     { errorClass: 'contract',   retryable: false },
  [ErrorCode.ComplianceHighRisk]:           { errorClass: 'contract',   retryable: false },
  [ErrorCode.ComplianceUnauthorized]:       { errorClass: 'auth',       retryable: false },
  [ErrorCode.ComplianceNotFound]:           { errorClass: 'contract',   retryable: false },
  [ErrorCode.ComplianceInvalidRiskScore]:   { errorClass: 'validation', retryable: false },
  [ErrorCode.ComplianceOracleStale]:        { errorClass: 'contract',   retryable: false },
  [ErrorCode.ComplianceInvalidHash]:        { errorClass: 'validation', retryable: false },
  [ErrorCode.ComplianceOracleNotRegistered]:{ errorClass: 'auth',       retryable: false },
  [ErrorCode.ComplianceBatchTooLarge]:      { errorClass: 'validation', retryable: false },

  // Config
  [ErrorCode.ConfigInvalidNetwork]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.ConfigMissingContract]:   { errorClass: 'validation', retryable: false },
  [ErrorCode.ConfigInvalidRpcUrl]:     { errorClass: 'validation', retryable: false },
  [ErrorCode.ConfigMissingKeypair]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.ConfigInvalidPassphrase]: { errorClass: 'validation', retryable: false },

  // Network
  [ErrorCode.NetworkConnectionFailed]:  { errorClass: 'network', retryable: true,  retryDelayMs: 1_000 },
  [ErrorCode.NetworkTransactionFailed]: { errorClass: 'network', retryable: false },
  [ErrorCode.NetworkTimeout]:           { errorClass: 'network', retryable: true,  retryDelayMs: 2_000 },
  [ErrorCode.NetworkSimulationError]:   { errorClass: 'network', retryable: false },
  [ErrorCode.NetworkInsufficientFunds]: { errorClass: 'network', retryable: false },
  [ErrorCode.NetworkSequenceMismatch]:  { errorClass: 'network', retryable: true,  retryDelayMs: 500 },
  [ErrorCode.NetworkLedgerClosed]:      { errorClass: 'network', retryable: true,  retryDelayMs: 500 },
  [ErrorCode.NetworkMaxRetriesExceeded]:{ errorClass: 'network', retryable: false },

  // Validation
  [ErrorCode.ValidationInvalidAddress]:    { errorClass: 'validation', retryable: false },
  [ErrorCode.ValidationInvalidDID]:        { errorClass: 'validation', retryable: false },
  [ErrorCode.ValidationInvalidCredential]: { errorClass: 'validation', retryable: false },
  [ErrorCode.ValidationMissingField]:      { errorClass: 'validation', retryable: false },
  [ErrorCode.ValidationFieldTooLong]:      { errorClass: 'validation', retryable: false },
  [ErrorCode.ValidationInvalidProof]:      { errorClass: 'validation', retryable: false },

  // Rate limit
  [ErrorCode.RateLimitExceeded]:      { errorClass: 'ratelimit', retryable: true,  retryDelayMs: 60_000 },
  [ErrorCode.RateLimitWindowExpired]: { errorClass: 'ratelimit', retryable: true,  retryDelayMs: 0 },
};

// ── Base error class ──────────────────────────────────────────────────────────

/**
 * Base error class for all Stellar Identity SDK errors.
 *
 * Every error exposes:
 * - `code`        — numeric error code for programmatic branching
 * - `errorClass`  — classification (network | contract | validation | auth | ratelimit | unknown)
 * - `retryable`   — whether the retry engine should attempt the call again
 * - `retryDelayMs`— suggested base delay before the first retry
 * - `recovery`    — human-readable hint about what to do next
 * - `details`     — structured context for debugging / logging
 *
 * @category Errors
 */
export class StellarIdentityError extends Error {
  public readonly code: ErrorCode;
  public readonly errorClass: ErrorClass;
  public readonly retryable: boolean;
  public readonly retryDelayMs: number;
  public readonly recovery: string;
  public readonly details: Record<string, unknown>;
  /** Unix timestamp (ms) when the error was created. */
  public readonly timestamp: number;

  constructor(
    code: ErrorCode,
    message?: string,
    details?: Record<string, unknown>,
  ) {
    const meta = ERROR_META[code] ?? { errorClass: 'unknown' as ErrorClass, retryable: false };
    const hint = RECOVERY_HINTS[code] ?? 'Check the error code documentation for guidance.';
    const defaultMsg = RECOVERY_HINTS[code]
      ? RECOVERY_HINTS[code].split('.')[0]   // first sentence as default message
      : `SDK error ${code}`;

    super(message ?? defaultMsg);
    this.name = 'StellarIdentityError';
    this.code = code;
    this.errorClass = meta.errorClass;
    this.retryable = meta.retryable;
    this.retryDelayMs = meta.retryDelayMs ?? 0;
    this.recovery = hint;
    this.details = details ?? {};
    this.timestamp = Date.now();
    Object.setPrototypeOf(this, StellarIdentityError.prototype);
  }

  /** Serialize to a plain object safe for JSON logging. */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      code: this.code,
      errorClass: this.errorClass,
      message: this.message,
      recovery: this.recovery,
      retryable: this.retryable,
      retryDelayMs: this.retryDelayMs,
      details: this.details,
      timestamp: this.timestamp,
      stack: this.stack,
    };
  }
}

// ── Domain-specific error classes ─────────────────────────────────────────────

/** Errors originating from the DID Registry contract. @category Errors */
export class DIDError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'DIDError';
    Object.setPrototypeOf(this, DIDError.prototype);
  }
}

/** Errors originating from the Credential Issuer contract. @category Errors */
export class CredentialError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'CredentialError';
    Object.setPrototypeOf(this, CredentialError.prototype);
  }
}

/** Errors originating from the Reputation Score contract. @category Errors */
export class ReputationError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ReputationError';
    Object.setPrototypeOf(this, ReputationError.prototype);
  }
}

/** Errors originating from the ZK Attestation contract. @category Errors */
export class ZKProofError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ZKProofError';
    Object.setPrototypeOf(this, ZKProofError.prototype);
  }
}

/** Errors originating from the Compliance Filter contract. @category Errors */
export class ComplianceError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ComplianceError';
    Object.setPrototypeOf(this, ComplianceError.prototype);
  }
}

/** SDK configuration errors — invalid network, missing contracts, bad URLs. @category Errors */
export class ConfigurationError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

/** Transient network and RPC errors — generally safe to retry. @category Errors */
export class NetworkError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/** Input validation errors — fix the input before retrying. @category Errors */
export class ValidationError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

/** Rate limit errors — back off before retrying. @category Errors */
export class RateLimitError extends StellarIdentityError {
  constructor(code: ErrorCode, message?: string, details?: Record<string, unknown>) {
    super(code, message, details);
    this.name = 'RateLimitError';
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

// ── Contract error mapping ────────────────────────────────────────────────────

type ErrorClassCtor = new (
  code: ErrorCode,
  message?: string,
  details?: Record<string, unknown>,
) => StellarIdentityError;

const CONTRACT_CLASS_MAP: Record<string, ErrorClassCtor> = {
  DIDRegistryError:       DIDError,
  CredentialIssuerError:  CredentialError,
  ReputationScoreError:   ReputationError,
  ZKAttestationError:     ZKProofError,
  ComplianceFilterError:  ComplianceError,
};

const CONTRACT_CODE_MAP: Record<string, [ErrorCode, ErrorClassCtor]> = {
  // DID Registry
  'DIDRegistryError:AlreadyExists':    [ErrorCode.DIDAlreadyExists,     DIDError],
  'DIDRegistryError:NotFound':         [ErrorCode.DIDNotFound,          DIDError],
  'DIDRegistryError:Unauthorized':     [ErrorCode.DIDUnauthorized,      DIDError],
  'DIDRegistryError:InvalidFormat':    [ErrorCode.DIDInvalidFormat,     DIDError],
  'DIDRegistryError:Deactivated':      [ErrorCode.DIDDeactivated,       DIDError],
  'DIDRegistryError:InvalidSignature': [ErrorCode.DIDInvalidSignature,  DIDError],
  'DIDRegistryError:RateLimitExceeded':[ErrorCode.DIDRateLimitExceeded, DIDError],
  'DIDRegistryError:AlreadyDeactivated':[ErrorCode.DIDDeactivated,      DIDError],

  // Credential Issuer
  'CredentialIssuerError:Unauthorized':       [ErrorCode.CredentialUnauthorized,     CredentialError],
  'CredentialIssuerError:NotFound':           [ErrorCode.CredentialNotFound,         CredentialError],
  'CredentialIssuerError:InvalidCredential':  [ErrorCode.CredentialInvalid,          CredentialError],
  'CredentialIssuerError:AlreadyRevoked':     [ErrorCode.CredentialAlreadyRevoked,   CredentialError],
  'CredentialIssuerError:Expired':            [ErrorCode.CredentialExpired,          CredentialError],
  'CredentialIssuerError:InvalidSignature':   [ErrorCode.CredentialInvalidSignature, CredentialError],
  'CredentialIssuerError:InvalidIssuer':      [ErrorCode.CredentialInvalidIssuer,    CredentialError],
  'CredentialIssuerError:SchemaNotFound':     [ErrorCode.CredentialSchemaNotFound,   CredentialError],
  'CredentialIssuerError:SchemaValidationFailed':[ErrorCode.CredentialSchemaInvalid, CredentialError],
  'CredentialIssuerError:DelegationExpired':  [ErrorCode.CredentialDelegationExpired,CredentialError],
  'CredentialIssuerError:DelegationRevoked':  [ErrorCode.CredentialDelegationRevoked,CredentialError],
  'CredentialIssuerError:DelegationLimitExceeded':[ErrorCode.CredentialLimitExceeded,CredentialError],
  'CredentialIssuerError:RateLimitExceeded':  [ErrorCode.CredentialRateLimitExceeded,CredentialError],

  // Reputation Score
  'ReputationScoreError:AlreadyExists':    [ErrorCode.ReputationAlreadyExists,    ReputationError],
  'ReputationScoreError:NotFound':         [ErrorCode.ReputationNotFound,         ReputationError],
  'ReputationScoreError:Unauthorized':     [ErrorCode.ReputationUnauthorized,     ReputationError],
  'ReputationScoreError:InvalidScore':     [ErrorCode.ReputationInvalidScore,     ReputationError],
  'ReputationScoreError:InvalidDepth':     [ErrorCode.ReputationInvalidDepth,     ReputationError],
  'ReputationScoreError:NotInitialized':   [ErrorCode.ReputationNotInitialized,   ReputationError],
  'ReputationScoreError:RateLimitExceeded':[ErrorCode.ReputationRateLimitExceeded,ReputationError],

  // ZK Attestation
  'ZKAttestationError:InvalidProof':         [ErrorCode.ZKInvalidProof,          ZKProofError],
  'ZKAttestationError:NotFound':             [ErrorCode.ZKNotFound,              ZKProofError],
  'ZKAttestationError:Unauthorized':         [ErrorCode.ZKUnauthorized,          ZKProofError],
  'ZKAttestationError:InvalidCircuit':       [ErrorCode.ZKInvalidCircuit,        ZKProofError],
  'ZKAttestationError:VerificationFailed':   [ErrorCode.ZKVerificationFailed,    ZKProofError],
  'ZKAttestationError:Expired':              [ErrorCode.ZKExpired,               ZKProofError],
  'ZKAttestationError:NullifierAlreadyUsed': [ErrorCode.ZKNullifierAlreadyUsed,  ZKProofError],
  'ZKAttestationError:InvalidPublicInputs':  [ErrorCode.ZKInvalidPublicInputs,   ZKProofError],
  'ZKAttestationError:CircuitDeactivated':   [ErrorCode.ZKCircuitDeactivated,    ZKProofError],
  'ZKAttestationError:RevokedCredential':    [ErrorCode.ZKRevokedCredential,     ZKProofError],
  'ZKAttestationError:PredicateMismatch':    [ErrorCode.ZKPredicateMismatch,     ZKProofError],
  'ZKAttestationError:AttributeNotFound':    [ErrorCode.ZKAttributeNotFound,     ZKProofError],
  'ZKAttestationError:DisclosureConflict':   [ErrorCode.ZKDisclosureConflict,    ZKProofError],
  'ZKAttestationError:CombiningFailed':      [ErrorCode.ZKCombiningFailed,       ZKProofError],

  // Compliance Filter
  'ComplianceFilterError:AddressBlocked':     [ErrorCode.ComplianceAddressBlocked,     ComplianceError],
  'ComplianceFilterError:HighRisk':           [ErrorCode.ComplianceHighRisk,           ComplianceError],
  'ComplianceFilterError:Unauthorized':       [ErrorCode.ComplianceUnauthorized,       ComplianceError],
  'ComplianceFilterError:NotFound':           [ErrorCode.ComplianceNotFound,           ComplianceError],
  'ComplianceFilterError:InvalidRiskScore':   [ErrorCode.ComplianceInvalidRiskScore,   ComplianceError],
  'ComplianceFilterError:OracleStale':        [ErrorCode.ComplianceOracleStale,        ComplianceError],
  'ComplianceFilterError:InvalidHash':        [ErrorCode.ComplianceInvalidHash,        ComplianceError],
  'ComplianceFilterError:OracleNotRegistered':[ErrorCode.ComplianceOracleNotRegistered,ComplianceError],
  'ComplianceFilterError:BatchTooLarge':      [ErrorCode.ComplianceBatchTooLarge,      ComplianceError],
};

// Patterns for parsing raw Soroban/Horizon error strings
const RUST_CONTRACT_CODE_PATTERN = /Error\(Contract,\s*#(\d+)\)/;
const RUST_NAMED_ERROR_PATTERN    = /([A-Za-z]+Error):([A-Za-z]+)/;
const INSUFFICIENT_FUNDS_PATTERN  = /op_no_source_account|insufficient.?balance|below.?minimum/i;
const SEQUENCE_MISMATCH_PATTERN   = /tx_bad_seq|sequence/i;
const LEDGER_CLOSED_PATTERN       = /tx_too_late|ledger_closed/i;

// ── mapContractError ──────────────────────────────────────────────────────────

/**
 * Maps any thrown value (contract error, network error, plain Error, string)
 * to the appropriate typed `StellarIdentityError` subclass.
 *
 * Resolution order:
 * 1. Pass through existing `StellarIdentityError` instances unchanged.
 * 2. Match Soroban contract error format `Error(Contract, #N)`.
 * 3. Match named Rust error variant `ContractNameError:Variant`.
 * 4. Match contract class name in the message.
 * 5. Detect specific network conditions (insufficient funds, sequence, ledger).
 * 6. Classify generic network / timeout / fetch errors.
 * 7. Fall back to `NetworkTransactionFailed`.
 *
 * @category Errors
 */
export function mapContractError(
  error: unknown,
  context?: Record<string, unknown>,
): StellarIdentityError {
  if (error instanceof StellarIdentityError) return error;

  const message = error instanceof Error ? error.message : String(error);
  const details = { ...(context ?? {}), rawMessage: message };

  // 1. Soroban contract error number: Error(Contract, #N)
  const contractMatch = message.match(RUST_CONTRACT_CODE_PATTERN);
  if (contractMatch) {
    const n = parseInt(contractMatch[1], 10);
    const mapped = mapErrorCode(n);
    if (mapped) return mapped;
  }

  // 2. Named Rust error variant: DIDRegistryError:NotFound
  const namedMatch = message.match(RUST_NAMED_ERROR_PATTERN);
  if (namedMatch) {
    const key = `${namedMatch[1]}:${namedMatch[2]}`;
    const entry = CONTRACT_CODE_MAP[key];
    if (entry) {
      const [code, Ctor] = entry;
      return new Ctor(code, message, details);
    }
  }

  // 3. Contract class name in message
  for (const [className, Ctor] of Object.entries(CONTRACT_CLASS_MAP)) {
    if (message.includes(className)) {
      return new Ctor(ErrorCode.NetworkTransactionFailed, message, details);
    }
  }

  // 4. Specific network conditions
  if (INSUFFICIENT_FUNDS_PATTERN.test(message)) {
    return new NetworkError(ErrorCode.NetworkInsufficientFunds, message, details);
  }
  if (SEQUENCE_MISMATCH_PATTERN.test(message)) {
    return new NetworkError(ErrorCode.NetworkSequenceMismatch, message, details);
  }
  if (LEDGER_CLOSED_PATTERN.test(message)) {
    return new NetworkError(ErrorCode.NetworkLedgerClosed, message, details);
  }

  // 5. Generic network / timeout
  if (/timeout|timed.?out/i.test(message)) {
    return new NetworkError(ErrorCode.NetworkTimeout, message, details);
  }
  if (/fetch|connect|econnrefused|enotfound|econnreset|network/i.test(message)) {
    return new NetworkError(ErrorCode.NetworkConnectionFailed, message, details);
  }
  if (/simulation|simulate/i.test(message)) {
    return new NetworkError(ErrorCode.NetworkSimulationError, message, details);
  }
  if (/rate.?limit/i.test(message)) {
    return new RateLimitError(ErrorCode.RateLimitExceeded, message, details);
  }

  return new NetworkError(ErrorCode.NetworkTransactionFailed, message, details);
}

// ── mapErrorCode ──────────────────────────────────────────────────────────────

/**
 * Maps a raw Soroban contract numeric error code to a typed error.
 * Returns `null` if the code is not recognised.
 *
 * @category Errors
 */
export function mapErrorCode(code: number): StellarIdentityError | null {
  // DID Registry: 1–8
  if (code >= 1 && code <= 8) {
    switch (code) {
      case 1: return new DIDError(ErrorCode.DIDAlreadyExists);
      case 2: return new DIDError(ErrorCode.DIDNotFound);
      case 3: return new DIDError(ErrorCode.DIDUnauthorized);
      case 4: return new DIDError(ErrorCode.DIDInvalidFormat);
      case 5: return new DIDError(ErrorCode.DIDDeactivated);
      case 6: return new DIDError(ErrorCode.DIDInvalidSignature);
      case 7: return new DIDError(ErrorCode.DIDDeactivated);     // AlreadyDeactivated alias
      case 8: return new DIDError(ErrorCode.DIDRateLimitExceeded);
    }
  }
  // Credential Issuer: 100–117
  if (code >= 100 && code <= 120) {
    switch (code) {
      case 101: return new CredentialError(ErrorCode.CredentialUnauthorized);
      case 102: return new CredentialError(ErrorCode.CredentialNotFound);
      case 103: return new CredentialError(ErrorCode.CredentialInvalid);
      case 104: return new CredentialError(ErrorCode.CredentialAlreadyRevoked);
      case 105: return new CredentialError(ErrorCode.CredentialExpired);
      case 106: return new CredentialError(ErrorCode.CredentialInvalidSignature);
      case 107: return new CredentialError(ErrorCode.CredentialInvalidIssuer);
      case 108: return new CredentialError(ErrorCode.CredentialSchemaNotFound);
      case 109: return new CredentialError(ErrorCode.CredentialSchemaInvalid);
      case 110: return new CredentialError(ErrorCode.CredentialDelegationExpired);
      case 111: return new CredentialError(ErrorCode.CredentialDelegationRevoked);
      case 112: return new CredentialError(ErrorCode.CredentialLimitExceeded);
      case 117: return new CredentialError(ErrorCode.CredentialRateLimitExceeded);
    }
  }
  // Reputation Score: 200–209
  if (code >= 200 && code <= 210) {
    switch (code) {
      case 201: return new ReputationError(ErrorCode.ReputationAlreadyExists);
      case 202: return new ReputationError(ErrorCode.ReputationNotFound);
      case 203: return new ReputationError(ErrorCode.ReputationUnauthorized);
      case 204: return new ReputationError(ErrorCode.ReputationInvalidScore);
      case 205: return new ReputationError(ErrorCode.ReputationInvalidDepth);
      case 206: return new ReputationError(ErrorCode.ReputationNotInitialized);
      case 209: return new ReputationError(ErrorCode.ReputationRateLimitExceeded);
    }
  }
  // ZK Attestation: 300–314
  if (code >= 300 && code <= 320) {
    switch (code) {
      case 301: return new ZKProofError(ErrorCode.ZKInvalidProof);
      case 302: return new ZKProofError(ErrorCode.ZKNotFound);
      case 303: return new ZKProofError(ErrorCode.ZKUnauthorized);
      case 304: return new ZKProofError(ErrorCode.ZKInvalidCircuit);
      case 305: return new ZKProofError(ErrorCode.ZKVerificationFailed);
      case 306: return new ZKProofError(ErrorCode.ZKExpired);
      case 307: return new ZKProofError(ErrorCode.ZKNullifierAlreadyUsed);
      case 308: return new ZKProofError(ErrorCode.ZKInvalidPublicInputs);
      case 309: return new ZKProofError(ErrorCode.ZKCircuitDeactivated);
      case 310: return new ZKProofError(ErrorCode.ZKRevokedCredential);
      case 311: return new ZKProofError(ErrorCode.ZKPredicateMismatch);
      case 312: return new ZKProofError(ErrorCode.ZKAttributeNotFound);
      case 313: return new ZKProofError(ErrorCode.ZKDisclosureConflict);
      case 314: return new ZKProofError(ErrorCode.ZKCombiningFailed);
    }
  }
  // Compliance Filter: 400–412
  if (code >= 400 && code <= 420) {
    switch (code) {
      case 401: return new ComplianceError(ErrorCode.ComplianceAddressBlocked);
      case 402: return new ComplianceError(ErrorCode.ComplianceHighRisk);
      case 403: return new ComplianceError(ErrorCode.ComplianceUnauthorized);
      case 404: return new ComplianceError(ErrorCode.ComplianceNotFound);
      case 405: return new ComplianceError(ErrorCode.ComplianceInvalidRiskScore);
      case 406: return new ComplianceError(ErrorCode.ComplianceOracleStale);
      case 407: return new ComplianceError(ErrorCode.ComplianceInvalidHash);
      case 408: return new ComplianceError(ErrorCode.ComplianceOracleNotRegistered);
      case 411: return new ComplianceError(ErrorCode.ComplianceBatchTooLarge);
    }
  }
  return null;
}

// ── Type guards ───────────────────────────────────────────────────────────────

/** @category Errors */
export function isDIDError(e: unknown): e is DIDError {
  return e instanceof DIDError;
}
/** @category Errors */
export function isCredentialError(e: unknown): e is CredentialError {
  return e instanceof CredentialError;
}
/** @category Errors */
export function isReputationError(e: unknown): e is ReputationError {
  return e instanceof ReputationError;
}
/** @category Errors */
export function isZKProofError(e: unknown): e is ZKProofError {
  return e instanceof ZKProofError;
}
/** @category Errors */
export function isComplianceError(e: unknown): e is ComplianceError {
  return e instanceof ComplianceError;
}
/** @category Errors */
export function isConfigurationError(e: unknown): e is ConfigurationError {
  return e instanceof ConfigurationError;
}
/** @category Errors */
export function isNetworkError(e: unknown): e is NetworkError {
  return e instanceof NetworkError;
}
/** @category Errors */
export function isValidationError(e: unknown): e is ValidationError {
  return e instanceof ValidationError;
}
/** @category Errors */
export function isRateLimitError(e: unknown): e is RateLimitError {
  return e instanceof RateLimitError;
}
/** Returns true for any StellarIdentityError that is safe to retry. @category Errors */
export function isRetryableError(e: unknown): e is StellarIdentityError {
  return e instanceof StellarIdentityError && e.retryable;
}

// ── Convenience builders ──────────────────────────────────────────────────────

/** Build a ValidationError for a missing required field. */
export function missingField(fieldName: string): ValidationError {
  return new ValidationError(
    ErrorCode.ValidationMissingField,
    `Required field "${fieldName}" is missing or empty.`,
    { fieldName },
  );
}

/** Build a ValidationError for a field that exceeds its maximum length. */
export function fieldTooLong(fieldName: string, maxLength: number, actual: number): ValidationError {
  return new ValidationError(
    ErrorCode.ValidationFieldTooLong,
    `Field "${fieldName}" exceeds maximum length of ${maxLength} (got ${actual}).`,
    { fieldName, maxLength, actual },
  );
}

/** Build a ValidationError for an invalid Stellar address. */
export function invalidAddress(address: string): ValidationError {
  return new ValidationError(
    ErrorCode.ValidationInvalidAddress,
    `Invalid Stellar address: "${address}". Expected a G... address of 56 characters.`,
    { address },
  );
}

/** Build a ValidationError for an invalid DID string. */
export function invalidDID(did: string): ValidationError {
  return new ValidationError(
    ErrorCode.ValidationInvalidDID,
    `Invalid DID: "${did}". Expected format "did:stellar:<G...address>".`,
    { did },
  );
}
