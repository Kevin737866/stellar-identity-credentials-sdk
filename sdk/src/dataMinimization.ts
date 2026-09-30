import { VerifiableCredential } from './types';
import * as crypto from 'crypto';

// ─── Existing interfaces (preserved) ────────────────────────────────────────

export interface BlindedAttribute {
  originalValue: unknown;
  blindingFactor: string;
}

export interface SaltedHashCommitment {
  hash: string;
  salt: string;
}

export interface AttributeExpiration {
  attributeName: string;
  expirationDate: number; // timestamp
}

export interface MinimalDisclosurePolicy {
  allowedAttributes: string[];
  requireBlindingFor?: string[];
  attributeExpirations?: AttributeExpiration[];
}

// ─── Issue #189: New interfaces ───────────────────────────────────────────────

/**
 * A request from a verifier to a holder, declaring which credential attributes
 * are needed and for what purpose.  Only attributes listed in
 * `requiredAttributes` should ever be shared — the `DataMinimizationEngine`
 * will enforce this at validation time.
 */
export interface ProofRequest {
  /** Unique identifier for this proof request. */
  id: string;
  /** Human-readable purpose that explains why the attributes are needed. */
  purpose: string;
  /**
   * The minimum set of attributes the verifier must see to fulfil the purpose.
   * Requesting *more* than the minimum is rejected by `validateProofRequest`.
   */
  requiredAttributes: string[];
  /** DID or address of the verifier making the request. */
  verifierId: string;
  /**
   * Optional allow-list: the full set of attributes the verifier is *permitted*
   * to ask for.  Used by `createProofRequest` to cap requiredAttributes.
   */
  allowedAttributes?: string[];
  /** ISO-8601 timestamp at which the request was created. */
  createdAt: string;
}

/**
 * Immutable audit record produced whenever a ProofRequest is fulfilled.
 * Stored by the holder for accountability purposes.
 */
export interface AuditEntry {
  /** Unique identifier for this audit entry. */
  id: string;
  /** Unix epoch milliseconds when the sharing event occurred. */
  timestamp: number;
  /** Purpose as declared in the original ProofRequest. */
  purpose: string;
  /** DID or address of the verifier who received the attributes. */
  verifierId: string;
  /** DID or address of the holder who shared the attributes. */
  holderId: string;
  /** Exact set of attributes that were shared. */
  sharedAttributes: string[];
  /** ID of the ProofRequest that triggered this sharing event. */
  requestId: string;
}

/**
 * Machine-readable consent receipt given to the holder as proof that they
 * explicitly agreed to share the listed attributes for the stated purpose.
 */
export interface ConsentReceipt {
  /** Unique identifier for this consent receipt. */
  id: string;
  /** Unix epoch milliseconds when consent was given. */
  timestamp: number;
  /** DID or address of the holder who granted consent. */
  holderId: string;
  /** DID or address of the verifier who received the consent. */
  verifierId: string;
  /** Purpose as declared in the original ProofRequest. */
  purpose: string;
  /** Attributes covered by this consent. */
  attributes: string[];
  /** Unix epoch milliseconds after which this receipt expires (30 days default). */
  expiresAt: number;
}

// ─── DataMinimizationEngine ───────────────────────────────────────────────────

export class DataMinimizationEngine {

  // ── Original methods (preserved) ──────────────────────────────────────────

  /**
   * Generates a salted hash commitment for a given attribute value.
   */
  public generateSaltedHash(value: string | number | boolean): SaltedHashCommitment {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.createHash('sha256').update(`${value}:${salt}`).digest('hex');
    return { hash, salt };
  }

  /**
   * Creates a blinded attribute with a random blinding factor.
   */
  public generateBlindedAttribute(value: unknown): BlindedAttribute {
    const blindingFactor = crypto.randomBytes(32).toString('hex');
    return { originalValue: value, blindingFactor };
  }

  /**
   * Applies a minimal disclosure policy to a given credential.
   * Redacts any fields in `credentialData` not specified in `allowedAttributes`.
   * Also enforces `attributeExpirations`.
   */
  public applyDisclosurePolicy(
    credential: VerifiableCredential,
    policy: MinimalDisclosurePolicy,
  ): VerifiableCredential {
    const redactedData: Record<string, unknown> = {};

    const now = Date.now();
    for (const key of Object.keys(credential.credentialData)) {
      if (policy.allowedAttributes.includes(key)) {
        // Check attribute-level expiration
        const expiration = policy.attributeExpirations?.find(e => e.attributeName === key);
        if (expiration && now > expiration.expirationDate) {
          continue; // Attribute expired, omit it
        }

        // Apply blinding if required
        if (policy.requireBlindingFor?.includes(key)) {
          redactedData[key] = this.generateBlindedAttribute(credential.credentialData[key]);
        } else {
          redactedData[key] = credential.credentialData[key];
        }
      }
    }

    return {
      ...credential,
      credentialData: redactedData,
    };
  }

  // ── Issue #189: New methods ────────────────────────────────────────────────

  /**
   * Creates a `ProofRequest` asserting a minimum set of attributes needed for
   * the stated purpose.  Any attribute in `requiredAttributes` that is NOT in
   * `allowedAttributes` is silently dropped — the resulting request is always
   * constrained to the permitted set.
   *
   * @param purpose          Human-readable reason for the request.
   * @param requiredAttributes The minimum attributes needed.
   * @param verifierId       DID or address of the requesting verifier.
   * @param allowedAttributes The full set the verifier may ever ask for.
   * @returns A new `ProofRequest` object.
   */
  public createProofRequest(
    purpose: string,
    requiredAttributes: string[],
    verifierId: string,
    allowedAttributes: string[],
  ): ProofRequest {
    // Enforce: requiredAttributes ⊆ allowedAttributes
    const sanitised = requiredAttributes.filter(attr => allowedAttributes.includes(attr));

    return {
      id: this.generateId('req'),
      purpose,
      requiredAttributes: sanitised,
      verifierId,
      allowedAttributes,
      createdAt: new Date().toISOString(),
    };
  }

  /**
   * Validates a `ProofRequest` against the set of attributes a holder actually
   * possesses.  Throws if the request asks for more than what is available or
   * if `requiredAttributes` is not a proper subset of `allowedAttributes`.
   *
   * @param request             The proof request to validate.
   * @param availableAttributes All attribute names the holder can share.
   * @returns The minimum set of attribute names that should be shared.
   * @throws `Error` when the request is overbroad.
   */
  public validateProofRequest(
    request: ProofRequest,
    availableAttributes: string[],
  ): string[] {
    const allowed = request.allowedAttributes ?? request.requiredAttributes;

    // 1. Ensure every required attribute is within the allowed set.
    const overbroad = request.requiredAttributes.filter(attr => !allowed.includes(attr));
    if (overbroad.length > 0) {
      throw new Error(
        `Overbroad proof request: attributes [${overbroad.join(', ')}] are not in allowedAttributes.`,
      );
    }

    // 2. Ensure all required attributes are actually available.
    const unavailable = request.requiredAttributes.filter(
      attr => !availableAttributes.includes(attr),
    );
    if (unavailable.length > 0) {
      throw new Error(
        `Proof request cannot be fulfilled: attributes [${unavailable.join(', ')}] are not available.`,
      );
    }

    // 3. Return only the minimum — don't volunteer extras.
    return request.requiredAttributes.slice();
  }

  /**
   * Produces an immutable `AuditEntry` that records *which* attributes were
   * shared with *whom* and *why*.
   *
   * @param request          The original proof request.
   * @param sharedAttributes The attributes that were actually shared.
   * @param holderId         DID or address of the holder who shared them.
   * @returns A new `AuditEntry`.
   */
  public generateAuditEntry(
    request: ProofRequest,
    sharedAttributes: string[],
    holderId: string,
  ): AuditEntry {
    return {
      id: this.generateId('audit'),
      timestamp: Date.now(),
      purpose: request.purpose,
      verifierId: request.verifierId,
      holderId,
      sharedAttributes: sharedAttributes.slice(),
      requestId: request.id,
    };
  }

  /**
   * Generates a `ConsentReceipt` acknowledging that the holder consented to
   * sharing the listed attributes for the stated purpose.  The receipt expires
   * after 30 days by default.
   *
   * @param request          The original proof request.
   * @param holderId         DID or address of the holder granting consent.
   * @param sharedAttributes Attributes covered by this consent.
   * @returns A new `ConsentReceipt`.
   */
  public generateConsentReceipt(
    request: ProofRequest,
    holderId: string,
    sharedAttributes: string[],
  ): ConsentReceipt {
    const now = Date.now();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

    return {
      id: this.generateId('consent'),
      timestamp: now,
      holderId,
      verifierId: request.verifierId,
      purpose: request.purpose,
      attributes: sharedAttributes.slice(),
      expiresAt: now + thirtyDaysMs,
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private generateId(prefix: string): string {
    const random = crypto.randomBytes(8).toString('hex');
    return `${prefix}-${Date.now()}-${random}`;
  }
}
