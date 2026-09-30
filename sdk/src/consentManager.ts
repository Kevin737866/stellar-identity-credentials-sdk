/**
 * Consent Management — Issue #190
 *
 * Provides a fine-grained, auditable consent layer so that holders can
 * explicitly grant and revoke permission for verifiers to access specific
 * credential attributes for a stated purpose.
 *
 * All state is held in an in-memory Map keyed by holderId.  Production
 * deployments should persist `ConsentRecord` objects to durable storage.
 */

// ─── Interfaces ───────────────────────────────────────────────────────────────

/**
 * A single scoped consent granted by a holder to a verifier for a specific
 * set of attributes and purpose.
 */
export interface ConsentScope {
  /** DID or address of the verifier who received consent. */
  verifierId: string;
  /** The attribute names covered by this consent grant. */
  attributes: string[];
  /** Human-readable purpose for which access was granted. */
  purpose: string;
  /** Unix epoch milliseconds when consent was granted. */
  grantedAt: number;
  /** Optional Unix epoch milliseconds after which this scope expires. */
  expiresAt?: number;
  /** Whether this scope is currently active (not revoked or expired). */
  isActive: boolean;
}

/**
 * One entry in the immutable audit log of consent lifecycle events.
 */
export interface ConsentHistoryEntry {
  /** Unix epoch milliseconds when the event occurred. */
  timestamp: number;
  /** The type of consent event. */
  action: 'grant' | 'revoke' | 'expire';
  /** DID or address of the verifier involved. */
  verifierId: string;
  /** Purpose associated with the event. */
  purpose: string;
  /** Attributes involved in the event. */
  attributes: string[];
}

/**
 * Aggregate consent record for a single holder, comprising all scopes and
 * the full history of consent lifecycle events.
 */
export interface ConsentRecord {
  /** Unique identifier for this record. */
  id: string;
  /** DID or address of the holder who owns this record. */
  holderId: string;
  /** All consent scopes, active and inactive. */
  scopes: ConsentScope[];
  /** Append-only audit history of all consent events. */
  history: ConsentHistoryEntry[];
}

// ─── ConsentManager ───────────────────────────────────────────────────────────

export class ConsentManager {

  /** Internal storage: holderId → ConsentRecord */
  private records: Map<string, ConsentRecord> = new Map();

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Grants scoped consent for a verifier to access specific attributes for a
   * stated purpose.  If a matching active scope already exists it is replaced.
   *
   * @param holderId   DID or address of the holder granting consent.
   * @param verifierId DID or address of the verifier receiving consent.
   * @param attributes The attribute names being shared.
   * @param purpose    Human-readable purpose for the access.
   * @param expiresAt  Optional expiry timestamp (Unix epoch ms).
   * @returns The updated `ConsentRecord` for the holder.
   */
  public grantConsent(
    holderId: string,
    verifierId: string,
    attributes: string[],
    purpose: string,
    expiresAt?: number,
  ): ConsentRecord {
    const record = this.getOrCreate(holderId);
    const now = Date.now();

    // Deactivate any existing scope for the same verifier+purpose pair
    for (const scope of record.scopes) {
      if (scope.verifierId === verifierId && scope.purpose === purpose && scope.isActive) {
        scope.isActive = false;
      }
    }

    // Add new active scope
    const newScope: ConsentScope = {
      verifierId,
      attributes: attributes.slice(),
      purpose,
      grantedAt: now,
      expiresAt,
      isActive: true,
    };
    record.scopes.push(newScope);

    // Append audit history entry
    record.history.push({
      timestamp: now,
      action: 'grant',
      verifierId,
      purpose,
      attributes: attributes.slice(),
    });

    return record;
  }

  /**
   * Revokes all active consent scopes for a given verifier+purpose pair.
   *
   * @param holderId   DID or address of the holder revoking consent.
   * @param verifierId DID or address of the verifier whose consent is revoked.
   * @param purpose    The purpose for which consent is being revoked.
   * @returns The updated `ConsentRecord` for the holder.
   * @throws `Error` when no consent record exists for the holder.
   */
  public revokeConsent(
    holderId: string,
    verifierId: string,
    purpose: string,
  ): ConsentRecord {
    const record = this.records.get(holderId);
    if (!record) {
      throw new Error(`No consent record found for holder '${holderId}'.`);
    }

    const now = Date.now();
    let revokedAttributes: string[] = [];

    for (const scope of record.scopes) {
      if (scope.verifierId === verifierId && scope.purpose === purpose && scope.isActive) {
        scope.isActive = false;
        revokedAttributes = [...revokedAttributes, ...scope.attributes];
      }
    }

    if (revokedAttributes.length === 0) {
      // Nothing was active — still record the attempt for auditability
      revokedAttributes = [];
    }

    record.history.push({
      timestamp: now,
      action: 'revoke',
      verifierId,
      purpose,
      attributes: [...new Set(revokedAttributes)], // deduplicate
    });

    return record;
  }

  /**
   * Checks whether the holder has active, non-expired consent for a verifier
   * to access all of the required attributes for the stated purpose.
   *
   * @param holderId           DID or address of the holder.
   * @param verifierId         DID or address of the verifier requesting access.
   * @param requiredAttributes Attributes the verifier wants to access.
   * @param purpose            The purpose of the access.
   * @returns `true` only if valid consent exists covering ALL required attributes.
   */
  public checkConsent(
    holderId: string,
    verifierId: string,
    requiredAttributes: string[],
    purpose: string,
  ): boolean {
    const record = this.records.get(holderId);
    if (!record) return false;

    const now = Date.now();

    // Collect all attributes covered by active, non-expired scopes for this
    // verifier+purpose combination
    const coveredAttributes = new Set<string>();
    for (const scope of record.scopes) {
      if (
        scope.verifierId === verifierId &&
        scope.purpose === purpose &&
        scope.isActive
      ) {
        // Check expiry
        if (scope.expiresAt !== undefined && now > scope.expiresAt) {
          continue; // Expired — do not count
        }
        for (const attr of scope.attributes) {
          coveredAttributes.add(attr);
        }
      }
    }

    // All required attributes must be covered
    return requiredAttributes.every(attr => coveredAttributes.has(attr));
  }

  /**
   * Returns the full consent history for a holder (append-only audit log).
   *
   * @param holderId DID or address of the holder.
   * @returns Array of `ConsentHistoryEntry` objects in chronological order.
   */
  public getConsentHistory(holderId: string): ConsentHistoryEntry[] {
    const record = this.records.get(holderId);
    if (!record) return [];
    return record.history.slice(); // Return a defensive copy
  }

  /**
   * Marks all expired scopes as inactive and appends 'expire' history entries.
   * Should be called periodically to keep records clean.
   *
   * @param holderId DID or address of the holder.
   * @returns The updated `ConsentRecord`, or `undefined` if none exists.
   */
  public purgeExpiredConsents(holderId: string): ConsentRecord | undefined {
    const record = this.records.get(holderId);
    if (!record) return undefined;

    const now = Date.now();

    for (const scope of record.scopes) {
      if (
        scope.isActive &&
        scope.expiresAt !== undefined &&
        now > scope.expiresAt
      ) {
        scope.isActive = false;

        record.history.push({
          timestamp: now,
          action: 'expire',
          verifierId: scope.verifierId,
          purpose: scope.purpose,
          attributes: scope.attributes.slice(),
        });
      }
    }

    return record;
  }

  /**
   * Returns the full `ConsentRecord` for a holder, or `undefined` if none
   * has been created yet.
   */
  public getRecord(holderId: string): ConsentRecord | undefined {
    return this.records.get(holderId);
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /** Gets an existing record or creates a new empty one. */
  private getOrCreate(holderId: string): ConsentRecord {
    let record = this.records.get(holderId);
    if (!record) {
      record = {
        id: `consent-record-${holderId}-${Date.now()}`,
        holderId,
        scopes: [],
        history: [],
      };
      this.records.set(holderId, record);
    }
    return record;
  }
}
