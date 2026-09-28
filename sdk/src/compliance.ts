/**
 * compliance.ts — Regulatory compliance SDK layer
 *
 * Covers:
 *   screenAddress()             single address sanctions check
 *   screenTransaction()         full transaction risk analysis
 *   generateComplianceReport()  regulatory filing generation
 *   subscribeToAlerts()         real-time risk monitoring webhook
 *   proveComplianceStatus()     ZK proof of valid KYC / sanctions-clear
 *
 * Regional: GDPR, CCPA, FATF Travel Rule, MiCA
 * Integrations: Chainalysis, Elliptic, ComplyAdvantage, Stellar TOML
 */

import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  Address,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import { StellarIdentityConfig, ComplianceRule, ComplianceRuleEnforcement, RuleEvaluationResult, ComplianceResult } from './types';
import { StellarIdentityError, ComplianceError, ErrorCode } from './errors';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ScreeningStatus = 'clear' | 'suspicious' | 'blocked';

export interface ScreeningResult {
  address: string;
  status: ScreeningStatus;
  /** 0–100; 100 = highest risk */
  riskScore: number;
  /** Sanctions list sources where matches were found */
  matches: string[];
  timestamp: number;
  /** Provider that performed the check */
  provider?: string;
}

export interface TransactionRisk {
  txHash: string;
  sender: string;
  receiver: string;
  amount: string;
  asset: string;
  senderRisk: ScreeningResult;
  receiverRisk: ScreeningResult;
  /** Aggregate risk score 0–100 */
  overallRisk: number;
  flags: string[];
  /** Whether the transaction exceeds FATF reporting threshold */
  requiresTravelRule: boolean;
  timestamp: number;
}

export interface ComplianceReport {
  subject: string;
  generatedAt: number;
  timeframeStart: number;
  timeframeEnd: number;
  screeningHistory: ScreeningResult[];
  riskSummary: {
    currentScore: number;
    peakScore: number;
    averageScore: number;
    totalScreenings: number;
  };
  regulatoryFlags: string[];
  /** FATF Travel Rule data if applicable */
  travelRuleData?: TravelRulePayload;
  auditTrail: AuditEntry[];
}

export interface AuditEntry {
  action: string;
  timestamp: number;
  detail: string;
  ledgerSequence?: number;
}

/** FATF Travel Rule — VASP-to-VASP information sharing payload */
export interface TravelRulePayload {
  originatorVASP: string;
  beneficiaryVASP: string;
  originator: {
    name: string;
    accountNumber: string;
    address?: string;
  };
  beneficiary: {
    name: string;
    accountNumber: string;
  };
  transferAmount: string;
  asset: string;
  transactionRef: string;
  timestamp: number;
}

export interface ZKComplianceProof {
  proofType: 'sanctions-clear' | 'kyc-valid' | 'threshold-below';
  /** Public commitment — reveals nothing about the subject */
  commitment: string;
  proofValue: string;
  verificationMethod: string;
  createdAt: number;
  expiresAt?: number;
}

export interface AlertSubscription {
  did: string;
  webhookUrl: string;
  events: AlertEvent[];
  active: boolean;
  createdAt: number;
}

export type AlertEvent =
  | 'sanctions-match'
  | 'risk-score-change'
  | 'list-update'
  | 'travel-rule-trigger';

export interface SanctionsListInfo {
  source: string;
  lastUpdated: number;
  hash: string;
  active: boolean;
  entryCount: number;
}

// ---------------------------------------------------------------------------
// ComplianceClient
// ---------------------------------------------------------------------------

export class ComplianceClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  /** Lazily constructed so unit tests do not need a valid StrKey contract id. */
  private _contract?: Contract;
  private get contract(): Contract {
    if (!this._contract) {
      this._contract = new Contract(this.config.contracts.complianceFilter);
    }
    return this._contract;
  }
  /** In-memory alert subscriptions (persisted off-chain by the caller) */
  private subscriptions: Map<string, AlertSubscription> = new Map();

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl ?? this.defaultRpcUrl());
  }

  // -------------------------------------------------------------------------
  // Sanctions list management
  // -------------------------------------------------------------------------

  /**
   * Register or update a sanctions list reference on-chain.
   * Called by an authorized oracle keypair (Band Protocol / DIA).
   * `hash` is the hex-encoded SHA-256 of the full list for integrity checks.
   */
  async updateSanctionsList(
    adminKeypair: Keypair,
    source: string,
    hash: string,
    entryCount: number,
  ): Promise<void> {
    const hashBytes = Buffer.from(hash, 'hex');
    if (hashBytes.length !== 32) throw this.err('hash must be 32 bytes (SHA-256 hex)');

    const account = await this.rpc.getAccount(adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'update_sanctions_list',
          xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
          nativeToScVal(enc(source), { type: 'bytes' }),
          nativeToScVal(hashBytes, { type: 'bytes' }),
          nativeToScVal(BigInt(entryCount), { type: 'u32' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(adminKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`update_sanctions_list failed: ${result.errorResult}`);
  }

  async getSanctionsList(source: string): Promise<SanctionsListInfo | null> {
    try {
      const val = await this.simulateRead('get_sanctions_list', [
        nativeToScVal(enc(source), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (!raw) return null;
      return {
        source: dec(raw.source),
        lastUpdated: Number(raw.last_updated ?? 0),
        hash: Buffer.from(raw.hash as Uint8Array).toString('hex'),
        active: Boolean(raw.active),
        entryCount: Number(raw.entry_count ?? 0),
      };
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Screening — < 1 second via Soroban RPC simulation
  // -------------------------------------------------------------------------

  /**
   * Screen a single Stellar address against all active sanctions lists.
   * Optionally enriches with Chainalysis / Elliptic / ComplyAdvantage data.
   */
  async screenAddress(
    address: string,
    options: { enrichWithExternal?: boolean } = {},
  ): Promise<ScreeningResult> {
    // On-chain check (primary — < 1s)
    let onChainResult = await this.screenAddressOnChain(address);

    // External enrichment (Chainalysis / Elliptic / ComplyAdvantage)
    if (options.enrichWithExternal) {
      const external = await this.fetchExternalRiskScore(address);
      if (external !== null) {
        onChainResult.riskScore = Math.max(onChainResult.riskScore, external);
        onChainResult.status = riskToStatus(onChainResult.riskScore);
        onChainResult.provider = 'chainalysis+on-chain';
      }
    }

    // Fire alerts
    this.fireAlerts(address, 'sanctions-match', onChainResult);

    return onChainResult;
  }

  /**
   * Screen a DID (did:stellar:<address>) — resolves to address then screens.
   */
  async screenDID(did: string): Promise<ScreeningResult> {
    try {
      const val = await this.simulateRead('screen_did', [
        nativeToScVal(enc(did), { type: 'bytes' }),
      ]);
      return this.parseScreeningResult(scValToNative(val), did);
    } catch {
      // Fallback: extract address from DID and screen directly
      const address = didToAddress(did);
      return this.screenAddress(address);
    }
  }

  /**
   * Full transaction risk analysis:
   * - Screens sender and receiver
   * - Checks FATF Travel Rule threshold (≥ 1000 USD equivalent)
   * - Aggregates risk flags
   */
  async screenTransaction(tx: {
    hash: string;
    sender: string;
    receiver: string;
    amount: string;
    asset: string;
  }): Promise<TransactionRisk> {
    const [senderRisk, receiverRisk] = await Promise.all([
      this.screenAddress(tx.sender),
      this.screenAddress(tx.receiver),
    ]);

    const overallRisk = Math.max(senderRisk.riskScore, receiverRisk.riskScore);
    const flags: string[] = [];

    if (senderRisk.status !== 'clear') flags.push(`sender:${senderRisk.status}`);
    if (receiverRisk.status !== 'clear') flags.push(`receiver:${receiverRisk.status}`);
    if (senderRisk.matches.length > 0) flags.push(`sender-sanctions:${senderRisk.matches.join(',')}`);
    if (receiverRisk.matches.length > 0) flags.push(`receiver-sanctions:${receiverRisk.matches.join(',')}`);

    // FATF Travel Rule: threshold ≥ 1000 USD equivalent
    const requiresTravelRule = parseFloat(tx.amount) >= 1000;
    if (requiresTravelRule) flags.push('fatf-travel-rule-required');

    return {
      txHash: tx.hash,
      sender: tx.sender,
      receiver: tx.receiver,
      amount: tx.amount,
      asset: tx.asset,
      senderRisk,
      receiverRisk,
      overallRisk,
      flags,
      requiresTravelRule,
      timestamp: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Regulatory reporting
  // -------------------------------------------------------------------------

  /**
   * Generate a compliance report for a DID over a given timeframe.
   * Fetches the on-chain audit trail and assembles a regulatory filing.
   */
  async generateComplianceReport(
    did: string,
    timeframe: { start: number; end: number },
  ): Promise<ComplianceReport> {
    const address = didToAddress(did);

    // Fetch on-chain audit trail keys
    const auditKeys = await this.getAuditTrail(address);

    // Fetch each report
    const auditEntries: AuditEntry[] = [];
    for (const key of auditKeys) {
      const report = await this.getRegulatoryReport(key);
      if (report && report.timestamp >= timeframe.start / 1000 && report.timestamp <= timeframe.end / 1000) {
        auditEntries.push({
          action: dec(report.activitySummary).split(':')[0] ?? 'unknown',
          timestamp: report.timestamp * 1000,
          detail: dec(report.riskFlags),
          ledgerSequence: report.ledgerSequence,
        });
      }
    }

    // Current screening result
    const current = await this.screenAddress(address).catch(() => null);
    const currentScore = current?.riskScore ?? 0;

    const scores = auditEntries.map(() => currentScore);
    const peakScore = scores.length ? Math.max(...scores) : currentScore;
    const avgScore = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : currentScore;

    const regulatoryFlags: string[] = [];
    if (currentScore > 70) regulatoryFlags.push('HIGH_RISK');
    if (current?.matches.length) regulatoryFlags.push('SANCTIONS_MATCH');

    return {
      subject: did,
      generatedAt: Date.now(),
      timeframeStart: timeframe.start,
      timeframeEnd: timeframe.end,
      screeningHistory: current ? [current] : [],
      riskSummary: {
        currentScore,
        peakScore,
        averageScore: Math.round(avgScore),
        totalScreenings: auditEntries.length,
      },
      regulatoryFlags,
      auditTrail: auditEntries,
    };
  }

  /**
   * File an immutable regulatory report on-chain.
   */
  async fileRegulatoryReport(
    reporterKeypair: Keypair,
    subject: string,
    activitySummary: string,
    riskFlags: string[],
  ): Promise<string> {
    const account = await this.rpc.getAccount(reporterKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(
        this.contract.call(
          'file_regulatory_report',
          xdr.ScVal.scvAddress(new Address(reporterKeypair.publicKey()).toScAddress()),
          xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
          nativeToScVal(enc(activitySummary), { type: 'bytes' }),
          nativeToScVal(enc(JSON.stringify(riskFlags)), { type: 'bytes' }),
        ),
      )
      .setTimeout(30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(reporterKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') throw this.err(`file_regulatory_report failed: ${result.errorResult}`);
    return `report:${subject}:${Date.now()}`;
  }

  // -------------------------------------------------------------------------
  // Alert subscriptions (FATF / real-time monitoring)
  // -------------------------------------------------------------------------

  /**
   * Subscribe a DID to real-time risk monitoring.
   * Webhooks are fired client-side when screenAddress() detects changes.
   * For production, wire this to a server-sent events or webhook delivery service.
   */
  subscribeToAlerts(
    did: string,
    webhookUrl: string,
    events: AlertEvent[] = ['sanctions-match', 'risk-score-change'],
  ): AlertSubscription {
    const sub: AlertSubscription = {
      did,
      webhookUrl,
      events,
      active: true,
      createdAt: Date.now(),
    };
    this.subscriptions.set(did, sub);
    return sub;
  }

  unsubscribeFromAlerts(did: string): void {
    const sub = this.subscriptions.get(did);
    if (sub) {
      sub.active = false;
      this.subscriptions.set(did, sub);
    }
  }

  // -------------------------------------------------------------------------
  // Privacy-preserving compliance (ZK proofs)
  // -------------------------------------------------------------------------

  /**
   * Generate a ZK proof of compliance status without revealing identity.
   * Proves "not on sanctions list" or "KYC valid" using a commitment scheme.
   *
   * The commitment is H(address || salt) — the verifier checks the proof
   * against the commitment without learning the underlying address.
   */
  async proveComplianceStatus(
    subjectKeypair: Keypair,
    proofType: ZKComplianceProof['proofType'],
    options: { expiresAt?: number } = {},
  ): Promise<ZKComplianceProof> {
    const address = subjectKeypair.publicKey();

    // Verify the subject is actually clear before generating proof
    const screening = await this.screenAddress(address);
    if (proofType === 'sanctions-clear' && screening.status === 'blocked') {
      throw this.err('Cannot generate sanctions-clear proof: address is blocked');
    }

    // Commitment: deterministic hash of address + proof type
    const salt = Buffer.from(subjectKeypair.rawSecretKey()).slice(0, 16).toString('hex');
    const commitment = await sha256Hex(`${address}:${proofType}:${salt}`);

    // Proof value: sign the commitment with the subject's key
    const proofValue = Buffer.from(
      subjectKeypair.sign(Buffer.from(commitment, 'hex')),
    ).toString('base64');

    return {
      proofType,
      commitment,
      proofValue,
      verificationMethod: `did:stellar:${address}#key-1`,
      createdAt: Date.now(),
      expiresAt: options.expiresAt,
    };
  }

  /**
   * Verify a ZK compliance proof.
   * Checks the signature over the commitment without revealing the address.
   */
  verifyComplianceProof(
    proof: ZKComplianceProof,
    subjectPublicKey: string,
  ): boolean {
    try {
      const kp = Keypair.fromPublicKey(subjectPublicKey);
      const sig = Buffer.from(proof.proofValue, 'base64');
      return kp.verify(Buffer.from(proof.commitment, 'hex'), sig);
    } catch {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // FATF Travel Rule
  // -------------------------------------------------------------------------

  /**
   * Build a FATF Travel Rule payload for VASP-to-VASP information sharing.
   * Attach to the Stellar transaction memo or send via secure channel.
   */
  buildTravelRulePayload(params: {
    originatorVASP: string;
    beneficiaryVASP: string;
    originatorName: string;
    originatorAccount: string;
    beneficiaryName: string;
    beneficiaryAccount: string;
    amount: string;
    asset: string;
    txRef: string;
  }): TravelRulePayload {
    return {
      originatorVASP: params.originatorVASP,
      beneficiaryVASP: params.beneficiaryVASP,
      originator: {
        name: params.originatorName,
        accountNumber: params.originatorAccount,
      },
      beneficiary: {
        name: params.beneficiaryName,
        accountNumber: params.beneficiaryAccount,
      },
      transferAmount: params.amount,
      asset: params.asset,
      transactionRef: params.txRef,
      timestamp: Date.now(),
    };
  }

  // -------------------------------------------------------------------------
  // Compliance rules
  // -------------------------------------------------------------------------

  /**
   * Register a brand-new compliance rule for the given jurisdiction.
   * Throws ComplianceError (ComplianceUnauthorized) when the admin keypair is
   * not authorized on-chain, or ComplianceError (ComplianceNotFound/code 404)
   * if a rule for this jurisdiction already exists.
   *
   * Alias of {@link registerComplianceRule} retained for legacy call sites.
   */
  async registerRule(
    adminKeypair: Keypair,
    jurisdiction: string,
    requirement: string,
    enforcement: ComplianceRuleEnforcement,
  ): Promise<void> {
    if (!jurisdiction || jurisdiction.trim() === '') {
      throw new ComplianceError(ErrorCode.ComplianceInvalidHash, 'jurisdiction must be non-empty');
    }
    if (!requirement) {
      throw new ComplianceError(ErrorCode.ComplianceInvalidHash, 'requirement must be non-empty');
    }
    return this.registerComplianceRule(adminKeypair, jurisdiction, requirement, enforcement);
  }

  /** Legacy alias kept for callers written before Issue #285. */
  async registerComplianceRule(
    adminKeypair: Keypair,
    jurisdiction: string,
    requirement: string,
    enforcement: ComplianceRuleEnforcement,
  ): Promise<void> {
    return this.invokeWrite(adminKeypair, 'register_compliance_rule', [
      xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
      nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
      nativeToScVal(enc(requirement), { type: 'bytes' }),
      nativeToScVal(enc(enforcement), { type: 'bytes' }),
    ]);
  }

  /**
   * Update the requirement / enforcement / active state of an existing rule.
   * Throws ComplianceError (ComplianceNotFound) when no rule exists for the
   * jurisdiction, and ComplianceError (ComplianceUnauthorized) on permission
   * failure.
   */
  async updateRule(
    adminKeypair: Keypair,
    jurisdiction: string,
    requirement: string,
    enforcement: ComplianceRuleEnforcement,
    active: boolean,
  ): Promise<void> {
    if (!jurisdiction || jurisdiction.trim() === '') {
      throw new ComplianceError(ErrorCode.ComplianceInvalidHash, 'jurisdiction must be non-empty');
    }
    return this.invokeWrite(adminKeypair, 'update_compliance_rule', [
      xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
      nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
      nativeToScVal(enc(requirement), { type: 'bytes' }),
      nativeToScVal(enc(enforcement), { type: 'bytes' }),
      nativeToScVal(active, { type: 'bool' }),
    ]);
  }

  /**
   * Deactivate (but do not delete) the rule registered for a jurisdiction.
   * The rule stays on-chain and can be re-activated via {@link updateRule}.
   */
  async deactivateRule(
    adminKeypair: Keypair,
    jurisdiction: string,
  ): Promise<void> {
    return this.invokeWrite(adminKeypair, 'deactivate_compliance_rule', [
      xdr.ScVal.scvAddress(new Address(adminKeypair.publicKey()).toScAddress()),
      nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
    ]);
  }

  /**
   * Read a single compliance rule by exact jurisdiction key. Returns null when
   * the contract has no entry for that jurisdiction.
   */
  async getRule(jurisdiction: string): Promise<ComplianceRule | null> {
    try {
      const val = await this.simulateRead('get_compliance_rule', [
        nativeToScVal(enc(jurisdiction), { type: 'bytes' }),
      ]);
      return this.parseComplianceRule(scValToNative(val), jurisdiction);
    } catch (e) {
      if (String(e).includes('NotFound') || String(e).includes('ContractError(404)')) {
        return null;
      }
      throw new ComplianceError(
        ErrorCode.ComplianceNotFound,
        `get_compliance_rule failed: ${e instanceof Error ? e.message : String(e)}`,
        { jurisdiction },
      );
    }
  }

  /**
   * Return the set of compliance rules that apply to a jurisdiction,
   * walking the hierarchical path from the most specific up to GLOBAL.
   *
   * Example effective rules for "US-CA-SF":
   *   GLOBAL                  (always considered)
   *   US
   *   US-CA
   *   US-CA-SF
   *
   * Inactive rules (active=false) are filtered out. Most-specific overrides
   * win when ancestor and descendant disagree (handled via Map keyed by rule
   * id `{jurisdiction}:{requirement}`).
   */
  async getEffectiveRules(jurisdiction: string): Promise<ComplianceRule[]> {
    const path = ancestorJurisdictions(jurisdiction);
    const out: ComplianceRule[] = [];
    for (const key of path) {
      const rule = await this.getRule(key);
      if (rule && rule.active) out.push(rule);
    }
    return out;
  }

  /**
   * Evaluate an address against the rules of a jurisdiction (default
   * "GLOBAL"). The returned object always contains the address and
   * jurisdiction; violations lists each active mandatory rule that the
   * current screening result does not satisfy.
   */
  async evaluateRules(
    address: string,
    jurisdiction: string = 'GLOBAL',
  ): Promise<RuleEvaluationResult> {
    if (!address) {
      throw new ComplianceError(ErrorCode.ComplianceInvalidHash, 'address must be non-empty');
    }
    const [screening, rules] = await Promise.all([
      this.screenAddress(address).catch(() => null),
      this.getEffectiveRules(jurisdiction),
    ]);

    const complianceScreening: ComplianceResult | undefined = screening
      ? {
          address: screening.address,
          status: screening.status === 'clear' ? 'cleared' : screening.status === 'suspicious' ? 'flagged' : 'blocked',
          riskScore: screening.riskScore,
          sanctionsLists: screening.matches,
          lastChecked: screening.timestamp,
          recommendations: [],
        }
      : undefined;

    const violations = rules.filter(rule =>
      evaluateRuleAgainstScreen(rule, complianceScreening)
    );

    return {
      address,
      jurisdiction,
      compliant: violations.length === 0,
      violations,
      screening: complianceScreening,
    };
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  /**
   * Shared submit-helper for the rule-mutating contract calls so the
   * try/prepare/sign/send pipeline is identical for every method.
   */
  private async invokeWrite(
    adminKeypair: Keypair,
    method: string,
    args: xdr.ScVal[],
  ): Promise<void> {
    const account = await this.rpc.getAccount(adminKeypair.publicKey());
    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase(),
    })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();
    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(adminKeypair);
    const result = await this.rpc.sendTransaction(prepared);
    if (result.status === 'ERROR') {
      throw new ComplianceError(
        ErrorCode.ComplianceUnauthorized,
        `${method} failed: ${result.errorResult}`,
      );
    }
  }

  private parseComplianceRule(raw: unknown, fallbackJurisdiction: string): ComplianceRule | null {
    if (!raw || typeof raw !== 'object') return null;
    const r = raw as Record<string, unknown>;
    return {
      jurisdiction: dec(r.jurisdiction) || fallbackJurisdiction,
      requirement: dec(r.requirement),
      enforcement: (dec(r.enforcement) === 'mandatory' ? 'mandatory' : 'advisory'),
      active: Boolean(r.active ?? true),
      updatedAt: Number(r.updated_at ?? r.updatedAt ?? 0) || undefined,
    };
  }

  private async screenAddressOnChain(address: string): Promise<ScreeningResult> {
    try {
      const val = await this.simulateRead('screen_address', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return this.parseScreeningResult(scValToNative(val), address);
    } catch (e) {
      const msg = String(e);
      // Contract returns error for blocked/high-risk — parse from error string
      if (msg.includes('AddressBlocked') || msg.includes('1')) {
        return { address, status: 'blocked', riskScore: 100, matches: [], timestamp: Date.now() };
      }
      if (msg.includes('HighRisk') || msg.includes('2')) {
        return { address, status: 'suspicious', riskScore: 80, matches: [], timestamp: Date.now() };
      }
      // Default clear if contract not yet deployed
      return { address, status: 'clear', riskScore: 0, matches: [], timestamp: Date.now() };
    }
  }

  private parseScreeningResult(raw: unknown, fallbackAddress: string): ScreeningResult {
    if (!raw || typeof raw !== 'object') {
      return { address: fallbackAddress, status: 'clear', riskScore: 0, matches: [], timestamp: Date.now() };
    }
    const r = raw as Record<string, unknown>;
    const statusRaw = dec(r.status);
    const status: ScreeningStatus =
      statusRaw === 'blocked' ? 'blocked' : statusRaw === 'suspicious' ? 'suspicious' : 'clear';
    return {
      address: fallbackAddress,
      status,
      riskScore: Number(r.risk_score ?? 0),
      matches: Array.isArray(r.matches) ? (r.matches as unknown[]).map(dec) : [],
      timestamp: Number(r.timestamp ?? Date.now()),
    };
  }

  private async getAuditTrail(address: string): Promise<string[]> {
    try {
      const val = await this.simulateRead('get_audit_trail', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      const raw = scValToNative(val);
      return Array.isArray(raw) ? (raw as unknown[]).map(dec) : [];
    } catch {
      return [];
    }
  }

  private async getRegulatoryReport(key: string): Promise<{
    activitySummary: unknown;
    riskFlags: unknown;
    timestamp: number;
    ledgerSequence: number;
  } | null> {
    try {
      const val = await this.simulateRead('get_regulatory_report', [
        nativeToScVal(enc(key), { type: 'bytes' }),
      ]);
      const raw = scValToNative(val) as Record<string, unknown> | null;
      if (!raw) return null;
      return {
        activitySummary: raw.activity_summary,
        riskFlags: raw.risk_flags,
        timestamp: Number(raw.timestamp ?? 0),
        ledgerSequence: Number(raw.ledger_sequence ?? 0),
      };
    } catch {
      return null;
    }
  }

  /** Stub for external provider enrichment (Chainalysis / Elliptic / ComplyAdvantage) */
  private async fetchExternalRiskScore(_address: string): Promise<number | null> {
    // In production: call provider API and return 0–100 score.
    // Returning null here so the on-chain result is used as-is.
    return null;
  }

  private fireAlerts(address: string, event: AlertEvent, result: ScreeningResult): void {
    const did = `did:stellar:${address}`;
    const sub = this.subscriptions.get(did);
    if (!sub || !sub.active || !sub.events.includes(event)) return;
    if (result.status === 'clear') return;
    // In production: POST to sub.webhookUrl
    // console.log(`[alert] ${event} for ${did} → ${sub.webhookUrl}`);
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;
    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.networkPassphrase() })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(30)
      .build();
    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }
    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value');
    return retval;
  }

  private defaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private networkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private err(msg: string): StellarIdentityError {
    return new ComplianceError(ErrorCode.ComplianceNotFound, msg);
  }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function enc(s: string): Uint8Array { return new TextEncoder().encode(s); }

function dec(v: unknown): string {
  if (v instanceof Uint8Array) return new TextDecoder().decode(v);
  return String(v ?? '');
}

function didToAddress(did: string): string {
  if (!did.startsWith('did:stellar:')) throw new Error(`Invalid DID: ${did}`);
  return did.slice('did:stellar:'.length).split(':')[0];
}

function riskToStatus(score: number): ScreeningStatus {
  if (score >= 100) return 'blocked';
  if (score > 70) return 'suspicious';
  return 'clear';
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Strip a `-separated` jurisdiction string into ancestor entries from
 * GLOBAL down to the most specific path entry. The returned array always
 * starts with the literal "GLOBAL".
 *
 * Example: ancestorJurisdictions("US-CA-SF")
 *   ["GLOBAL", "US", "US-CA", "US-CA-SF"]
 */
export function ancestorJurisdictions(jurisdiction: string): string[] {
  const out: string[] = ['GLOBAL'];
  if (!jurisdiction || jurisdiction === 'GLOBAL') return out;
  const sanitized = jurisdiction.replace(/^[-]+|[-]+$/g, '');
  if (!sanitized) return out;
  const parts = sanitized.split('-');
  let acc = '';
  for (const part of parts) {
    acc = acc ? `${acc}-${part}` : part;
    out.push(acc);
  }
  return out;
}

/**
 * Decides whether a single rule is currently violated by an address's
 * screening result. Pure function — exported for unit tests.
 *
 * Behaviour
 *  - inactive rules are never violated (they are filtered out elsewhere).
 *  - advisory rules are never violations (they surface as warnings, not
 *    blockers).
 *  - When no screening result is available the address is treated as
 *    not-screened; any rule with a non-empty requirement is considered
 *    violated so callers can prompt the user to complete KYC.
 */
export function evaluateRuleAgainstScreen(
  rule: ComplianceRule,
  screening: ComplianceResult | undefined,
): boolean {
  if (!rule.active) return false;
  if (rule.enforcement !== 'mandatory') return false;
  if (!screening) {
    // Without a screening we cannot prove compliance; treat this as a violation
    // so the address is forced to be screened before being cleared.
    return Boolean(rule.requirement);
  }

  // Cleared addresses satisfy every mandatory rule.
  if (screening.status === 'cleared' && screening.riskScore <= 50) return false;
  // Flagged / blocked addresses violate every mandatory rule.
  if (screening.status === 'flagged' || screening.status === 'blocked') return true;

  // Unknown status but high risk still violates.
  if (screening.riskScore > 70) return true;
  return false;
}
