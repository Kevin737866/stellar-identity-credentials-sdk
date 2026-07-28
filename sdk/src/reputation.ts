import CryptoJS from 'crypto-js';
import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  Address,
  Account,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import {
  ReputationBreakdown,
  ReputationComparison,
  ReputationData,
  ReputationFactors,
  ReputationHistoryPoint,
  ReputationScoreResult,
  ReputationTierProof,
  StellarIdentityConfig,
  TransactionOptions,
  TrustAttestation,
  TrustEdge,
  TrustGraph,
  TrustPath,
} from './types';
import { StellarIdentityError, ReputationError, mapContractError, ErrorCode } from './errors';
import {
  aggregateTrustWeight,
  findTrustPathsBFS,
  recommendTrustEntities,
} from './trustGraph';

/**
 * Client for managing on-chain reputation scores on Stellar.
 * Calculates reputation from transaction history, credential validity,
 * trust attestations, and network activity. Supports tier-based scoring
 * from Seedling through Prime.
 * @category Client
 */
export class ReputationClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  /** Lazily constructed so unit tests do not need a real StrKey contract id. */
  private _reputationScoreContract?: Contract;
  private get reputationScoreContract(): Contract {
    if (!this._reputationScoreContract) {
      this._reputationScoreContract = new Contract(this.config.contracts.reputationScore);
    }
    return this._reputationScoreContract;
  }

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
  }

  async initializeReputation(keypair: Keypair, txOptions?: TransactionOptions): Promise<ReputationData> {
    const address = keypair.publicKey();
    const retval = await this.invokeWrite(keypair, 'initialize_reputation', [
      xdr.ScVal.scvAddress(new Address(address).toScAddress()),
    ], txOptions);
    return this.parseReputationData(scValToNative(retval));
  }

  async updateReputation(
    keypair: Keypair,
    did: string,
    eventType: string,
    metadata: Record<string, number>,
    txOptions?: TransactionOptions,
  ): Promise<ReputationBreakdown> {
    const retval = await this.invokeWrite(keypair, 'update_reputation', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(eventType, { type: 'symbol' }),
      this.toMetadataMap(metadata),
    ], txOptions);

    return this.toBreakdown(this.parseReputationData(scValToNative(retval)), await this.getReputationPercentile(did));
  }

  async updateTransactionReputation(
    keypair: Keypair,
    did: string,
    successful: boolean,
    amount: number,
    txOptions?: TransactionOptions,
  ): Promise<number> {
    const retval = await this.invokeWrite(keypair, 'update_transaction_reputation', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(successful),
      nativeToScVal(BigInt(Math.max(0, Math.trunc(amount))), { type: 'u64' }),
    ], txOptions);

    return this.normalizeScore(scValToNative(retval));
  }

  async updateCredentialReputation(
    keypair: Keypair,
    did: string,
    credentialValid: boolean,
    credentialType: string,
    txOptions?: TransactionOptions,
  ): Promise<number> {
    const retval = await this.invokeWrite(keypair, 'update_credential_reputation', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(credentialValid),
      nativeToScVal(new TextEncoder().encode(credentialType), { type: 'bytes' }),
    ], txOptions);

    return this.normalizeScore(scValToNative(retval));
  }

  async calculateReputation(did: string): Promise<number> {
    const retval = await this.simulateRead('calculate_reputation', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
    ]);
    return this.normalizeScore(scValToNative(retval));
  }

  /**
   * Get a comprehensive reputation score breakdown including factors and percentile.
   * @param did - The DID or Stellar address to query
   * @returns Reputation breakdown with score, tier, and factor details
   */
  async getReputationScore(did: string): Promise<ReputationBreakdown> {
    const [data, percentile] = await Promise.all([
      this.getReputationData(did),
      this.getReputationPercentile(did),
    ]);
    return this.toBreakdown(data, percentile);
  }

  async getReputationScoreValue(did: string): Promise<number> {
    const retval = await this.simulateRead('get_reputation_score', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
    ]);
    return this.normalizeScore(scValToNative(retval));
  }

  async getReputationData(did: string): Promise<ReputationData> {
    const retval = await this.simulateRead('get_reputation_data', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
    ]);
    return this.parseReputationData(scValToNative(retval));
  }

  async getReputationHistory(did: string, timeframe: string | number = '90d'): Promise<ReputationHistoryPoint[]> {
    const retval = await this.simulateRead('get_reputation_history', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(BigInt(120), { type: 'u32' }),
    ]);

    const history = this.parseHistory(scValToNative(retval));
    const windowMs = this.parseTimeframe(timeframe);
    if (!windowMs) return history;

    const cutoff = Date.now() - windowMs;
    return history.filter(point => point.timestamp * 1000 >= cutoff);
  }

  async attestTrust(
    keypair: Keypair,
    subjectDID: string,
    score: number,
    reason: string,
    txOptions?: TransactionOptions,
  ): Promise<TrustEdge> {
    const clamped = Math.max(0, Math.min(1000, Math.round(score)));
    const retval = await this.invokeWrite(keypair, 'attest_trust', [
      xdr.ScVal.scvAddress(new Address(keypair.publicKey()).toScAddress()),
      xdr.ScVal.scvAddress(new Address(subjectDID).toScAddress()),
      nativeToScVal(BigInt(clamped), { type: 'u32' }),
      nativeToScVal(new TextEncoder().encode(reason), { type: 'bytes' }),
    ], txOptions);

    return this.parseTrustEdge(scValToNative(retval));
  }

  async getTrustGraph(did: string, depth = 2): Promise<TrustEdge[]> {
    const retval = await this.simulateRead('get_trust_graph', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(BigInt(depth), { type: 'u32' }),
    ]);
    return this.parseTrustGraph(scValToNative(retval));
  }

  /**
   * Read the chronological list of trust attestations emitted for `subject`.
   * Mirrors `getTrustGraph` in payload shape but represents a history view
   * instead of an aggregate state.
   *
   * Implementation note: when the on-chain `get_trust_attestations` is not
   * yet deployed, the SDK returns the flattened TrustEdge[] graph as a
   * stand-in so callers can build UIs against the same attestation type
   * shape during development.
   */
  async getTrustAttestations(subject: string): Promise<TrustAttestation[]> {
    try {
      const retval = await this.simulateRead('get_trust_attestations', [
        xdr.ScVal.scvAddress(new Address(subject).toScAddress()),
      ]);
      const raw = scValToNative(retval);
      if (Array.isArray(raw)) {
        return raw.map(item => this.parseAttestation(item));
      }
      return [];
    } catch {
      // Fallback: surface the current trust graph as attestation history.
      const edges = await this.getTrustGraph(subject, 1);
      return edges.map(edge => ({ ...edge }));
    }
  }

  /**
   * Build a typed trust-graph snapshot rooted at `subject`. Wraps the
   * existing {@link getTrustGraph} call so callers can hand the snapshot
   * to client-side algorithms without re-fetching.
   */
  async getTrustGraphSnapshot(subject: string, depth = 2): Promise<TrustGraph> {
    const edges = await this.getTrustGraph(subject, depth);
    const nodes = new Set<string>([subject, ...edges.map(e => e.truster)]);
    return { subject, depth, edges, nodes: Array.from(nodes) };
  }

  /**
   * Find every trust path from `from` to `to` bounded by `maxDepth` hops.
   * The search is performed client-side over the trusted-of-trusted view
   * returned by {@link getTrustGraph}, so it does not require a separate
   * contract call.
   *
   * The returned array is sorted by descending `cumulativeWeight` so the
   * strongest path is at index 0.
   */
  async findTrustPaths(
    from: string,
    to: string,
    maxDepth = 3,
  ): Promise<TrustPath[]> {
    if (maxDepth < 1) {
      throw new ReputationError(ErrorCode.ReputationInvalidDepth, 'maxDepth must be >= 1');
    }
    const graph = await this.getTrustGraphSnapshot(from, maxDepth);
    return findTrustPathsBFS(from, to, graph.edges, maxDepth);
  }

  /**
   * Sum the inbound trust weights for `subject` across all currently-active
   * attestations. Self-attestations are excluded to avoid circular shadowing
   * of the result.
   */
  async getAggregateTrustWeight(subject: string): Promise<number> {
    const graph = await this.getTrustGraphSnapshot(subject, 1);
    return aggregateTrustWeight(graph.edges, subject);
  }

  /**
   * Recommend entities that `address` does not already directly trust but
   * which are strongly vouched for by entities `address` already trusts.
   * Mirrors a simple "friends of friends" walk over a depth-2 graph.
   */
  async getTrustRecommendations(address: string, limit = 5): Promise<string[]> {
    if (limit < 1) {
      throw new ReputationError(ErrorCode.ReputationInvalidDepth, 'limit must be >= 1');
    }
    const graph = await this.getTrustGraphSnapshot(address, 2);
    return recommendTrustEntities(graph.edges, address, limit);
  }

  async compareReputation(didA: string, didB: string): Promise<ReputationComparison> {
    const [profileA, profileB] = await Promise.all([
      this.getReputationScore(didA),
      this.getReputationScore(didB),
    ]);

    const deltaFactors: ReputationFactors = {
      transactionVolume: profileA.factors.transactionVolume - profileB.factors.transactionVolume,
      transactionConsistency: profileA.factors.transactionConsistency - profileB.factors.transactionConsistency,
      credentialCount: profileA.factors.credentialCount - profileB.factors.credentialCount,
      credentialDiversity: profileA.factors.credentialDiversity - profileB.factors.credentialDiversity,
      accountAge: profileA.factors.accountAge - profileB.factors.accountAge,
      disputeHistory: profileA.factors.disputeHistory - profileB.factors.disputeHistory,
    };

    return {
      didA: profileA,
      didB: profileB,
      delta: {
        score: Number((profileA.score - profileB.score).toFixed(1)),
        percentile: profileA.percentile - profileB.percentile,
        factors: deltaFactors,
      },
      winner: profileA.score === profileB.score ? 'tie' : profileA.score > profileB.score ? 'didA' : 'didB',
    };
  }

  async getReputationPercentile(did: string): Promise<number> {
    const retval = await this.simulateRead('get_reputation_percentile', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
    ]);
    return Number(scValToNative(retval));
  }

  async meetsReputationThreshold(did: string, threshold: number): Promise<boolean> {
    const retval = await this.simulateRead('meets_reputation_threshold', [
      xdr.ScVal.scvAddress(new Address(did).toScAddress()),
      nativeToScVal(BigInt(Math.round(threshold)), { type: 'u32' }),
    ]);
    return Boolean(scValToNative(retval));
  }

  async getReputationFactors(did: string): Promise<Record<string, number>> {
    const data = await this.getReputationScore(did);
    return { ...data.factors };
  }

  async resetReputation(keypair: Keypair, txOptions?: TransactionOptions): Promise<ReputationData> {
    const retval = await this.invokeWrite(keypair, 'reset_reputation', [
      xdr.ScVal.scvAddress(new Address(keypair.publicKey()).toScAddress()),
    ], txOptions);
    return this.parseReputationData(scValToNative(retval));
  }

  /**
   * Get a full reputation analysis including score, percentile, history, and recommendations.
   * @param did - The DID or Stellar address to analyze
   * @returns Comprehensive reputation analysis
   */
  async getReputationAnalysis(did: string): Promise<ReputationScoreResult> {
    const [snapshot, history] = await Promise.all([
      this.getReputationScore(did),
      this.getReputationHistory(did, '180d'),
    ]);

    return {
      score: snapshot.score,
      percentile: snapshot.percentile,
      factors: { ...snapshot.factors },
      history: history.map(point => point.score),
      lastUpdated: snapshot.lastUpdated,
    };
  }

  async getReputationTierProof(did: string, nonce = `${Date.now()}`): Promise<ReputationTierProof> {
    const snapshot = await this.getReputationScore(did);
    const scoreRange = this.getTierRange(snapshot.tier);
    const commitment = CryptoJS.SHA256(`${did}:${snapshot.tier}:${nonce}`).toString();

    return {
      did,
      tier: snapshot.tier,
      scoreRange,
      commitment,
      generatedAt: Date.now(),
    };
  }

  getReputationTier(score: number): { tier: string; color: string; description: string } {
    if (score >= 900) return { tier: 'Prime', color: '#0F766E', description: 'Deep history, verified credentials, and strong network trust.' };
    if (score >= 750) return { tier: 'Strong', color: '#2563EB', description: 'Reliable activity profile suitable for governance and lending.' };
    if (score >= 550) return { tier: 'Established', color: '#D97706', description: 'Moderate trust with room to deepen signal diversity.' };
    if (score >= 300) return { tier: 'Emerging', color: '#DC2626', description: 'Early-stage reputation with limited history.' };
    return { tier: 'Seedling', color: '#6B7280', description: 'Sybil-resistant base tier for new or lightly used accounts.' };
  }

  /**
   * Calculate the trend of reputation changes from historical data.
   * @param history - Array of historical score values
   * @returns Trend direction, absolute change, and percentage change
   */
  calculateReputationTrend(history: number[]): { trend: 'up' | 'down' | 'stable'; change: number; percentage: number } {
    if (history.length < 2) return { trend: 'stable', change: 0, percentage: 0 };
    const recent = history.slice(-5);
    const older = history.slice(-10, -5);
    if (older.length === 0) return { trend: 'stable', change: 0, percentage: 0 };

    const recentAvg = recent.reduce((sum, value) => sum + value, 0) / recent.length;
    const olderAvg = older.reduce((sum, value) => sum + value, 0) / older.length;
    const change = recentAvg - olderAvg;
    const percentage = olderAvg === 0 ? 0 : (change / olderAvg) * 100;

    return {
      trend: Math.abs(percentage) < 2 ? 'stable' : change > 0 ? 'up' : 'down',
      change: Number(change.toFixed(1)),
      percentage: Number(percentage.toFixed(1)),
    };
  }

  private async invokeWrite(
    keypair: Keypair,
    method: string,
    args: xdr.ScVal[],
    txOptions?: TransactionOptions,
  ): Promise<xdr.ScVal> {
    try {
      const account = await this.rpc.getAccount(keypair.publicKey());
      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(this.reputationScoreContract.call(method, ...args))
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      const result = await this.rpc.sendTransaction(prepared);
      if (result.status === 'ERROR') {
        throw new Error(`Transaction failed: ${result.errorResult}`);
      }

      const hash = 'hash' in result ? result.hash : prepared.hash().toString('hex');
      const response = await this.rpc.getTransaction(hash);
      // Pre-fix (Issue #286 PR): the SDK types declare returnValue only on the
      // success variant, but `getTransaction` returns a discriminated union.
      // We narrow with a string-literal `in` check before reading.
      if ('status' in response && response.status === 'SUCCESS' && 'returnValue' in response) {
        const retval = (response as { returnValue?: xdr.ScVal }).returnValue;
        if (retval) return retval;
      }

      const simulated = await this.rpc.simulateTransaction(prepared);
      if (SorobanRpc.Api.isSimulationError(simulated)) {
        throw new Error((simulated as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
      }
      const retval = (simulated as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
      if (!retval) throw new Error('No return value from contract');
      return retval;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // Pre-fix (Issue #286 PR): `SorobanRpc.Account` is a structural type that
    // is not exported from every stellar-sdk minor version. We duck-type the
    // minimum Account shape that TransactionBuilder accepts, then cast
    // through `unknown` so TypeScript does not complain about the missing
    // exported namespace type.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account: any = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => undefined,
    };

    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(this.reputationScoreContract.call(method, ...args))
      .setTimeout(30)
      .build();

    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }

    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value from contract');
    return retval;
  }

  private toMetadataMap(metadata: Record<string, number>): xdr.ScVal {
    const entries = Object.entries(metadata).map(([key, value]) => new xdr.ScMapEntry({
      key: nativeToScVal(key, { type: 'symbol' }),
      val: nativeToScVal(BigInt(Math.trunc(value)), { type: 'i128' }),
    }));

    return xdr.ScVal.scvMap(entries);
  }

  private parseReputationData(raw: unknown): ReputationData {
    const record = this.toRecord(raw);
    return {
      did: this.asString(record.did ?? record.address),
      score: this.normalizeScore(record.score),
      transactionCount: this.asNumber(record.transaction_count ?? record.transactionCount),
      successfulTransactions: this.asNumber(record.successful_transactions ?? record.successfulTransactions),
      credentialCount: this.asNumber(record.credential_count ?? record.credentialCount),
      validCredentials: this.asNumber(record.valid_credentials ?? record.validCredentials),
      lastUpdated: this.asNumber(record.last_updated ?? record.lastUpdated),
      createdAt: this.asNumber(record.created_at ?? record.createdAt),
      reputationFactors: this.parseFactors(record.reputation_factors ?? record.reputationFactors),
      transactionVolumeSum: this.asNumber(record.transaction_volume_sum ?? record.transactionVolumeSum),
      counterpartyDiversity: this.asNumber(record.counterparty_diversity ?? record.counterpartyDiversity),
      feeConsistency: this.asNumber(record.fee_consistency ?? record.feeConsistency),
      contractInteractions: this.asNumber(record.contract_interactions ?? record.contractInteractions),
      verifiedKyc: this.asNumber(record.verified_kyc ?? record.verifiedKyc),
      employmentCredentials: this.asNumber(record.employment_credentials ?? record.employmentCredentials),
      academicCredentials: this.asNumber(record.academic_credentials ?? record.academicCredentials),
      selfClaimedCredentials: this.asNumber(record.self_claimed_credentials ?? record.selfClaimedCredentials),
      sanctionsMatches: this.asNumber(record.sanctions_matches ?? record.sanctionsMatches),
      credentialRevocations: this.asNumber(record.credential_revocations ?? record.credentialRevocations),
      disputes: this.asNumber(record.disputes),
    };
  }

  private parseFactors(raw: unknown): ReputationFactors {
    const record = this.toRecord(raw);
    return {
      transactionVolume: this.asNumber(record.transaction_volume ?? record.transactionVolume),
      transactionConsistency: this.asNumber(record.transaction_consistency ?? record.transactionConsistency),
      credentialCount: this.asNumber(record.credential_count ?? record.credentialCount),
      credentialDiversity: this.asNumber(record.credential_diversity ?? record.credentialDiversity),
      accountAge: this.asNumber(record.account_age ?? record.accountAge),
      disputeHistory: this.asNumber(record.dispute_history ?? record.disputeHistory),
    };
  }

  private parseHistory(raw: unknown): ReputationHistoryPoint[] {
    if (!Array.isArray(raw)) return [];
    return raw.map(item => {
      const record = this.toRecord(item);
      return {
        timestamp: this.asNumber(record.timestamp),
        score: this.normalizeScore(record.score),
        eventType: this.asString(record.event_type ?? record.eventType),
      };
    });
  }

  private parseTrustGraph(raw: unknown): TrustEdge[] {
    if (!Array.isArray(raw)) return [];
    return raw.map(item => this.parseTrustEdge(item));
  }

  private parseTrustEdge(raw: unknown): TrustEdge {
    const record = this.toRecord(raw);
    return {
      truster: this.asString(record.truster),
      subject: this.asString(record.subject),
      weight: this.asNumber(record.weight),
      reason: this.bytesToString(record.reason),
      timestamp: this.asNumber(record.timestamp),
    };
  }

  private parseAttestation(raw: unknown): TrustAttestation {
    const edge = this.parseTrustEdge(raw);
    const record = this.toRecord(raw);
    const note = record.note ? this.bytesToString(record.note) : undefined;
    return { ...edge, note };
  }

  private toBreakdown(data: ReputationData, percentile: number): ReputationBreakdown {
    return {
      did: data.did,
      score: data.score,
      rawScore: Number((data.score * 10).toFixed(0)),
      percentile,
      tier: this.getReputationTier(data.score).tier,
      factors: data.reputationFactors,
      penalties: {
        sanctionsMatches: data.sanctionsMatches,
        credentialRevocations: data.credentialRevocations,
        disputes: data.disputes,
      },
      lastUpdated: data.lastUpdated,
    };
  }

  private getTierRange(tier: string): [number, number] {
    switch (tier) {
      case 'Prime': return [900, 1000];
      case 'Strong': return [750, 899.9];
      case 'Established': return [550, 749.9];
      case 'Emerging': return [300, 549.9];
      default: return [0, 299.9];
    }
  }

  private parseTimeframe(timeframe: string | number): number | null {
    if (typeof timeframe === 'number') {
      return timeframe * 24 * 60 * 60 * 1000;
    }
    const match = /^([0-9]+)([dmy])$/.exec(timeframe);
    if (!match) return null;
    const value = Number(match[1]);
    const unit = match[2];
    if (unit === 'd') return value * 24 * 60 * 60 * 1000;
    if (unit === 'm') return value * 30 * 24 * 60 * 60 * 1000;
    return value * 365 * 24 * 60 * 60 * 1000;
  }

  private normalizeScore(value: unknown): number {
    return Number((this.asNumber(value) / 10).toFixed(1));
  }

  private toRecord(value: unknown): Record<string, unknown> {
    return value && typeof value === 'object' ? value as Record<string, unknown> : {};
  }

  private asNumber(value: unknown): number {
    if (typeof value === 'bigint') return Number(value);
    if (typeof value === 'number') return value;
    if (typeof value === 'string') return Number(value);
    return 0;
  }

  private asString(value: unknown): string {
    if (typeof value === 'string') return value;
    if (Array.isArray(value)) return new TextDecoder().decode(Uint8Array.from(value.map(item => Number(item))));
    return value == null ? '' : String(value);
  }

  private bytesToString(value: unknown): string {
    if (typeof value === 'string') return value;
    if (value instanceof Uint8Array) return new TextDecoder().decode(value);
    if (Array.isArray(value)) return new TextDecoder().decode(Uint8Array.from(value.map(item => Number(item))));
    return value == null ? '' : String(value);
  }

  private getDefaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private getNetworkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private handleError(error: unknown): StellarIdentityError {
    return mapContractError(error);
  }
}
