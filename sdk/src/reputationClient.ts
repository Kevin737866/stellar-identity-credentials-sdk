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
import {
  ReputationData,
  ReputationScoreResult,
  StellarIdentityConfig,
  TransactionOptions,
  StellarIdentityError,
} from './types';

export class ReputationClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private reputationScoreContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.reputationScoreContract = new Contract(config.contracts.reputationScore);
  }

  async initializeReputation(address: string, txOptions?: TransactionOptions): Promise<void> {
    try {
      const keypair = Keypair.fromPublicKey(address);
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.reputationScoreContract.call(
            'initialize_reputation',
            xdr.ScVal.scvAddress(new Address(address).toScAddress())
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(keypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateTransactionReputation(
    address: string,
    successful: boolean,
    amount: number,
    _txOptions?: TransactionOptions
  ): Promise<number> {
    try {
      const retval = await this.simulateRead('update_transaction_reputation', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
        nativeToScVal(successful),
        nativeToScVal(BigInt(amount), { type: 'u64' }),
      ]);
      return Number(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async updateCredentialReputation(
    address: string,
    credentialValid: boolean,
    credentialType: string,
    _txOptions?: TransactionOptions
  ): Promise<number> {
    try {
      const retval = await this.simulateRead('update_credential_reputation', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
        nativeToScVal(credentialValid),
        nativeToScVal(new TextEncoder().encode(credentialType), { type: 'bytes' }),
      ]);
      return Number(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getReputationScore(address: string): Promise<number> {
    try {
      const retval = await this.simulateRead('get_reputation_score', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return Number(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getReputationData(address: string): Promise<ReputationData> {
    try {
      const retval = await this.simulateRead('get_reputation_data', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return this.parseReputationData(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchGetReputationScores(addresses: string[]): Promise<number[]> {
    return Promise.all(addresses.map(a => this.getReputationScore(a)));
  }

  async getReputationHistory(address: string, _limit = 10): Promise<number[]> {
    try {
      const retval = await this.simulateRead('get_reputation_history', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      const raw = scValToNative(retval);
      return Array.isArray(raw) ? raw.map(Number) : [];
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getReputationPercentile(address: string): Promise<number> {
    try {
      const retval = await this.simulateRead('get_reputation_percentile', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return Number(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async meetsReputationThreshold(address: string, threshold: number): Promise<boolean> {
    try {
      const retval = await this.simulateRead('meets_reputation_threshold', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
        nativeToScVal(BigInt(threshold), { type: 'u32' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getReputationFactors(address: string): Promise<Record<string, number>> {
    try {
      const retval = await this.simulateRead('get_reputation_factors', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]);
      return this.parseReputationFactors(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async resetReputation(
    adminKeypair: Keypair,
    address: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.reputationScoreContract.call(
            'reset_reputation',
            xdr.ScVal.scvAddress(new Address(address).toScAddress())
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getReputationAnalysis(address: string): Promise<ReputationScoreResult> {
    const [score, percentile, factors, history, lastUpdated] = await Promise.all([
      this.getReputationScore(address),
      this.getReputationPercentile(address),
      this.getReputationFactors(address),
      this.getReputationHistory(address),
      this.getReputationData(address).then(d => d.lastUpdated).catch(() => Date.now()),
    ]);
    return { score, percentile, factors, history, lastUpdated };
  }

  async buildTransactionReputation(
    address: string,
    transactions: Array<{ hash: string; successful: boolean; amount: number; timestamp: number }>,
    txOptions?: TransactionOptions
  ): Promise<number> {
    let score = await this.getReputationScore(address).catch(() => 50);
    for (const tx of transactions) {
      try {
        score = await this.updateTransactionReputation(address, tx.successful, tx.amount, txOptions);
      } catch (error) {
        console.warn(`Failed to update reputation for tx ${tx.hash}:`, error);
      }
    }
    return score;
  }

  async buildCredentialReputation(
    address: string,
    credentials: Array<{ type: string; valid: boolean; issuer: string; issuanceDate: number }>,
    txOptions?: TransactionOptions
  ): Promise<number> {
    let score = await this.getReputationScore(address).catch(() => 50);
    for (const cred of credentials) {
      try {
        score = await this.updateCredentialReputation(address, cred.valid, cred.type, txOptions);
      } catch (error) {
        console.warn(`Failed to update reputation for credential ${cred.type}:`, error);
      }
    }
    return score;
  }

  getReputationTier(score: number): { tier: string; color: string; description: string } {
    if (score >= 90) return { tier: 'Excellent', color: '#10B981', description: 'Outstanding reputation with excellent track record' };
    if (score >= 75) return { tier: 'Good', color: '#3B82F6', description: 'Strong reputation with good performance' };
    if (score >= 60) return { tier: 'Fair', color: '#F59E0B', description: 'Moderate reputation with room for improvement' };
    if (score >= 40) return { tier: 'Poor', color: '#F97316', description: 'Low reputation requiring attention' };
    return { tier: 'Very Poor', color: '#EF4444', description: 'Very low reputation with significant issues' };
  }

  calculateReputationTrend(history: number[]): { trend: 'up' | 'down' | 'stable'; change: number; percentage: number } {
    if (history.length < 2) return { trend: 'stable', change: 0, percentage: 0 };
    const recent = history.slice(-5);
    const older = history.slice(-10, -5);
    if (older.length === 0) return { trend: 'stable', change: 0, percentage: 0 };
    const recentAvg = recent.reduce((s, v) => s + v, 0) / recent.length;
    const olderAvg = older.reduce((s, v) => s + v, 0) / older.length;
    const change = recentAvg - olderAvg;
    const percentage = olderAvg > 0 ? (change / olderAvg) * 100 : 0;
    const trend: 'up' | 'down' | 'stable' = Math.abs(percentage) < 2 ? 'stable' : change > 0 ? 'up' : 'down';
    return { trend, change, percentage };
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;

    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.getNetworkPassphrase() })
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

  private parseReputationData(raw: unknown): ReputationData {
    const r = Array.isArray(raw) ? raw : [];
    return {
      address: String(r[0] ?? ''),
      score: Number(r[1] ?? 0),
      transactionCount: Number(r[2] ?? 0),
      successfulTransactions: Number(r[3] ?? 0),
      credentialCount: Number(r[4] ?? 0),
      validCredentials: Number(r[5] ?? 0),
      lastUpdated: Number(r[6] ?? 0),
      reputationFactors: this.parseReputationFactors(r[7]),
    };
  }

  private parseReputationFactors(factors: unknown): Record<string, number> {
    const result: Record<string, number> = {};
    if (factors && typeof factors === 'object') {
      for (const [key, value] of Object.entries(factors as Record<string, unknown>)) {
        result[key] = Number(value);
      }
    }
    return result;
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
    const err = new Error(error instanceof Error ? error.message : String(error)) as StellarIdentityError;
    err.code = (error as StellarIdentityError).code || 500;
    err.type = (error as StellarIdentityError).type || 'UnknownError';
    return err;
  }
}
