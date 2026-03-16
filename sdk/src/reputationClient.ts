import { 
  Server, 
  TransactionBuilder, 
  Networks, 
  Keypair, 
  Contract,
  Address
} from 'stellar-sdk';
import { 
  ReputationData,
  ReputationScoreResult,
  StellarIdentityConfig,
  TransactionOptions,
  StellarIdentityError
} from './types';

export class ReputationClient {
  private server: Server;
  private config: StellarIdentityConfig;
  private reputationScoreContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.server = new Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.reputationScoreContract = new Contract(config.contracts.reputationScore);
  }

  /**
   * Initialize reputation tracking for an address
   */
  async initializeReputation(
    address: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const keypair = Keypair.fromSecret(address); // This would need to be provided differently
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.reputationScoreContract.call('initialize_reputation', new Address(address))
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(keypair);
      await this.server.sendTransaction(transaction);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update reputation based on transaction
   */
  async updateTransactionReputation(
    address: string,
    successful: boolean,
    amount: number,
    txOptions?: TransactionOptions
  ): Promise<number> {
    try {
      const result = await this.reputationScoreContract.call(
        'update_transaction_reputation',
        new Address(address),
        successful,
        amount
      );
      
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update reputation based on credential verification
   */
  async updateCredentialReputation(
    address: string,
    credentialValid: boolean,
    credentialType: string,
    txOptions?: TransactionOptions
  ): Promise<number> {
    try {
      const result = await this.reputationScoreContract.call(
        'update_credential_reputation',
        new Address(address),
        credentialValid,
        credentialType
      );
      
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get reputation score for an address
   */
  async getReputationScore(address: string): Promise<number> {
    try {
      const result = await this.reputationScoreContract.call('get_reputation_score', new Address(address));
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get full reputation data for an address
   */
  async getReputationData(address: string): Promise<ReputationData> {
    try {
      const result = await this.reputationScoreContract.call('get_reputation_data', new Address(address));
      return this.parseReputationData(result.result.val);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Batch get reputation scores for multiple addresses
   */
  async batchGetReputationScores(addresses: string[]): Promise<number[]> {
    try {
      const stellarAddresses = addresses.map(addr => new Address(addr));
      const result = await this.reputationScoreContract.call('batch_get_reputation_scores', stellarAddresses);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get reputation history for an address
   */
  async getReputationHistory(address: string, limit: number = 10): Promise<number[]> {
    try {
      const result = await this.reputationScoreContract.call('get_reputation_history', new Address(address), limit);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Calculate reputation percentile rank
   */
  async getReputationPercentile(address: string): Promise<number> {
    try {
      const result = await this.reputationScoreContract.call('get_reputation_percentile', new Address(address));
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Check if address meets minimum reputation threshold
   */
  async meetsReputationThreshold(address: string, threshold: number): Promise<boolean> {
    try {
      const result = await this.reputationScoreContract.call('meets_reputation_threshold', new Address(address), threshold);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get reputation factors for an address
   */
  async getReputationFactors(address: string): Promise<Record<string, number>> {
    try {
      const result = await this.reputationScoreContract.call('get_reputation_factors', new Address(address));
      return this.parseReputationFactors(result.result.val);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Reset reputation (admin function)
   */
  async resetReputation(
    adminKeypair: Keypair,
    address: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(adminKeypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.reputationScoreContract.call('reset_reputation', new Address(address))
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(adminKeypair);
      await this.server.sendTransaction(transaction);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get top reputation addresses
   */
  async getTopReputationAddresses(limit: number = 10): Promise<string[]> {
    try {
      const result = await this.reputationScoreContract.call('get_top_reputation_addresses', limit);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get comprehensive reputation analysis
   */
  async getReputationAnalysis(address: string): Promise<ReputationScoreResult> {
    try {
      const [score, percentile, factors, history, lastUpdated] = await Promise.all([
        this.getReputationScore(address),
        this.getReputationPercentile(address),
        this.getReputationFactors(address),
        this.getReputationHistory(address),
        this.getLastUpdated(address)
      ]);

      return {
        score,
        percentile,
        factors,
        history,
        lastUpdated
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Build reputation through transaction history
   */
  async buildTransactionReputation(
    address: string,
    transactions: Array<{
      hash: string;
      successful: boolean;
      amount: number;
      timestamp: number;
    }>,
    txOptions?: TransactionOptions
  ): Promise<number> {
    let currentScore = await this.getReputationScore(address).catch(() => 50); // Default to 50 if not found

    for (const tx of transactions) {
      try {
        currentScore = await this.updateTransactionReputation(
          address,
          tx.successful,
          tx.amount,
          txOptions
        );
      } catch (error) {
        console.warn(`Failed to update reputation for transaction ${tx.hash}:`, error);
      }
    }

    return currentScore;
  }

  /**
   * Build reputation through credential validation
   */
  async buildCredentialReputation(
    address: string,
    credentials: Array<{
      type: string;
      valid: boolean;
      issuer: string;
      issuanceDate: number;
    }>,
    txOptions?: TransactionOptions
  ): Promise<number> {
    let currentScore = await this.getReputationScore(address).catch(() => 50); // Default to 50 if not found

    for (const credential of credentials) {
      try {
        currentScore = await this.updateCredentialReputation(
          address,
          credential.valid,
          credential.type,
          txOptions
        );
      } catch (error) {
        console.warn(`Failed to update reputation for credential ${credential.type}:`, error);
      }
    }

    return currentScore;
  }

  /**
   * Get reputation tier classification
   */
  getReputationTier(score: number): {
    tier: string;
    color: string;
    description: string;
  } {
    if (score >= 90) {
      return {
        tier: 'Excellent',
        color: '#10B981', // Green
        description: 'Outstanding reputation with excellent track record'
      };
    } else if (score >= 75) {
      return {
        tier: 'Good',
        color: '#3B82F6', // Blue
        description: 'Strong reputation with good performance'
      };
    } else if (score >= 60) {
      return {
        tier: 'Fair',
        color: '#F59E0B', // Yellow
        description: 'Moderate reputation with room for improvement'
      };
    } else if (score >= 40) {
      return {
        tier: 'Poor',
        color: '#F97316', // Orange
        description: 'Low reputation requiring attention'
      };
    } else {
      return {
        tier: 'Very Poor',
        color: '#EF4444', // Red
        description: 'Very low reputation with significant issues'
      };
    }
  }

  /**
   * Calculate reputation trend
   */
  calculateReputationTrend(history: number[]): {
    trend: 'up' | 'down' | 'stable';
    change: number;
    percentage: number;
  } {
    if (history.length < 2) {
      return { trend: 'stable', change: 0, percentage: 0 };
    }

    const recent = history.slice(-5); // Last 5 entries
    const older = history.slice(-10, -5); // Previous 5 entries if available

    if (older.length === 0) {
      return { trend: 'stable', change: 0, percentage: 0 };
    }

    const recentAvg = recent.reduce((sum, val) => sum + val, 0) / recent.length;
    const olderAvg = older.reduce((sum, val) => sum + val, 0) / older.length;
    
    const change = recentAvg - olderAvg;
    const percentage = olderAvg > 0 ? (change / olderAvg) * 100 : 0;

    let trend: 'up' | 'down' | 'stable';
    if (Math.abs(percentage) < 2) {
      trend = 'stable';
    } else if (change > 0) {
      trend = 'up';
    } else {
      trend = 'down';
    }

    return { trend, change, percentage };
  }

  private parseReputationData(result: any): ReputationData {
    return {
      address: result[0],
      score: result[1],
      transactionCount: result[2],
      successfulTransactions: result[3],
      credentialCount: result[4],
      validCredentials: result[5],
      lastUpdated: result[6],
      reputationFactors: this.parseReputationFactors(result[7])
    };
  }

  private parseReputationFactors(factors: any): Record<string, number> {
    const result: Record<string, number> = {};
    // Parse the Map<string, u32> from contract result
    for (const [key, value] of factors) {
      result[key] = value;
    }
    return result;
  }

  private async getLastUpdated(address: string): Promise<number> {
    try {
      const data = await this.getReputationData(address);
      return data.lastUpdated;
    } catch {
      return Date.now();
    }
  }

  private getDefaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet':
        return 'https://horizon.stellar.org';
      case 'testnet':
        return 'https://horizon-testnet.stellar.org';
      case 'futurenet':
        return 'https://horizon-futurenet.stellar.org';
      default:
        return 'https://horizon-testnet.stellar.org';
    }
  }

  private getNetworkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet':
        return Networks.PUBLIC;
      case 'testnet':
        return Networks.TESTNET;
      case 'futurenet':
        return Networks.FUTURENET;
      default:
        return Networks.TESTNET;
    }
  }

  private handleError(error: any): StellarIdentityError {
    const stellarError: StellarIdentityError = new Error(error.message) as StellarIdentityError;
    stellarError.code = error.code || 500;
    stellarError.type = error.type || 'UnknownError';
    return stellarError;
  }
}
