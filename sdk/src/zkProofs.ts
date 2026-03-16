import { 
  Server, 
  TransactionBuilder, 
  Networks, 
  Keypair, 
  Contract,
  Address
} from 'stellar-sdk';
import { 
  ZKProof,
  ZKCircuit,
  ZKProofOptions,
  ZKVerificationResult,
  StellarIdentityConfig,
  TransactionOptions,
  StellarIdentityError
} from './types';

export class ZKProofsClient {
  private server: Server;
  private config: StellarIdentityConfig;
  private zkAttestationContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.server = new Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.zkAttestationContract = new Contract(config.contracts.zkAttestation);
  }

  /**
   * Register a new ZK circuit
   */
  async registerCircuit(
    circuitId: string,
    name: string,
    description: string,
    verifierKey: string,
    publicInputCount: number,
    privateInputCount: number,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'register_circuit',
            circuitId,
            name,
            description,
            verifierKey,
            publicInputCount,
            privateInputCount
          )
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
   * Submit a zero-knowledge proof for verification
   */
  async submitProof(
    options: ZKProofOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            options.circuitId,
            options.publicInputs,
            options.proofBytes,
            options.expiresAt || null,
            options.metadata || {}
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(keypair);
      const result = await this.server.sendTransaction(transaction);
      
      if (result.result) {
        return this.extractProofId(result.result);
      } else {
        throw new Error('Transaction failed');
      }
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify a submitted proof
   */
  async verifyProof(proofId: string): Promise<ZKVerificationResult> {
    try {
      const isValid = await this.zkAttestationContract.call('verify_proof', proofId);
      const proof = await this.getProof(proofId);
      
      return {
        valid: isValid.result.val,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get proof details
   */
  async getProof(proofId: string): Promise<ZKProof> {
    try {
      const result = await this.zkAttestationContract.call('get_proof', proofId);
      return this.parseZKProof(result.result.val);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get circuit details
   */
  async getCircuit(circuitId: string): Promise<ZKCircuit> {
    try {
      const result = await this.zkAttestationContract.call('get_circuit', circuitId);
      return this.parseZKCircuit(result.result.val);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get all proofs for a circuit
   */
  async getCircuitProofs(circuitId: string): Promise<string[]> {
    try {
      const result = await this.zkAttestationContract.call('get_circuit_proofs', circuitId);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Deactivate a circuit
   */
  async deactivateCircuit(
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call('deactivate_circuit', circuitId)
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
   * Reactivate a circuit
   */
  async reactivateCircuit(
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call('reactivate_circuit', circuitId)
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
   * Get all active circuits
   */
  async getActiveCircuits(): Promise<string[]> {
    try {
      const result = await this.zkAttestationContract.call('get_active_circuits');
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Batch verify multiple proofs
   */
  async batchVerifyProofs(proofIds: string[]): Promise<ZKVerificationResult[]> {
    try {
      const results = await this.zkAttestationContract.call('batch_verify_proofs', proofIds);
      const verificationResults: ZKVerificationResult[] = [];
      
      for (let i = 0; i < proofIds.length; i++) {
        const proof = await this.getProof(proofIds[i]);
        
        verificationResults.push({
          valid: results.result.val[i],
          circuitId: proof.circuitId,
          proofId: proof.proofId,
          verifiedAt: Date.now(),
          expiresAt: proof.expiresAt
        });
      }
      
      return verificationResults;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create selective disclosure proof for age verification
   */
  async createAgeProof(
    circuitId: string,
    commitment: string,
    minAge: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const result = await this.zkAttestationContract.call(
        'create_age_proof',
        circuitId,
        commitment,
        minAge,
        proofBytes
      );
      
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify age proof
   */
  async verifyAgeProof(proofId: string, minAge: number): Promise<boolean> {
    try {
      const result = await this.zkAttestationContract.call('verify_age_proof', proofId, minAge);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create proof for income verification (without revealing exact amount)
   */
  async createIncomeProof(
    circuitId: string,
    commitment: string,
    minIncome: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            circuitId,
            [commitment, minIncome.toString()],
            proofBytes,
            null,
            { type: 'income_verification' }
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(keypair);
      const result = await this.server.sendTransaction(transaction);
      
      return this.extractProofId(result.result);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create proof for credential ownership without revealing details
   */
  async createCredentialOwnershipProof(
    circuitId: string,
    credentialHash: string,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            circuitId,
            [credentialHash],
            proofBytes,
            null,
            { type: 'credential_ownership' }
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(keypair);
      const result = await this.server.sendTransaction(transaction);
      
      return this.extractProofId(result.result);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Generate proof for range verification (e.g., age between 18-65)
   */
  async createRangeProof(
    circuitId: string,
    commitment: string,
    minValue: number,
    maxValue: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const keypair = Keypair.random(); // In practice, this should be provided
      
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            circuitId,
            [commitment, minValue.toString(), maxValue.toString()],
            proofBytes,
            null,
            { type: 'range_verification', min: minValue.toString(), max: maxValue.toString() }
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(keypair);
      const result = await this.server.sendTransaction(transaction);
      
      return this.extractProofId(result.result);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Generate commitment for private data
   */
  generateCommitment(privateData: string, salt?: string): string {
    const crypto = require('crypto');
    const actualSalt = salt || crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256');
    hash.update(privateData + actualSalt);
    return hash.digest('hex');
  }

  /**
   * Generate random salt for commitment
   */
  generateSalt(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  private parseZKProof(result: any): ZKProof {
    return {
      proofId: result[0],
      circuitId: result[1],
      publicInputs: result[2],
      proofBytes: result[3],
      verifierAddress: result[4],
      createdAt: result[5],
      expiresAt: result[6],
      metadata: this.parseMetadata(result[7])
    };
  }

  private parseZKCircuit(result: any): ZKCircuit {
    return {
      circuitId: result[0],
      name: result[1],
      description: result[2],
      verifierKey: result[3],
      publicInputCount: result[4],
      privateInputCount: result[5],
      createdBy: result[6],
      createdAt: result[7],
      active: result[8]
    };
  }

  private parseMetadata(metadata: any): Record<string, string> {
    const result: Record<string, string> = {};
    // Parse the Map<Symbol, Bytes> from contract result
    for (const [key, value] of metadata) {
      result[key] = value;
    }
    return result;
  }

  private extractProofId(result: any): string {
    // Extract proof ID from transaction result
    // This would depend on the actual result format from the contract
    return result.id || 'unknown';
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
