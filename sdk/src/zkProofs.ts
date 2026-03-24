import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import {
  ZKProof,
  ZKCircuit,
  ZKProofOptions,
  ZKVerificationResult,
  StellarIdentityConfig,
  TransactionOptions,
  StellarIdentityError,
} from './types';

export class ZKProofsClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private zkAttestationContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.zkAttestationContract = new Contract(config.contracts.zkAttestation);
  }

  async registerCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    name: string,
    description: string,
    verifierKey: string,
    publicInputCount: number,
    privateInputCount: number,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'register_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(name), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(description), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(verifierKey), { type: 'bytes' }),
            nativeToScVal(BigInt(publicInputCount), { type: 'u32' }),
            nativeToScVal(BigInt(privateInputCount), { type: 'u32' })
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

  async submitProof(
    submitterKeypair: Keypair,
    options: ZKProofOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const account = await this.rpc.getAccount(submitterKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            nativeToScVal(new TextEncoder().encode(options.circuitId), { type: 'bytes' }),
            nativeToScVal(options.publicInputs.map(i => new TextEncoder().encode(i)), { type: 'vec' }),
            nativeToScVal(new TextEncoder().encode(options.proofBytes), { type: 'bytes' }),
            options.expiresAt != null ? nativeToScVal(BigInt(options.expiresAt), { type: 'u64' }) : xdr.ScVal.scvVoid(),
            options.metadata ? nativeToScVal(new TextEncoder().encode(JSON.stringify(options.metadata)), { type: 'bytes' }) : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(submitterKeypair);
      await this.rpc.sendTransaction(prepared);
      return `proof-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyProof(proofId: string): Promise<ZKVerificationResult> {
    try {
      const isValidVal = await this.simulateRead('verify_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      const proof = await this.getProof(proofId);
      return {
        valid: scValToNative(isValidVal) as boolean,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getProof(proofId: string): Promise<ZKProof> {
    try {
      const retval = await this.simulateRead('get_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      return this.parseZKProof(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuit(circuitId: string): Promise<ZKCircuit> {
    try {
      const retval = await this.simulateRead('get_circuit', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return this.parseZKCircuit(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuitProofs(circuitId: string): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_circuit_proofs', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'deactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
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

  async reactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'reactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
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

  async getActiveCircuits(): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_active_circuits', []);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchVerifyProofs(proofIds: string[]): Promise<ZKVerificationResult[]> {
    return Promise.all(proofIds.map(id => this.verifyProof(id)));
  }

  async createAgeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minAge: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minAge)],
        proofBytes,
        metadata: { type: 'age_verification', minAge: String(minAge) },
      },
      txOptions
    );
  }

  async verifyAgeProof(proofId: string, minAge: number): Promise<boolean> {
    try {
      const retval = await this.simulateRead('verify_age_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
        nativeToScVal(BigInt(minAge), { type: 'u32' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async createIncomeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minIncome: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minIncome)],
        proofBytes,
        metadata: { type: 'income_verification' },
      },
      txOptions
    );
  }

  async createCredentialOwnershipProof(
    submitterKeypair: Keypair,
    circuitId: string,
    credentialHash: string,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [credentialHash],
        proofBytes,
        metadata: { type: 'credential_ownership' },
      },
      txOptions
    );
  }

  async createRangeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minValue: number,
    maxValue: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minValue), String(maxValue)],
        proofBytes,
        metadata: { type: 'range_verification', min: String(minValue), max: String(maxValue) },
      },
      txOptions
    );
  }

  generateCommitment(privateData: string, salt?: string): string {
    const crypto = require('crypto') as typeof import('crypto');
    const actualSalt = salt ?? (crypto.randomBytes(32).toString('hex'));
    return crypto.createHash('sha256').update(privateData + actualSalt).digest('hex');
  }

  generateSalt(): string {
    const crypto = require('crypto') as typeof import('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;

    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.getNetworkPassphrase() })
      .addOperation(this.zkAttestationContract.call(method, ...args))
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

  private parseZKProof(raw: unknown): ZKProof {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      proofId: toStr(r[0]),
      circuitId: toStr(r[1]),
      publicInputs: Array.isArray(r[2]) ? r[2].map(toStr) : [],
      proofBytes: toStr(r[3]),
      verifierAddress: toStr(r[4]),
      createdAt: Number(r[5] ?? 0),
      expiresAt: r[6] != null ? Number(r[6]) : undefined,
      metadata: this.parseMetadata(r[7]),
    };
  }

  private parseZKCircuit(raw: unknown): ZKCircuit {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      circuitId: toStr(r[0]),
      name: toStr(r[1]),
      description: toStr(r[2]),
      verifierKey: toStr(r[3]),
      publicInputCount: Number(r[4] ?? 0),
      privateInputCount: Number(r[5] ?? 0),
      createdBy: toStr(r[6]),
      createdAt: Number(r[7] ?? 0),
      active: Boolean(r[8]),
    };
  }

  private parseMetadata(metadata: unknown): Record<string, string> {
    const result: Record<string, string> = {};
    if (metadata && typeof metadata === 'object') {
      for (const [key, value] of Object.entries(metadata as Record<string, unknown>)) {
        result[key] = value instanceof Uint8Array ? new TextDecoder().decode(value) : String(value);
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
