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
  StellarIdentityConfig,
  TransactionOptions,
} from './types';
import { StellarIdentityError, ErrorCode, mapContractError } from './errors';
import { CacheManager, DataType } from './cacheManager';
import { Logger } from './logger';
import { RevocationRegistry, RevocationProof, BatchRevocationRecord } from './revocationTypes';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeStr(value: string): Uint8Array {
  return encoder.encode(value);
}

function decodeValue(value: unknown): string {
  if (value instanceof Uint8Array) return decoder.decode(value);
  return String(value ?? '');
}

export class RevocationRegistryClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private contract: Contract;
  private logger: Logger;
  private cache: CacheManager;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.contract = new Contract(config.contracts.credentialIssuer);
    this.logger = new Logger('RevocationRegistryClient');
    this.cache = new CacheManager();
  }

  async createRevocationRegistry(
    issuerKeypair: Keypair,
    name: string,
    metadata?: Record<string, string>,
    txOptions?: TransactionOptions,
  ): Promise<string> {
    this.logger.debug('createRevocationRegistry called', { name });
    try {
      const address = issuerKeypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.contract.call(
            'create_revocation_registry',
            xdr.ScVal.scvAddress(new Address(address).toScAddress()),
            nativeToScVal(encodeStr(name), { type: 'bytes' }),
            metadata != null
              ? nativeToScVal(
                  Object.entries(metadata).map(([k, v]) => ({
                    key: encodeStr(k),
                    val: encodeStr(v),
                  })),
                  { type: 'vec' }
                )
              : xdr.ScVal.scvVoid(),
          ),
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(issuerKeypair);

      const result = await this.rpc.sendTransaction(prepared);
      if (result.status === 'ERROR') {
        throw new Error(`Transaction failed: ${result.errorResult}`);
      }
      return `registry-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async revokeWithRegistry(
    issuerKeypair: Keypair,
    credentialId: string,
    registryId: string,
    reason?: string,
    txOptions?: TransactionOptions,
  ): Promise<void> {
    this.logger.debug('revokeWithRegistry called', { credentialId, registryId });
    try {
      const address = issuerKeypair.publicKey();
      const account = await this.rpc.getAccount(address);

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.contract.call(
            'revoke_with_registry',
            nativeToScVal(encodeStr(registryId), { type: 'bytes' }),
            nativeToScVal(encodeStr(credentialId), { type: 'bytes' }),
            reason != null
              ? nativeToScVal(encodeStr(reason), { type: 'bytes' })
              : xdr.ScVal.scvVoid(),
          ),
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(issuerKeypair);

      const result = await this.rpc.sendTransaction(prepared);
      if (result.status === 'ERROR') {
        throw new Error(`Transaction failed: ${result.errorResult}`);
      }

      this.cache.invalidate(DataType.CREDENTIAL_STATUS, credentialId);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchRevoke(
    issuerKeypair: Keypair,
    credentialIds: string[],
    registryId: string,
    reason?: string,
    txOptions?: TransactionOptions,
  ): Promise<BatchRevocationRecord> {
    this.logger.debug('batchRevoke called', { credentialIds, registryId });
    const failedCredentials: Array<{ credentialId: string; error: string }> = [];
    const succeeded: string[] = [];

    for (const credentialId of credentialIds) {
      try {
        await this.revokeWithRegistry(issuerKeypair, credentialId, registryId, reason, txOptions);
        succeeded.push(credentialId);
      } catch (err) {
        failedCredentials.push({
          credentialId,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    return {
      batchId: `batch-${Date.now()}`,
      registryId,
      credentialIds,
      revokedCount: succeeded.length,
      failedCount: failedCredentials.length,
      failedCredentials,
      reason,
      revokedAt: Date.now(),
      issuer: issuerKeypair.publicKey(),
    };
  }

  async getRevocationRegistry(registryId: string): Promise<RevocationRegistry> {
    this.logger.debug('getRevocationRegistry called', { registryId });
    try {
      const retval = await this.simulateRead('get_revocation_registry', [
        nativeToScVal(encodeStr(registryId), { type: 'bytes' }),
      ]);
      const raw = scValToNative(retval) as Record<string, unknown>;
      return this.parseRevocationRegistry(raw, registryId);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyRevocationProof(credentialId: string, proof: RevocationProof): Promise<boolean> {
    this.logger.debug('verifyRevocationProof called', { credentialId });
    try {
      const retval = await this.simulateRead('verify_revocation_proof', [
        nativeToScVal(encodeStr(credentialId), { type: 'bytes' }),
        nativeToScVal(encodeStr(proof.registryId), { type: 'bytes' }),
        nativeToScVal(encodeStr(proof.signature), { type: 'bytes' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async checkRevocationStatus(credentialId: string): Promise<{
    revoked: boolean;
    registryId?: string;
    revokedAt?: number;
    reason?: string;
  }> {
    this.logger.debug('checkRevocationStatus called', { credentialId });
    try {
      const retval = await this.simulateRead('check_revocation_status', [
        nativeToScVal(encodeStr(credentialId), { type: 'bytes' }),
      ]);
      const raw = scValToNative(retval) as Record<string, unknown>;
      return {
        revoked: Boolean(raw.revoked ?? raw[0] ?? false),
        registryId: raw.registry_id ? decodeValue(raw.registry_id) : raw.registryId ? decodeValue(raw.registryId) : undefined,
        revokedAt: Number(raw.revoked_at ?? raw[1] ?? 0),
        reason: raw.reason ? decodeValue(raw.reason) : raw[2] ? decodeValue(raw[2]) : undefined,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    const account = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => {},
    } as any;

    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(this.contract.call(method, ...args))
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

  private parseRevocationRegistry(raw: Record<string, unknown>, registryId: string): RevocationRegistry {
    const toStr = (v: unknown) => (v instanceof Uint8Array ? decoder.decode(v) : String(v ?? ''));
    const toNum = (v: unknown) => Number(v ?? 0);

    const meta = raw.metadata ?? raw[7];
    const parsedMeta: Record<string, string> = {};
    if (Array.isArray(meta)) {
      for (const entry of meta) {
        const e = entry as Record<string, unknown>;
        parsedMeta[toStr(e.key)] = toStr(e.val ?? e.value);
      }
    }

    return {
      id: toStr(raw.id ?? raw[0]) || registryId,
      issuer: toStr(raw.issuer ?? raw[1]),
      name: toStr(raw.name ?? raw[2]),
      credentialCount: toNum(raw.credential_count ?? raw[3]),
      revokedCount: toNum(raw.revoked_count ?? raw[4]),
      active: Boolean(raw.active ?? raw[5] ?? true),
      created: toNum(raw.created ?? raw[6]),
      updated: toNum(raw.updated ?? Date.now()),
      metadata: Object.keys(parsedMeta).length > 0 ? parsedMeta : undefined,
    };
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
    this.logger.error('RevocationRegistryClient error', error);
    return mapContractError(error);
  }
}
