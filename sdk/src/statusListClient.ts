/**
 * W3C Bitstring Status List Client (#267)
 *
 * TypeScript SDK client for interacting with the BitstringStatusList
 * Soroban contract. Provides methods for creating status lists,
 * updating revocation entries, and checking credential status.
 */

import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Contract,
  Address,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import {
  StellarIdentityConfig,
  TransactionOptions,
} from './types';
import { StellarIdentityError, ErrorCode, mapContractError } from './errors';
import { Logger } from './logger';

const encoder = new TextEncoder();

function encodeStr(value: string): Uint8Array {
  return encoder.encode(value);
}

export interface StatusListMetadata {
  id: string;
  issuer: string;
  size: number;
  revokedCount: number;
  createdAt: number;
  lastUpdated: number;
  active: boolean;
}

export class StatusListClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private contract: Contract;
  private logger: Logger;

  constructor(config: StellarIdentityConfig, contractAddress: string) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl);
    this.contract = new Contract(contractAddress);
    this.logger = Logger.getInstance();
  }

  /**
   * Create a new status list with the given number of entries.
   * @param admin - The admin/issuer keypair
   * @param listId - Unique identifier for the list
   * @param size - Number of bits/entries (1 .. 100000)
   */
  async createStatusList(
    admin: import('stellar-sdk').Keypair,
    listId: string,
    size: number,
  ): Promise<void> {
    this.logger.info(`Creating status list: ${listId} with size ${size}`);

    const account = await this.rpc.getAccount(admin.publicKey());
    const args = [
      nativeToScVal(new Address(admin.publicKey()).toScVal()),
      nativeToScVal(encodeStr(listId)),
      nativeToScVal(size, { type: 'u32' }),
    ];

    const transaction = new TransactionBuilder(account, {
      fee: this.config.fee ?? '100',
      networkPassphrase: this.config.networkPassphrase ?? Networks.TESTNET,
    })
      .addOperation(this.contract.call('create_status_list', ...args))
      .setTimeout(TransactionBuilder.TimeoutInfinite)
      .build();

    transaction.sign(admin);
    const result = await this.rpc.sendTransaction(transaction);
    if (result.status !== 'Ok') {
      throw new StellarIdentityError(
        ErrorCode.CONTRACT_ERROR,
        `Failed to create status list: ${result.errorResult?.result()}`,
      );
    }
  }

  /**
   * Update the revocation status of a credential at a given index.
   * @param admin - The admin/issuer keypair
   * @param listId - Status list identifier
   * @param index - Credential index in the list
   * @param revoked - true to revoke, false to un-revoke
   */
  async updateStatusListEntry(
    admin: import('stellar-sdk').Keypair,
    listId: string,
    index: number,
    revoked: boolean,
  ): Promise<void> {
    this.logger.info(`Updating status list entry: ${listId}[${index}] = ${revoked}`);

    const account = await this.rpc.getAccount(admin.publicKey());
    const args = [
      nativeToScVal(new Address(admin.publicKey()).toScVal()),
      nativeToScVal(encodeStr(listId)),
      nativeToScVal(index, { type: 'u32' }),
      nativeToScVal(revoked),
    ];

    const transaction = new TransactionBuilder(account, {
      fee: this.config.fee ?? '100',
      networkPassphrase: this.config.networkPassphrase ?? Networks.TESTNET,
    })
      .addOperation(this.contract.call('update_status_list_entry', ...args))
      .setTimeout(TransactionBuilder.TimeoutInfinite)
      .build();

    transaction.sign(admin);
    const result = await this.rpc.sendTransaction(transaction);
    if (result.status !== 'Ok') {
      throw new StellarIdentityError(
        ErrorCode.CONTRACT_ERROR,
        `Failed to update status list entry: ${result.errorResult?.result()}`,
      );
    }
  }

  /**
   * Check whether a credential at a given index has been revoked.
   * @param listId - Status list identifier
   * @param index - Credential index in the list
   * @returns true if revoked, false otherwise
   */
  async checkStatusList(
    listId: string,
    index: number,
  ): Promise<boolean> {
    this.logger.debug(`Checking status list: ${listId}[${index}]`);

    const args = [
      nativeToScVal(encodeStr(listId)),
      nativeToScVal(index, { type: 'u32' }),
    ];

    const result = await this.rpc.simulateTransaction(
      // @ts-expect-error - simulateTransaction accepts a partial tx
      new TransactionBuilder(
        await this.rpc.getAccount(this.config.publicKey ?? 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'),
        {
          fee: '100',
          networkPassphrase: this.config.networkPassphrase ?? Networks.TESTNET,
        },
      )
        .addOperation(this.contract.call('check_status_list_entry', ...args))
        .setTimeout(30)
        .build(),
    );

    if (result.error) {
      throw mapContractError(result.error);
    }

    const retVal = result.result?.retval;
    return scValToNative(retVal) as boolean;
  }

  /**
   * Dynamically expand a status list to accommodate more entries.
   * @param admin - The admin/issuer keypair
   * @param listId - Status list identifier
   * @param minSize - Minimum required size
   * @returns New size of the list
   */
  async expandStatusList(
    admin: import('stellar-sdk').Keypair,
    listId: string,
    minSize: number,
  ): Promise<number> {
    this.logger.info(`Expanding status list: ${listId} to at least ${minSize}`);

    const account = await this.rpc.getAccount(admin.publicKey());
    const args = [
      nativeToScVal(new Address(admin.publicKey()).toScVal()),
      nativeToScVal(encodeStr(listId)),
      nativeToScVal(minSize, { type: 'u32' }),
    ];

    const transaction = new TransactionBuilder(account, {
      fee: this.config.fee ?? '100',
      networkPassphrase: this.config.networkPassphrase ?? Networks.TESTNET,
    })
      .addOperation(this.contract.call('expand_status_list', ...args))
      .setTimeout(TransactionBuilder.TimeoutInfinite)
      .build();

    transaction.sign(admin);
    const result = await this.rpc.sendTransaction(transaction);
    if (result.status !== 'Ok') {
      throw new StellarIdentityError(
        ErrorCode.CONTRACT_ERROR,
        `Failed to expand status list: ${result.errorResult?.result()}`,
      );
    }

    // Fetch the updated metadata to get the new size
    const meta = await this.getMetadata(listId);
    return meta.size;
  }

  /**
   * Get metadata for a status list.
   * @param listId - Status list identifier
   */
  async getMetadata(listId: string): Promise<StatusListMetadata> {
    const args = [nativeToScVal(encodeStr(listId))];

    const result = await this.rpc.simulateTransaction(
      // @ts-expect-error - simulateTransaction accepts a partial tx
      new TransactionBuilder(
        await this.rpc.getAccount(this.config.publicKey ?? 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF'),
        {
          fee: '100',
          networkPassphrase: this.config.networkPassphrase ?? Networks.TESTNET,
        },
      )
        .addOperation(this.contract.call('get_metadata', ...args))
        .setTimeout(30)
        .build(),
    );

    if (result.error) {
      throw mapContractError(result.error);
    }

    const retVal = result.result?.retval;
    const native = scValToNative(retVal) as Record<string, unknown>;
    return {
      id: String(native.id ?? ''),
      issuer: String(native.issuer ?? ''),
      size: Number(native.size ?? 0),
      revokedCount: Number(native.revoked_count ?? 0),
      createdAt: Number(native.created_at ?? 0),
      lastUpdated: Number(native.last_updated ?? 0),
      active: Boolean(native.active ?? false),
    };
  }
}
