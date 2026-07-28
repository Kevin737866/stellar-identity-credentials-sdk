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
  CredentialSchema,
  SchemaValidationResult,
  SchemaVersion,
} from './types';
import { StellarIdentityError, mapContractError } from './errors';

export class SchemaRegistryClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private schemaRegistryContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.schemaRegistryContract = new Contract(config.contracts.schemaRegistry);
  }

  async registerSchema(
    issuerKeypair: Keypair,
    schemaId: string,
    definition: string,
    txOptions?: TransactionOptions,
  ): Promise<void> {
    const address = issuerKeypair.publicKey();
    const account = await this.rpc.getAccount(address);

    const tx = new TransactionBuilder(account, {
      fee: String(txOptions?.fee ?? 100),
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(
        this.schemaRegistryContract.call(
          'register_schema',
          xdr.ScVal.scvAddress(new Address(address).toScAddress()),
          nativeToScVal(new TextEncoder().encode(schemaId), { type: 'bytes' }),
          nativeToScVal(new TextEncoder().encode(definition), { type: 'bytes' }),
        )
      )
      .setTimeout(txOptions?.timeout ?? 30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(issuerKeypair);
    const result = await this.rpc.sendTransaction(prepared);

    if (result.status === 'ERROR') {
      throw new Error(`Transaction failed: ${result.errorResult}`);
    }
  }

  async updateSchema(
    issuerKeypair: Keypair,
    schemaId: string,
    definition: string,
    txOptions?: TransactionOptions,
  ): Promise<void> {
    const address = issuerKeypair.publicKey();
    const account = await this.rpc.getAccount(address);

    const tx = new TransactionBuilder(account, {
      fee: String(txOptions?.fee ?? 100),
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(
        this.schemaRegistryContract.call(
          'update_schema',
          xdr.ScVal.scvAddress(new Address(address).toScAddress()),
          nativeToScVal(new TextEncoder().encode(schemaId), { type: 'bytes' }),
          nativeToScVal(new TextEncoder().encode(definition), { type: 'bytes' }),
        )
      )
      .setTimeout(txOptions?.timeout ?? 30)
      .build();

    const prepared = await this.rpc.prepareTransaction(tx);
    prepared.sign(issuerKeypair);
    const result = await this.rpc.sendTransaction(prepared);

    if (result.status === 'ERROR') {
      throw new Error(`Transaction failed: ${result.errorResult}`);
    }
  }

  async getSchema(schemaId: string, version?: number): Promise<CredentialSchema> {
    const versionVal = version != null
      ? nativeToScVal(version, { type: 'u32' })
      : xdr.ScVal.scvVoid();

    const retval = await this.simulateRead('get_schema', [
      nativeToScVal(new TextEncoder().encode(schemaId), { type: 'bytes' }),
      versionVal,
    ]);

    return this.parseSchema(scValToNative(retval));
  }

  async listSchemas(page: number, pageSize: number): Promise<string[]> {
    const retval = await this.simulateRead('list_schemas', [
      nativeToScVal(page, { type: 'u32' }),
      nativeToScVal(pageSize, { type: 'u32' }),
    ]);

    const raw = scValToNative(retval);
    if (!Array.isArray(raw)) return [];
    return raw.map((item: unknown) => {
      if (item instanceof Uint8Array) return new TextDecoder().decode(item);
      return String(item);
    });
  }

  async validateData(schemaId: string, data: string): Promise<SchemaValidationResult> {
    try {
      const retval = await this.simulateRead('validate_schema_exists', [
        nativeToScVal(new TextEncoder().encode(schemaId), { type: 'bytes' }),
      ]);
      const exists = Boolean(scValToNative(retval));

      if (!exists) {
        return { valid: false, errors: [`Schema '${schemaId}' not found`] };
      }

      const schema = await this.getSchema(schemaId);
      const parsed = JSON.parse(data);
      const parsedDef = JSON.parse(schema.definition);

      const errors: string[] = [];
      if (parsedDef.required && Array.isArray(parsedDef.required)) {
        for (const field of parsedDef.required) {
          if (!(field in parsed)) {
            errors.push(`Missing required field: ${field}`);
          }
        }
      }

      return { valid: errors.length === 0, errors };
    } catch (error) {
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : String(error)],
      };
    }
  }

  async getSchemaVersion(schemaId: string): Promise<SchemaVersion[]> {
    const versions: SchemaVersion[] = [];
    try {
      const schema = await this.getSchema(schemaId);
      versions.push({
        version: schema.version,
        schemaId: schema.id,
        definition: schema.definition,
        updated: schema.updated,
      });

      for (let v = schema.version - 1; v >= 1; v--) {
        try {
          const historical = await this.getSchema(schemaId, v);
          versions.push({
            version: historical.version,
            schemaId: historical.id,
            definition: historical.definition,
            updated: historical.updated,
          });
        } catch {
          break;
        }
      }

      return versions;
    } catch {
      return versions;
    }
  }

  async validateSchema(schemaId: string): Promise<boolean> {
    const retval = await this.simulateRead('validate_schema_exists', [
      nativeToScVal(new TextEncoder().encode(schemaId), { type: 'bytes' }),
    ]);
    return Boolean(scValToNative(retval));
  }

  private parseSchema(raw: unknown): CredentialSchema {
    const r = raw as Record<string, unknown>;
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      id: toStr(r[0] ?? r.id),
      issuer: toStr(r[1] ?? r.issuer),
      version: Number(r[2] ?? r.version ?? 1),
      definition: toStr(r[3] ?? r.definition),
      created: Number(r[4] ?? r.created ?? 0),
      updated: Number(r[5] ?? r.updated ?? 0),
    };
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    const account = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => undefined,
    } as any;

    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.getNetworkPassphrase(),
    })
      .addOperation(this.schemaRegistryContract.call(method, ...args))
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
}
