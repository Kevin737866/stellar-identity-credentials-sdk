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
  Transaction,
} from 'stellar-sdk';
import {
  DIDDocument,
  VerificationMethod,
  Service,
  StellarIdentityConfig,
  CreateDIDOptions,
  UpdateDIDOptions,
  TransactionOptions,
  DIDResolutionResult,
} from './types';
import {
  StellarIdentityError,
  DIDError,
  ConfigurationError,
  ErrorCode,
  mapContractError,
} from './errors';
import { CacheManager, DataType } from './cacheManager';

// ── Constants ─────────────────────────────────────────────────────────────────

const DEFAULT_FEE = 100;
const DEFAULT_TIMEOUT_SECS = 30;
const DEFAULT_POLL_INTERVAL_MS = 2_000;
const DEFAULT_POLL_MAX_ATTEMPTS = 15;
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY_MS = 500;

const LIMITS = {
  MAX_VERIFICATION_METHODS: 20,
  MAX_SERVICES: 20,
  MAX_VM_ID_LENGTH: 256,
  MAX_VM_TYPE_LENGTH: 64,
  MAX_SERVICE_ID_LENGTH: 256,
  MAX_SERVICE_ENDPOINT_LENGTH: 1_024,
  MAX_AUTH_METHOD_LENGTH: 256,
} as const;

const RPC_URLS: Record<string, string> = {
  mainnet: 'https://soroban-rpc.stellar.org',
  futurenet: 'https://rpc-futurenet.stellar.org',
  testnet: 'https://soroban-testnet.stellar.org',
};

const NETWORK_PASSPHRASES: Record<string, string> = {
  mainnet: Networks.PUBLIC,
  futurenet: Networks.FUTURENET,
  testnet: Networks.TESTNET,
};

// Shared encoder / decoder singletons.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ── Internal helpers ──────────────────────────────────────────────────────────

function encodeBytes(value: string): Uint8Array {
  return encoder.encode(value);
}

function decodeBytes(value: unknown): string {
  return value instanceof Uint8Array ? decoder.decode(value) : String(value ?? '');
}

function hexToBytes(hex: string): Uint8Array {
  return Uint8Array.from((hex.match(/.{2}/g) ?? []).map(b => parseInt(b, 16)));
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface TransactionResult {
  hash: string;
  ledger: number;
  status: 'SUCCESS' | 'FAILED';
}

export interface BatchResolutionResult {
  did: string;
  result: DIDResolutionResult | null;
  error: Error | null;
}

export interface RetryOptions {
  attempts?: number;
  delayMs?: number;
}

// ── Client ────────────────────────────────────────────────────────────────────

/**
 * Client for managing decentralized identifiers (DIDs) on Stellar.
 * Provides methods for creating, resolving, updating, and deactivating DIDs
 * using the W3C did:stellar method via Soroban smart contracts.
 *
 * All mutating methods wait for on-chain confirmation before returning.
 * Read methods use an in-memory cache with automatic invalidation.
 *
 * @category Client
 */
export class DIDClient {
  private readonly rpc: SorobanRpc.Server;
  private readonly config: StellarIdentityConfig;
  private readonly contract: Contract;
  private readonly cache: CacheManager;
  private readonly networkPassphrase: string;

  constructor(config: StellarIdentityConfig) {
    if (!config.contracts?.didRegistry) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        'config.contracts.didRegistry is required',
      );
    }
    this.config = config;
    this.networkPassphrase =
      NETWORK_PASSPHRASES[config.network] ?? Networks.TESTNET;
    this.rpc = new SorobanRpc.Server(
      config.rpcUrl ?? RPC_URLS[config.network] ?? RPC_URLS.testnet,
    );
    this.contract = new Contract(config.contracts.didRegistry);
    this.cache = new CacheManager();
  }

  // ── DID lifecycle ─────────────────────────────────────────────────────────

  /**
   * Create a new DID on the Stellar network.
   *
   * @param keypair - The keypair of the DID controller.
   * @param options - DID creation options (verification methods, services).
   * @param txOptions - Optional transaction parameters.
   * @returns The generated DID string (e.g. `did:stellar:G…`).
   */
  async createDID(
    keypair: Keypair,
    options: CreateDIDOptions,
    txOptions?: TransactionOptions,
  ): Promise<string> {
    const address = keypair.publicKey();
    this.assertValidStellarAddress(address);
    this.assertCreateOptions(options);

    const did = this.generateDID(address);

    await this.sendTransaction(
      keypair,
      this.contract.call(
        'create_did',
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
        nativeToScVal(encodeBytes(did), { type: 'bytes' }),
        this.serializeVerificationMethods(options.verificationMethods),
        this.serializeServices(options.services),
      ),
      txOptions,
    );

    return did;
  }

  /**
   * Resolve a DID to its DID document.
   * Results are cached; use `forceRefresh` to bypass the cache.
   *
   * @param did - The DID to resolve (e.g. `did:stellar:G…`).
   * @param forceRefresh - Skip cache and fetch from chain.
   * @returns Resolution result containing the DID document and metadata.
   */
  async resolveDID(
    did: string,
    forceRefresh = false,
  ): Promise<DIDResolutionResult> {
    this.assertValidDIDFormat(did);

    if (!forceRefresh) {
      const cached = this.cache.get<DIDResolutionResult>(DataType.DID_DOCUMENT, did);
      if (cached) return cached;
    }

    const retval = await this.withRetry(() =>
      this.simulateRead('resolve_did', [
        nativeToScVal(encodeBytes(did), { type: 'bytes' }),
      ]),
    );

    const raw = scValToNative(retval) as Record<string, unknown>;
    const didDocument = this.parseDIDDocument(raw, did);

    const result: DIDResolutionResult = {
      didDocument,
      resolverMetadata: { method: 'stellar', network: this.config.network },
      documentMetadata: {
        created: didDocument.created,
        updated: didDocument.updated,
      },
    };

    this.cache.set(DataType.DID_DOCUMENT, did, result);
    return result;
  }

  /**
   * Resolve multiple DIDs concurrently.
   * Failures are captured per-DID rather than aborting the entire batch.
   *
   * @param dids - Array of DID strings to resolve.
   * @returns Array of per-DID resolution results or errors.
   */
  async resolveDIDBatch(dids: string[]): Promise<BatchResolutionResult[]> {
    return Promise.all(
      dids.map(async did => {
        try {
          const result = await this.resolveDID(did);
          return { did, result, error: null };
        } catch (error) {
          return { did, result: null, error: error as Error };
        }
      }),
    );
  }

  /**
   * Update the verification methods and/or services of an existing DID.
   * Pass `undefined` for a field to leave it unchanged on-chain.
   *
   * Supports two calling conventions:
   * 1. `updateDID(keypair, options: UpdateDIDOptions, txOptions?)`
   * 2. `updateDID(keypair, verificationMethods?, services?, txOptions?)`
   *
   * @param keypair - The keypair of the DID controller.
   * @param optionsOrVMs - Either `UpdateDIDOptions` or verification methods array.
   * @param servicesOrTx - Services array (when using legacy signature) or txOptions.
   * @param txOptions - Optional transaction parameters.
   */
  async updateDID(
    keypair: Keypair,
    optionsOrVMs?: UpdateDIDOptions | VerificationMethod[],
    servicesOrTx?: Service[] | TransactionOptions,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    let verificationMethods: VerificationMethod[] | undefined;
    let services: Service[] | undefined;

    // Detect calling convention: if first arg is an object with 'verificationMethods' or 'services'
    if (
      optionsOrVMs &&
      typeof optionsOrVMs === 'object' &&
      !Array.isArray(optionsOrVMs) &&
      ('verificationMethods' in optionsOrVMs || 'services' in optionsOrVMs)
    ) {
      const opts = optionsOrVMs as UpdateDIDOptions;
      verificationMethods = opts.verificationMethods;
      services = opts.services;
      txOptions = servicesOrTx as TransactionOptions | undefined;
    } else {
      verificationMethods = optionsOrVMs as VerificationMethod[] | undefined;
      services = servicesOrTx as Service[] | undefined;
    }
    const address = keypair.publicKey();
    this.assertValidStellarAddress(address);

    if (verificationMethods !== undefined) {
      this.assertVerificationMethods(verificationMethods);
    }
    if (services !== undefined) {
      this.assertServices(services);
    }

    const methodsScVal = verificationMethods !== undefined
      ? xdr.ScVal.scvVec([this.serializeVerificationMethods(verificationMethods)])
      : xdr.ScVal.scvVoid();

    const servicesScVal = services !== undefined
      ? xdr.ScVal.scvVec([this.serializeServices(services)])
      : xdr.ScVal.scvVoid();

    const result = await this.sendTransaction(
      keypair,
      this.contract.call(
        'update_did',
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
        methodsScVal,
        servicesScVal,
      ),
      txOptions,
    );

    this.cache.invalidate(DataType.DID_DOCUMENT, this.generateDID(address));
    return result;
  }

  /**
   * Permanently deactivate a DID.
   *
   * @param keypair - The keypair of the DID controller.
   * @param txOptions - Optional transaction parameters.
   */
  async deactivateDID(
    keypair: Keypair,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    const address = keypair.publicKey();
    this.assertValidStellarAddress(address);

    const result = await this.sendTransaction(
      keypair,
      this.contract.call(
        'deactivate_did',
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ),
      txOptions,
    );

    this.cache.invalidate(DataType.DID_DOCUMENT, this.generateDID(address));
    return result;
  }

  // ── Authentication management ─────────────────────────────────────────────

  /**
   * Add an authentication method to the caller's DID.
   *
   * @param keypair - The keypair of the DID controller.
   * @param authenticationMethod - The authentication method identifier.
   * @param txOptions - Optional transaction parameters.
   */
  async addAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    return this.mutateAuthentication(
      keypair,
      'add_authentication',
      authenticationMethod,
      txOptions,
    );
  }

  /**
   * Remove an authentication method from the caller's DID.
   *
   * @param keypair - The keypair of the DID controller.
   * @param authenticationMethod - The authentication method identifier.
   * @param txOptions - Optional transaction parameters.
   */
  async removeAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    return this.mutateAuthentication(
      keypair,
      'remove_authentication',
      authenticationMethod,
      txOptions,
    );
  }

  // ── Read-only queries ─────────────────────────────────────────────────────

  /**
   * Check whether a DID is registered on-chain.
   *
   * @param did - The DID string to check.
   */
  async didExists(did: string): Promise<boolean> {
    this.assertValidDIDFormat(did);
    const retval = await this.withRetry(() =>
      this.simulateRead('did_exists', [
        nativeToScVal(encodeBytes(did), { type: 'bytes' }),
      ]),
    );
    return scValToNative(retval) as boolean;
  }

  /**
   * Look up the DID associated with a Stellar address.
   *
   * @param address - A Stellar public key (G…).
   * @returns The DID string, or `null` if none is registered.
   */
  async getControllerDID(address: string): Promise<string | null> {
    this.assertValidStellarAddress(address);
    const retval = await this.withRetry(() =>
      this.simulateRead('get_controller_did', [
        xdr.ScVal.scvAddress(new Address(address).toScAddress()),
      ]),
    );
    const raw = scValToNative(retval);
    if (!raw) return null;
    return raw instanceof Uint8Array ? decodeBytes(raw) : String(raw);
  }

  // ── TOML resolution ───────────────────────────────────────────────────────

  /**
   * Resolve a DID document via the stellar.toml file published at the
   * controller's home domain. Useful as a fallback when on-chain data
   * is unavailable.
   *
   * @param did - The DID string to resolve.
   */
  async resolveDIDWithTOML(did: string): Promise<DIDDocument> {
    this.assertValidDIDFormat(did);
    const stellarAddress = this.extractStellarAddress(did);
    const toml = await this.fetchStellarTOML(stellarAddress);
    return this.parseDIDFromTOML(toml, stellarAddress);
  }

  // ── DID utility methods ───────────────────────────────────────────────────

  /**
   * Validate the format of a DID string without making a network call.
   *
   * @param did - The DID string to validate.
   */
  validateDIDFormat(did: string): boolean {
    if (!did.startsWith('did:stellar:')) return false;
    const [potentialAddress] = did.substring(12).split(':');
    return this.isValidStellarAddress(potentialAddress);
  }

  /**
   * Generate a `did:stellar:` DID from a Stellar address.
   *
   * @param address - A valid Stellar public key.
   * @param suffix - Optional suffix appended as an additional DID path segment.
   */
  generateDID(address: string, suffix?: string): string {
    this.assertValidStellarAddress(address);
    return suffix ? `did:stellar:${address}:${suffix}` : `did:stellar:${address}`;
  }

  /**
   * Extract the Stellar address embedded in a DID string.
   *
   * @param did - A `did:stellar:G…` string.
   * @returns The Stellar public key.
   */
  extractStellarAddress(did: string): string {
    this.assertValidDIDFormat(did);
    return did.substring(12).split(':')[0];
  }

  // ── Private — transaction helpers ─────────────────────────────────────────

  /**
   * Build, sign, submit, and await confirmation for a single Soroban operation.
   */
  private async sendTransaction(
    keypair: Keypair,
    operation: xdr.Operation,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    const address = keypair.publicKey();
    const account = await this.withRetry(() => this.rpc.getAccount(address));

    const tx = new TransactionBuilder(account, {
      fee: String(txOptions?.fee ?? DEFAULT_FEE),
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(operation)
      .setTimeout(txOptions?.timeout ?? DEFAULT_TIMEOUT_SECS)
      .build();

    const prepared = await this.withRetry(() => this.rpc.prepareTransaction(tx));
    (prepared as Transaction).sign(keypair);

    const submission = await this.rpc.sendTransaction(prepared as Transaction);
    if (submission.status === 'ERROR') {
      throw new DIDError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Transaction submission failed: ${JSON.stringify(submission.errorResult)}`,
      );
    }

    return this.pollTransactionConfirmation(submission.hash, txOptions);
  }

  /**
   * Poll the RPC until a submitted transaction is confirmed or times out.
   */
  private async pollTransactionConfirmation(
    hash: string,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    const maxAttempts = DEFAULT_POLL_MAX_ATTEMPTS;
    const intervalMs = DEFAULT_POLL_INTERVAL_MS;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      await sleep(intervalMs);
      const status = await this.rpc.getTransaction(hash);

      if (status.status === SorobanRpc.Api.GetTransactionStatus.SUCCESS) {
        return {
          hash,
          ledger: (status as SorobanRpc.Api.GetSuccessfulTransactionResponse).ledger,
          status: 'SUCCESS',
        };
      }

      if (status.status === SorobanRpc.Api.GetTransactionStatus.FAILED) {
        throw new DIDError(
          ErrorCode.ConfigInvalidRpcUrl,
          `Transaction ${hash} failed on-chain`,
        );
      }
      // NOT_FOUND or PENDING → keep polling.
    }

    throw new DIDError(
      ErrorCode.ConfigInvalidRpcUrl,
      `Transaction ${hash} not confirmed after ${maxAttempts} attempts`,
    );
  }

  /**
   * Execute a read-only contract call by simulation (no fee, no signing).
   */
  private async simulateRead(
    method: string,
    args: xdr.ScVal[],
  ): Promise<xdr.ScVal> {
    // Use a throwaway keypair only to satisfy TransactionBuilder's type
    // requirements — simulation never broadcasts.
    const dummy = Keypair.random();
    const account = {
      accountId: () => dummy.publicKey(),
      sequenceNumber: () => '0',
      incrementSequenceNumber: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } as any;

    const tx = new TransactionBuilder(account, {
      fee: '100',
      networkPassphrase: this.networkPassphrase,
    })
      .addOperation(this.contract.call(method, ...args))
      .setTimeout(DEFAULT_TIMEOUT_SECS)
      .build();

    const sim = await this.rpc.simulateTransaction(tx);

    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error(
        (sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error,
      );
    }

    const retval = (
      sim as SorobanRpc.Api.SimulateTransactionSuccessResponse
    ).result?.retval;

    if (!retval) {
      throw new Error(`No return value from contract method '${method}'`);
    }

    return retval;
  }

  /**
   * Retry an async operation with exponential back-off.
   */
  private async withRetry<T>(
    fn: () => Promise<T>,
    options: RetryOptions = {},
  ): Promise<T> {
    const attempts = options.attempts ?? DEFAULT_RETRY_ATTEMPTS;
    const delayMs = options.delayMs ?? DEFAULT_RETRY_DELAY_MS;
    let lastError: unknown;

    for (let i = 0; i < attempts; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        if (i < attempts - 1) {
          await sleep(delayMs * 2 ** i); // exponential back-off
        }
      }
    }

    throw this.handleError(lastError);
  }

  // ── Private — authentication helper ──────────────────────────────────────

  private async mutateAuthentication(
    keypair: Keypair,
    contractMethod: string,
    authenticationMethod: string,
    txOptions?: TransactionOptions,
  ): Promise<TransactionResult> {
    this.assertValidStellarAddress(keypair.publicKey());
    this.assertNonEmpty(authenticationMethod, 'Authentication method');
    this.assertMaxLength(
      authenticationMethod,
      LIMITS.MAX_AUTH_METHOD_LENGTH,
      'Authentication method',
    );

    const result = await this.sendTransaction(
      keypair,
      this.contract.call(
        contractMethod,
        xdr.ScVal.scvAddress(new Address(keypair.publicKey()).toScAddress()),
        nativeToScVal(encodeBytes(authenticationMethod), { type: 'bytes' }),
      ),
      txOptions,
    );

    this.cache.invalidate(
      DataType.DID_DOCUMENT,
      this.generateDID(keypair.publicKey()),
    );
    return result;
  }

  // ── Private — serialization ───────────────────────────────────────────────

  private serializeVerificationMethods(vms: VerificationMethod[]): xdr.ScVal {
    return nativeToScVal(
      vms.map(vm => ({
        id: encodeBytes(vm.id),
        type_: encodeBytes(vm.type),
        controller: new Address(vm.controller),
        public_key: hexToBytes(vm.publicKey),
      })),
      { type: 'vec' },
    );
  }

  private serializeServices(services: Service[]): xdr.ScVal {
    return nativeToScVal(
      services.map(s => ({
        id: encodeBytes(s.id),
        type_: encodeBytes(s.type),
        endpoint: encodeBytes(s.endpoint),
      })),
      { type: 'vec' },
    );
  }

  // ── Private — parsing ─────────────────────────────────────────────────────

  private parseDIDDocument(
    raw: Record<string, unknown>,
    did: string,
  ): DIDDocument {
    return {
      id: decodeBytes(raw.id) || did,
      controller: decodeBytes(raw.controller),
      verificationMethod: Array.isArray(raw.verification_method)
        ? raw.verification_method.map((vm: unknown) => {
            const v = vm as Record<string, unknown>;
            return {
              id: decodeBytes(v.id),
              type: decodeBytes(v.type_),
              controller: decodeBytes(v.controller),
              publicKey: bytesToHex(v.public_key as Uint8Array),
            };
          })
        : [],
      authentication: Array.isArray(raw.authentication)
        ? raw.authentication.map(decodeBytes)
        : [],
      service: Array.isArray(raw.service)
        ? raw.service.map((s: unknown) => {
            const sv = s as Record<string, unknown>;
            return {
              id: decodeBytes(sv.id),
              type: decodeBytes(sv.type_),
              endpoint: decodeBytes(sv.endpoint),
            };
          })
        : [],
      created: Number(raw.created ?? 0),
      updated: Number(raw.updated ?? 0),
    };
  }

  private parseDIDFromTOML(
    toml: Record<string, string>,
    address: string,
  ): DIDDocument {
    const now = Date.now();
    return {
      id: `did:stellar:${address}`,
      controller: toml['ACCOUNTS'] ?? address,
      verificationMethod: [],
      authentication: [],
      service: [],
      created: now,
      updated: now,
    };
  }

  // ── Private — TOML ────────────────────────────────────────────────────────

  private async fetchStellarTOML(
    address: string,
  ): Promise<Record<string, string>> {
    const domain = this.getDomainFromAddress(address);
    const response = await fetch(`https://${domain}/.well-known/stellar.toml`);
    if (!response.ok) {
      throw new Error(
        `Failed to fetch stellar.toml from ${domain}: HTTP ${response.status}`,
      );
    }
    return this.parseTOML(await response.text());
  }

  /**
   * Derive the home domain for a Stellar address.
   * Override this in a subclass to support federation lookups.
   */
  protected getDomainFromAddress(_address: string): string {
    return 'stellar.org';
  }

  private parseTOML(text: string): Record<string, string> {
    return Object.fromEntries(
      text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#') && line.includes('='))
        .map(line => {
          const eq = line.indexOf('=');
          return [
            line.slice(0, eq).trim(),
            line.slice(eq + 1).trim().replace(/"/g, ''),
          ] as [string, string];
        }),
    );
  }

  // ── Private — validation ──────────────────────────────────────────────────

  private isValidStellarAddress(address: string): boolean {
    try {
      Address.fromString(address);
      return true;
    } catch {
      return false;
    }
  }

  private assertValidStellarAddress(address: string): void {
    if (!this.isValidStellarAddress(address)) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Invalid Stellar address: ${address}`,
      );
    }
  }

  private assertValidDIDFormat(did: string): void {
    if (!this.validateDIDFormat(did)) {
      throw new DIDError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Invalid DID format: ${did}`,
      );
    }
  }

  private assertNonEmpty(value: string, fieldName: string): void {
    if (!value || value.trim().length === 0) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `${fieldName} must not be empty`,
      );
    }
  }

  private assertMaxLength(
    value: string,
    max: number,
    fieldName: string,
  ): void {
    if (value.length > max) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `${fieldName} exceeds maximum length of ${max} characters`,
      );
    }
  }

  private assertVerificationMethods(vms: VerificationMethod[]): void {
    if (vms.length > LIMITS.MAX_VERIFICATION_METHODS) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Too many verification methods (max ${LIMITS.MAX_VERIFICATION_METHODS})`,
      );
    }
    for (const vm of vms) {
      this.assertMaxLength(vm.id, LIMITS.MAX_VM_ID_LENGTH, 'Verification method ID');
      this.assertMaxLength(vm.type, LIMITS.MAX_VM_TYPE_LENGTH, 'Verification method type');
      this.assertValidStellarAddress(vm.controller);
      if (!vm.publicKey || !/^[0-9a-fA-F]+$/.test(vm.publicKey)) {
        throw new ConfigurationError(
          ErrorCode.ConfigInvalidRpcUrl,
          'Verification method publicKey must be a hex string',
        );
      }
    }
  }

  private assertServices(services: Service[]): void {
    if (services.length > LIMITS.MAX_SERVICES) {
      throw new ConfigurationError(
        ErrorCode.ConfigInvalidRpcUrl,
        `Too many services (max ${LIMITS.MAX_SERVICES})`,
      );
    }
    for (const svc of services) {
      this.assertMaxLength(svc.id, LIMITS.MAX_SERVICE_ID_LENGTH, 'Service ID');
      this.assertMaxLength(
        svc.endpoint,
        LIMITS.MAX_SERVICE_ENDPOINT_LENGTH,
        'Service endpoint',
      );
      try {
        new URL(svc.endpoint);
      } catch {
        throw new ConfigurationError(
          ErrorCode.ConfigInvalidRpcUrl,
          `Service endpoint is not a valid URL: ${svc.endpoint}`,
        );
      }
    }
  }

  private assertCreateOptions(options: CreateDIDOptions): void {
    this.assertVerificationMethods(options.verificationMethods);
    this.assertServices(options.services);
  }

  private handleError(error: unknown): StellarIdentityError {
    return mapContractError(error);
  }
}