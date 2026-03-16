import { 
  Server, 
  TransactionBuilder, 
  Networks, 
  Keypair, 
  Contract,
  Address,
  xdr
} from 'stellar-sdk';
import { 
  DIDDocument, 
  VerificationMethod, 
  Service, 
  StellarIdentityConfig,
  CreateDIDOptions,
  TransactionOptions,
  DIDResolutionResult,
  StellarIdentityError
} from './types';

export class DIDClient {
  private server: Server;
  private config: StellarIdentityConfig;
  private didRegistryContract: Contract;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.server = new Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.didRegistryContract = new Contract(config.contracts.didRegistry);
  }

  /**
   * Create a new DID document for a Stellar address
   * DID format: did:stellar:<stellar_address>
   */
  async createDID(
    keypair: Keypair,
    options: CreateDIDOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'create_did',
            ...this.prepareVerificationMethods(options.verificationMethods),
            ...this.prepareServices(options.services)
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      if (txOptions?.memo) {
        transaction.addMemo(txOptions.memo);
      }

      transaction.sign(keypair);
      const result = await this.server.sendTransaction(transaction);
      
      if (result.result) {
        return this.generateDID(keypair.publicKey());
      } else {
        throw new Error('Transaction failed');
      }
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Resolve a DID document
   */
  async resolveDID(did: string): Promise<DIDResolutionResult> {
    try {
      const result = await this.didRegistryContract.call('resolve_did', did);
      const didDocument = this.parseDIDDocument(result.result.val);
      
      return {
        didDocument,
        resolverMetadata: {
          method: 'stellar',
          network: this.config.network,
        },
        documentMetadata: {
          created: didDocument.created,
          updated: didDocument.updated,
        },
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Update a DID document
   */
  async updateDID(
    keypair: Keypair,
    verificationMethods?: VerificationMethod[],
    services?: Service[],
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call(
            'update_did',
            verificationMethods ? this.prepareVerificationMethods(verificationMethods) : [],
            services ? this.prepareServices(services) : []
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
   * Deactivate a DID document
   */
  async deactivateDID(
    keypair: Keypair,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call('deactivate_did')
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
   * Add authentication method to DID
   */
  async addAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call('add_authentication', authenticationMethod)
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
   * Remove authentication method from DID
   */
  async removeAuthentication(
    keypair: Keypair,
    authenticationMethod: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(keypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.didRegistryContract.call('remove_authentication', authenticationMethod)
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
   * Check if a DID exists
   */
  async didExists(did: string): Promise<boolean> {
    try {
      const result = await this.didRegistryContract.call('did_exists', did);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get DID for a controller address
   */
  async getControllerDID(address: string): Promise<string | null> {
    try {
      const result = await this.didRegistryContract.call('get_controller_did', address);
      return result.result.val || null;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Validate DID format
   */
  validateDIDFormat(did: string): boolean {
    return did.startsWith('did:stellar:') && this.isValidStellarAddress(did.substring(11));
  }

  /**
   * Generate DID from Stellar address
   */
  generateDID(address: string): string {
    if (!this.isValidStellarAddress(address)) {
      throw new Error('Invalid Stellar address');
    }
    return `did:stellar:${address}`;
  }

  /**
   * Extract Stellar address from DID
   */
  extractStellarAddress(did: string): string {
    if (!this.validateDIDFormat(did)) {
      throw new Error('Invalid DID format');
    }
    return did.substring(11);
  }

  /**
   * Resolve DID using Stellar TOML
   */
  async resolveDIDWithTOML(did: string): Promise<DIDDocument> {
    const stellarAddress = this.extractStellarAddress(did);
    const stellarToml = await this.fetchStellarTOML(stellarAddress);
    
    return this.parseDIDFromTOML(stellarToml, stellarAddress);
  }

  private prepareVerificationMethods(methods: VerificationMethod[]): any[] {
    return methods.map(method => [
      method.id,
      method.type,
      method.controller,
      method.publicKey
    ]);
  }

  private prepareServices(services: Service[]): any[] {
    return services.map(service => [
      service.id,
      service.type,
      service.endpoint
    ]);
  }

  private parseDIDDocument(result: any): DIDDocument {
    // Parse the xdr result into DIDDocument format
    return {
      id: result[0],
      controller: result[1],
      verificationMethod: result[2].map((vm: any) => ({
        id: vm[0],
        type: vm[1],
        controller: vm[2],
        publicKey: vm[3]
      })),
      authentication: result[3],
      service: result[4].map((s: any) => ({
        id: s[0],
        type: s[1],
        endpoint: s[2]
      })),
      created: result[5],
      updated: result[6]
    };
  }

  private async fetchStellarTOML(address: string): Promise<any> {
    const domain = this.getDomainFromAddress(address);
    const response = await fetch(`https://${domain}/.well-known/stellar.toml`);
    const tomlText = await response.text();
    return this.parseTOML(tomlText);
  }

  private getDomainFromAddress(address: string): string {
    // This is a simplified implementation
    // In practice, you'd use federation protocols or other methods
    return 'stellar.org'; // Default fallback
  }

  private parseTOML(tomlText: string): any {
    // Simplified TOML parsing - use a proper TOML library in production
    const lines = tomlText.split('\n');
    const result: any = {};
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        const [key, ...valueParts] = trimmed.split('=');
        if (key && valueParts.length > 0) {
          const value = valueParts.join('=').trim().replace(/"/g, '');
          result[key.trim()] = value;
        }
      }
    }
    
    return result;
  }

  private parseDIDFromTOML(toml: any, address: string): DIDDocument {
    return {
      id: `did:stellar:${address}`,
      controller: address,
      verificationMethod: [],
      authentication: [],
      service: [],
      created: Date.now(),
      updated: Date.now()
    };
  }

  private isValidStellarAddress(address: string): boolean {
    try {
      return Address.fromString(address).toString() === address;
    } catch {
      return false;
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
