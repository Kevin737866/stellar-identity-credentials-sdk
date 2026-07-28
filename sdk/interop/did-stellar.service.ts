import { Injectable, Logger, NotFoundException, BadRequestException } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Inject } from '@nestjs/common';
import { Cache } from 'cache-manager';
import { Horizon } from '@stellar/stellar-sdk';
import * as base58 from 'bs58';

@Injectable()
export class DidStellarService {
  private readonly logger = new Logger(DidStellarService.name);
  private readonly testnetHorizon = new Horizon.Server('https://horizon-testnet.stellar.org');
  private readonly mainnetHorizon = new Horizon.Server('https://horizon.stellar.org');

  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  /**
   * Resolves a fully qualified raw Stellar DID into a structured W3C Compliant DID Document matrix.
   * Matches signature: did:stellar:<network>:<publicKey>
   */
  public async resolveDid(did: string): Promise<UniversalResolverResponse> {
    const cacheKey = `did:resolve:${did}`;
    const cachedResponse = await this.cacheManager.get<UniversalResolverResponse>(cacheKey);
    if (cachedResponse) {
      this.logger.log(`Cache hit for DID resolution: ${did}`);
      return cachedResponse;
    }

    const segments = did.split(':');
    if (segments.length !== 4 || segments[0] !== 'did' || segments[1] !== 'stellar') {
      return this.buildErrorResponse('invalidDid');
    }

    const [, , network, publicKey] = segments;

    if (network !== 'mainnet' && network !== 'testnet') {
      return this.buildErrorResponse('unsupportedDidMethod');
    }

    try {
      // 1. Verify target account identity actually exists on the network cluster ledger
      const horizonServer = network === 'mainnet' ? this.mainnetHorizon : this.testnetHorizon;
      const accountInfo = await horizonServer.loadAccount(publicKey);

      // 2. Transform Stellar master keys into multibase standard arrays (Ed25519 header prefix: 0xed, 0x01)
      const rawPublicKeyBytes = base58.decode(publicKey); // Assuming base58 configuration payload format mappings
      const ed25519Prefix = Buffer.from([0xed, 0x01]);
      const multibasePublicKey = 'z' + base58.encode(Buffer.concat([ed25519Prefix, rawPublicKeyBytes]));

      const keyId = `${did}#key-1`;

      // 3. Assemble compliant W3C decentralized document properties
      const didDocument: DidDocument = {
        '@context': [
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/ed25519-2020/v1'
        ],
        id: did,
        verificationMethod: [
          {
            id: keyId,
            type: 'Ed25519VerificationKey2020',
            controller: did,
            publicKeyMultibase: multibasePublicKey
          }
        ],
        authentication: [keyId],
        assertionMethod: [keyId]
      };

      const response: UniversalResolverResponse = {
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
        didDocument,
        didDocumentMetadata: {
          created: new Date().toISOString() // Fallback time tracking index properties
        }
      };

      // 4. Cache valid documents for 1 hour to prevent flooding network providers
      await this.cacheManager.set(cacheKey, response, 3600000);

      return response;

    } catch (error: any) {
      this.logger.error(`Stellar Ledger resolve failure on key [${publicKey}]:`, error?.message);
      if (error?.response?.status === 404) {
        return this.buildErrorResponse('notFound');
      }
      return this.buildErrorResponse('invalidDid');
    }
  }

  private buildErrorResponse(errorType: 'invalidDid' | 'notFound' | 'unsupportedDidMethod'): UniversalResolverResponse {
    return {
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
        error: errorType
      },
      didDocument: null,
      didDocumentMetadata: {}
    };
  }
}