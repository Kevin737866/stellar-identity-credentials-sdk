import { DIDResolver, W3CResolutionResult } from '../didResolver';
import { StellarIdentityConfig, DIDDocument } from '../types';

// Mock stellar-sdk
jest.mock('stellar-sdk', () => ({
  SorobanRpc: {
    Server: jest.fn().mockImplementation(() => ({
      simulateTransaction: jest.fn(),
      getAccount: jest.fn(),
      prepareTransaction: jest.fn(),
      sendTransaction: jest.fn(),
      getTransaction: jest.fn(),
    })),
    Api: {
      isSimulationError: jest.fn().mockReturnValue(false),
      SimulateTransactionSuccessResponse: class {},
      SimulateTransactionErrorResponse: class {},
    },
  },
  Contract: jest.fn().mockImplementation(() => ({
    call: jest.fn().mockReturnValue({}),
  })),
  Keypair: {
    random: jest.fn().mockReturnValue({
      publicKey: jest.fn().mockReturnValue('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5'),
      sign: jest.fn(),
    }),
  },
  TransactionBuilder: jest.fn().mockImplementation((account: any, opts: any) => ({
    addOperation: jest.fn().mockReturnThis(),
    setTimeout: jest.fn().mockReturnThis(),
    build: jest.fn().mockReturnValue({}),
  })),
  Networks: {
    PUBLIC: 'Public Global Stellar Network ; September 2015',
    TESTNET: 'Test SDF Network ; September 2015',
    FUTURENET: 'Test SDF Future Network ; October 2022',
  },
  Address: {
    fromString: jest.fn().mockReturnValue({}),
    fromScAddress: jest.fn().mockReturnValue({}),
  },
  nativeToScVal: jest.fn().mockReturnValue({}),
  scValToNative: jest.fn().mockReturnValue({}),
  xdr: {
    ScVal: {
      scvAddress: jest.fn().mockReturnValue({}),
      scvVec: jest.fn().mockReturnValue({}),
      scvVoid: jest.fn().mockReturnValue({}),
      scvMap: jest.fn().mockReturnValue({}),
    },
    ScMapEntry: jest.fn(),
  },
}));

const VALID_TESTNET_CONFIG: StellarIdentityConfig = {
  network: 'testnet',
  contracts: {
    didRegistry: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822a',
    credentialIssuer: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822b',
    reputationScore: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822c',
    zkAttestation: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822d',
    complianceFilter: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822e',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

const VALID_DID = 'did:stellar:GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';

describe('DIDResolver - TOML Resolution', () => {
  let resolver: DIDResolver;

  beforeEach(() => {
    resolver = new DIDResolver(VALID_TESTNET_CONFIG);
    // Clear all caches
    resolver.clearCache();
  });

  describe('resolveViaTOML', () => {
    it('should reject invalid DID format', async () => {
      const result = await resolver.resolveViaTOML('invalid-did');
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
    });

    it('should handle TOML fetch failure gracefully', async () => {
      const mockFetch = jest.spyOn(global, 'fetch').mockRejectedValueOnce(
        new Error('Network error')
      );

      const result = await resolver.resolveViaTOML(VALID_DID);

      expect(result.didResolutionMetadata.error).toBe('internalError');
      expect(result.didResolutionMetadata.message).toContain('Failed to fetch TOML');

      mockFetch.mockRestore();
    });

    it('should handle TOML not found (404)', async () => {
      const mockResponse = {
        ok: false,
        status: 404,
        text: jest.fn(),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolveViaTOML(VALID_DID);

      expect(result.didResolutionMetadata.error).toBe('notFound');
      expect(result.didResolutionMetadata.message).toContain('TOML file not found');

      mockFetch.mockRestore();
    });

    it('should handle timeout', async () => {
      const abortError = new DOMException('The operation was aborted.', 'AbortError');
      const mockFetch = jest.spyOn(global, 'fetch').mockRejectedValueOnce(abortError);

      const result = await resolver.resolveViaTOML(VALID_DID, { timeout: 100 });

      expect(result.didResolutionMetadata.error).toBe('timeout');
      expect(result.didResolutionMetadata.message).toContain('timed out');

      mockFetch.mockRestore();
    });

    it('should parse valid TOML and return DID document', async () => {
      const tomlContent = `
DID_CONTROLLER = "GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5"
DID_PUBLIC_KEY = "GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5"
DID_AUTHENTICATION = "#key-1"

[[DID_SERVICES]]
id = "#hub"
type = "IdentityHub"
serviceEndpoint = "https://identity-hub.example.com"
`;
      const mockResponse = {
        ok: true,
        text: jest.fn().mockResolvedValue(tomlContent),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolveViaTOML(VALID_DID);

      expect(result.didResolutionMetadata.error).toBeUndefined();
      expect(result.didResolutionMetadata.method).toBe('stellar-toml');

      const doc = result.didDocument as DIDDocument;
      expect(doc.id).toBe(VALID_DID);
      expect(doc.controller).toBe('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5');
      expect(doc.verificationMethod.length).toBe(1);
      expect(doc.service.length).toBe(1);
      expect(doc.service[0].type).toBe('IdentityHub');

      mockFetch.mockRestore();
    });

    it('should cache TOML results', async () => {
      const tomlContent = `
DID_CONTROLLER = "GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5"
`;
      const mockResponse = {
        ok: true,
        text: jest.fn().mockResolvedValue(tomlContent),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValue(
        mockResponse as unknown as Response
      );

      // First call
      await resolver.resolveViaTOML(VALID_DID);
      // Second call should use cache
      await resolver.resolveViaTOML(VALID_DID);

      // Should only have fetched once
      expect(mockFetch).toHaveBeenCalledTimes(1);

      mockFetch.mockRestore();
    });
  });
});

describe('DIDResolver - HTTP Resolution', () => {
  let resolver: DIDResolver;

  beforeEach(() => {
    resolver = new DIDResolver(VALID_TESTNET_CONFIG);
    resolver.clearCache();
  });

  describe('resolveViaHTTP', () => {
    it('should reject invalid DID format', async () => {
      const result = await resolver.resolveViaHTTP('invalid-did');
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
    });

    it('should handle HTTP fetch failure', async () => {
      const mockFetch = jest.spyOn(global, 'fetch').mockRejectedValueOnce(
        new Error('Connection refused')
      );

      const result = await resolver.resolveViaHTTP(VALID_DID);

      expect(result.didResolutionMetadata.error).toBe('internalError');
      expect(result.didResolutionMetadata.message).toContain('Failed to resolve via HTTP');

      mockFetch.mockRestore();
    });

    it('should handle HTTP 404', async () => {
      const mockResponse = {
        ok: false,
        status: 404,
        json: jest.fn(),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolveViaHTTP(VALID_DID);

      expect(result.didResolutionMetadata.error).toBe('notFound');

      mockFetch.mockRestore();
    });

    it('should handle HTTP 500', async () => {
      const mockResponse = {
        ok: false,
        status: 500,
        json: jest.fn(),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolveViaHTTP(VALID_DID);

      expect(result.didResolutionMetadata.error).toBe('internalError');
      expect(result.didResolutionMetadata.message).toContain('500');

      mockFetch.mockRestore();
    });

    it('should handle timeout', async () => {
      const abortError = new DOMException('The operation was aborted.', 'AbortError');
      const mockFetch = jest.spyOn(global, 'fetch').mockRejectedValueOnce(abortError);

      const result = await resolver.resolveViaHTTP(VALID_DID, undefined, { timeout: 100 });

      expect(result.didResolutionMetadata.error).toBe('timeout');

      mockFetch.mockRestore();
    });

    it('should parse valid HTTP response', async () => {
      const httpBody = {
        didDocument: {
          id: VALID_DID,
          controller: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'Ed25519VerificationKey2018',
              controller: VALID_DID,
              publicKey: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
            },
          ],
          authentication: ['#key-1'],
          service: [
            {
              id: '#hub',
              type: 'IdentityHub',
              endpoint: 'https://hub.example.com',
            },
          ],
          created: Date.now(),
          updated: Date.now(),
        },
      };
      const mockResponse = {
        ok: true,
        status: 200,
        json: jest.fn().mockResolvedValue(httpBody),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolveViaHTTP(VALID_DID);

      expect(result.didResolutionMetadata.error).toBeUndefined();
      expect(result.didResolutionMetadata.method).toBe('stellar-http');

      const doc = result.didDocument as DIDDocument;
      expect(doc.id).toBe(VALID_DID);
      expect(doc.verificationMethod.length).toBe(1);
      expect(doc.service.length).toBe(1);

      mockFetch.mockRestore();
    });

    it('should accept Accept header for DID resolution', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        json: jest.fn().mockResolvedValue({ id: VALID_DID }),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      await resolver.resolveViaHTTP(VALID_DID);

      const fetchCall = mockFetch.mock.calls[0];
      expect(fetchCall[1]?.headers).toEqual({
        'Accept': 'application/did+ld+json, application/json',
      });

      mockFetch.mockRestore();
    });

    it('should cache HTTP results', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        json: jest.fn().mockResolvedValue({ id: VALID_DID }),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValue(
        mockResponse as unknown as Response
      );

      // First call
      await resolver.resolveViaHTTP(VALID_DID);
      // Second call should use cache
      await resolver.resolveViaHTTP(VALID_DID);

      expect(mockFetch).toHaveBeenCalledTimes(1);

      mockFetch.mockRestore();
    });

    it('should use custom endpoint when provided', async () => {
      const customEndpoint = 'https://custom-resolver.example.com';
      const mockResponse = {
        ok: true,
        status: 200,
        json: jest.fn().mockResolvedValue({ id: VALID_DID }),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      await resolver.resolveViaHTTP(VALID_DID, customEndpoint);

      const fetchCall = mockFetch.mock.calls[0];
      expect(fetchCall[0]).toContain(customEndpoint);

      mockFetch.mockRestore();
    });
  });
});

describe('DIDResolver - Unified resolve with options', () => {
  let resolver: DIDResolver;

  beforeEach(() => {
    resolver = new DIDResolver(VALID_TESTNET_CONFIG);
    resolver.clearCache();
  });

  describe('resolve() with method option', () => {
    it('should route to TOML when method is "toml"', async () => {
      const tomlContent = `
DID_CONTROLLER = "GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5"
`;
      const mockResponse = {
        ok: true,
        text: jest.fn().mockResolvedValue(tomlContent),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolve(VALID_DID, { method: 'toml' });

      expect(result.didResolutionMetadata.method).toBe('stellar-toml');
      expect(result.didResolutionMetadata.error).toBeUndefined();

      mockFetch.mockRestore();
    });

    it('should route to HTTP when method is "http"', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        json: jest.fn().mockResolvedValue({ id: VALID_DID }),
      };
      const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValueOnce(
        mockResponse as unknown as Response
      );

      const result = await resolver.resolve(VALID_DID, { method: 'http' });

      expect(result.didResolutionMetadata.method).toBe('stellar-http');
      expect(result.didResolutionMetadata.error).toBeUndefined();

      mockFetch.mockRestore();
    });

    it('should default to contract resolution when no method specified', async () => {
      const result = await resolver.resolve(VALID_DID);

      // Contract resolution would fail in test because we haven't mocked the full
      // Soroban simulation flow, but it should still be called
      expect(result.didResolutionMetadata.method).toBeUndefined();
    });
  });

  describe('resolveWithFallback', () => {
    it('should try contract first, then TOML, then HTTP', async () => {
      // Make TOML fail too - only HTTP should succeed
      const mockFetch = jest.spyOn(global, 'fetch')
        // TOML call fails
        .mockRejectedValueOnce(new Error('TOML down'))
        // HTTP call succeeds
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: jest.fn().mockResolvedValue({ id: VALID_DID }),
        } as unknown as Response);

      const result = await resolver.resolve(VALID_DID, { fallback: true, timeout: 100 });

      // Should have got the HTTP result
      expect(result.didResolutionMetadata.method).toBe('stellar-http');
      expect(result.didResolutionMetadata.error).toBeUndefined();

      mockFetch.mockRestore();
    });

    it('should return error when all methods fail', async () => {
      const mockFetch = jest.spyOn(global, 'fetch')
        .mockRejectedValue(new Error('Everything is down'));

      const result = await resolver.resolve(VALID_DID, { fallback: true, timeout: 100 });

      expect(result.didResolutionMetadata.error).toBeDefined();
      expect(result.didDocument).toEqual({});

      mockFetch.mockRestore();
    });
  });

  describe('explicit resolveWithFallback', () => {
    it('should return HTTP result when contract and TOML fail', async () => {
      const mockFetch = jest.spyOn(global, 'fetch')
        .mockRejectedValueOnce(new Error('TOML down'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: jest.fn().mockResolvedValue({ id: VALID_DID }),
        } as unknown as Response);

      const result = await resolver.resolveWithFallback(VALID_DID, { timeout: 100 });

      expect(result.didResolutionMetadata.method).toBe('stellar-http');

      mockFetch.mockRestore();
    });
  });
});

describe('DIDResolver - Clear cache', () => {
  it('should clear all caches including TOML and HTTP', async () => {
    const resolver = new DIDResolver(VALID_TESTNET_CONFIG);

    // Cache a TOML result
    const mockResponse = {
      ok: true,
      text: jest.fn().mockResolvedValue(''),
    };
    const mockFetch = jest.spyOn(global, 'fetch').mockResolvedValue(
      mockResponse as unknown as Response
    );

    await resolver.resolveViaTOML(VALID_DID);
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Clear cache
    resolver.clearCache();

    // Should fetch again
    await resolver.resolveViaTOML(VALID_DID);
    expect(mockFetch).toHaveBeenCalledTimes(2);

    mockFetch.mockRestore();
  });
});

describe('DIDResolver - Static helpers', () => {
  it('addressToDID should convert address to DID', () => {
    const did = DIDResolver.addressToDID('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5');
    expect(did).toBe(VALID_DID);
  });

  it('addressToDID with suffix', () => {
    const did = DIDResolver.addressToDID('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5', 'v1');
    expect(did).toBe(`${VALID_DID}:v1`);
  });

  it('didToAddress should extract address', () => {
    const address = DIDResolver.didToAddress(VALID_DID);
    expect(address).toBe('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5');
  });

  it('didToAddress with suffix', () => {
    const address = DIDResolver.didToAddress(`${VALID_DID}:v1`);
    expect(address).toBe('GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5');
  });

  it('validateDIDFormat should accept valid DID', () => {
    const resolver = new DIDResolver(VALID_TESTNET_CONFIG);
    const error = resolver.validateDIDFormat(VALID_DID);
    expect(error).toBeNull();
  });

  it('validateDIDFormat should reject non-did:stellar prefix', () => {
    const resolver = new DIDResolver(VALID_TESTNET_CONFIG);
    const error = resolver.validateDIDFormat('did:other:abc123');
    expect(error).toContain('must start with');
  });
});
