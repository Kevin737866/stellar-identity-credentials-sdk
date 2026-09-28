import { DIDClient } from '../didClient';
import { StellarIdentityConfig } from '../types';

// ── Mock stellar-sdk ─────────────────────────────────────────────────────────
const mockToScAddress = jest.fn().mockReturnValue(Buffer.alloc(32));

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
      GetTransactionStatus: {
        SUCCESS: 'SUCCESS',
        FAILED: 'FAILED',
        NOT_FOUND: 'NOT_FOUND',
      },
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
  TransactionBuilder: jest.fn().mockImplementation(() => ({
    addOperation: jest.fn().mockReturnThis(),
    setTimeout: jest.fn().mockReturnThis(),
    build: jest.fn().mockReturnValue({}),
  })),
  Networks: {
    PUBLIC: 'Public Global Stellar Network ; September 2015',
    TESTNET: 'Test SDF Network ; September 2015',
    FUTURENET: 'Test SDF Future Network ; October 2022',
  },
  Address: jest.fn().mockImplementation(() => ({
    toScAddress: mockToScAddress,
  })),
  nativeToScVal: jest.fn().mockReturnValue({}),
  scValToNative: jest.fn(),
  xdr: {
    ScVal: {
      scvAddress: jest.fn().mockReturnValue({}),
      scvVec: jest.fn().mockReturnValue({}),
      scvVoid: jest.fn().mockReturnValue({}),
      scvMap: jest.fn().mockReturnValue({}),
    },
    Operation: {} as any,
  },
  Transaction: class {},
}));

// Import mocks after jest.mock
const stellarSdk = require('stellar-sdk');

jest.mock('../cacheManager', () => ({
  CacheManager: jest.fn().mockImplementation(() => ({
    get: jest.fn().mockReturnValue(null),
    set: jest.fn(),
    invalidate: jest.fn(),
  })),
  DataType: {
    DID_DOCUMENT: 'did_document',
  },
}));

const validTestnetConfig: StellarIdentityConfig = {
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

const VALID_ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const VALID_DID = `did:stellar:${VALID_ADDRESS}`;

// ── Helpers ──────────────────────────────────────────────────────────────────

function mockSimSuccess(retval?: any) {
  stellarSdk.SorobanRpc.Api.isSimulationError.mockReturnValue(false);
}

function mockWriteSuccess(hash = 'abc123', ledger = 1000) {
  return {
    getAccount: jest.fn().mockResolvedValue({
      accountId: () => VALID_ADDRESS,
      sequenceNumber: () => '12345',
      incrementSequenceNumber: () => {},
    }),
    prepareTransaction: jest.fn().mockResolvedValue({ sign: jest.fn() }),
    sendTransaction: jest.fn().mockResolvedValue({ status: 'PENDING', hash }),
    getTransaction: jest.fn().mockResolvedValue({ status: 'SUCCESS', ledger }),
  };
}

describe('DIDClient', () => {
  let client: DIDClient;
  let mockKeypair: any;
  let mockServer: any;

  beforeEach(() => {
    jest.clearAllMocks();
    // Re-init the SorobanRpc.Server mock to return fresh mockServer each time
    mockServer = {
      simulateTransaction: jest.fn().mockResolvedValue({
        result: { retval: {} },
      }),
      getAccount: jest.fn(),
      prepareTransaction: jest.fn(),
      sendTransaction: jest.fn(),
      getTransaction: jest.fn(),
    };
    stellarSdk.SorobanRpc.Server.mockReturnValue(mockServer);

    // Re-apply Address mock factory (clearAllMocks preserves factory)
    stellarSdk.Address.mockImplementation(() => ({
      toScAddress: mockToScAddress,
    }));
    stellarSdk.Address.fromString = jest.fn();

    // Always return null by default for scValToNative
    stellarSdk.scValToNative.mockReturnValue(null);
    stellarSdk.SorobanRpc.Api.isSimulationError.mockReturnValue(false);

    // Re-apply Contract mock (in case clearAllMocks reset the factory's return inline mocks)
    const { Contract } = require('stellar-sdk');
    Contract.mockImplementation(() => ({
      call: jest.fn().mockReturnValue({}),
    }));

    client = new DIDClient(validTestnetConfig);
    mockKeypair = {
      publicKey: jest.fn().mockReturnValue(VALID_ADDRESS),
      sign: jest.fn(),
    };
  });

  describe('constructor', () => {
    it('should throw ConfigurationError when didRegistry is missing', () => {
      expect(() => {
        new DIDClient({
          ...validTestnetConfig,
          contracts: { ...validTestnetConfig.contracts, didRegistry: '' as any },
        });
      }).toThrow();
    });
  });

  describe('generateDID', () => {
    it('should generate a valid did:stellar DID', () => {
      const did = client.generateDID(VALID_ADDRESS);
      expect(did).toBe(VALID_DID);
    });

    it('should generate DID with suffix', () => {
      const did = client.generateDID(VALID_ADDRESS, 'v1');
      expect(did).toBe(`${VALID_DID}:v1`);
    });
  });

  describe('validateDIDFormat', () => {
    it('should return true for valid DID', () => {
      expect(client.validateDIDFormat(VALID_DID)).toBe(true);
    });

    it('should return false for non-stellar DID', () => {
      expect(client.validateDIDFormat('did:eth:0x123')).toBe(false);
    });

    it('should return false for invalid format', () => {
      expect(client.validateDIDFormat('not-a-did')).toBe(false);
    });
  });

  describe('extractStellarAddress', () => {
    it('should extract address from DID', () => {
      const address = client.extractStellarAddress(VALID_DID);
      expect(address).toBe(VALID_ADDRESS);
    });
  });

  describe('createDID', () => {
    it('should create a DID via contract call', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const did = await client.createDID(mockKeypair, {
        verificationMethods: [{
          id: '#key-1', type: 'Ed25519VerificationKey2018',
          controller: VALID_ADDRESS, publicKey: 'deadbeef',
        }],
        services: [{
          id: '#hub', type: 'IdentityHub',
          endpoint: 'https://hub.example.com',
        }],
      });

      expect(did).toBe(VALID_DID);
    });
  });

  describe('resolveDID', () => {
    it('should resolve a DID document', async () => {
      mockSimSuccess();
      stellarSdk.scValToNative.mockReturnValue({
        id: new TextEncoder().encode(VALID_DID),
        controller: new TextEncoder().encode(VALID_ADDRESS),
        verification_method: [],
        authentication: [],
        service: [],
        created: 1700000000n,
        updated: 1700000000n,
      });

      const result = await client.resolveDID(VALID_DID);
      expect(result.didDocument.id).toBe(VALID_DID);
    });

    it('should reject invalid DID format', async () => {
      await expect(client.resolveDID('invalid')).rejects.toThrow();
    });
  });

  describe('resolveDIDBatch', () => {
    it('should resolve multiple DIDs', async () => {
      mockSimSuccess();
      stellarSdk.scValToNative.mockReturnValue({
        id: new TextEncoder().encode(VALID_DID),
        controller: new TextEncoder().encode(VALID_ADDRESS),
        verification_method: [],
        authentication: [],
        service: [],
        created: 1700000000n,
        updated: 1700000000n,
      });

      const results = await client.resolveDIDBatch([VALID_DID, `did:stellar:GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5`]);
      expect(results).toHaveLength(2);
      expect(results[0].error).toBeNull();
      expect(results[0].result?.didDocument.id).toBe(VALID_DID);
    });
  });

  describe('updateDID', () => {
    it('should update DID verification methods and services', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const result = await client.updateDID(
        mockKeypair,
        [{ id: '#key-2', type: 'Ed25519VerificationKey2018', controller: VALID_ADDRESS, publicKey: 'cafebabe' }],
        [{ id: '#svc', type: 'CredentialRepository', endpoint: 'https://cred.example.com' }],
      );

      expect(result.status).toBe('SUCCESS');
    });
  });

  describe('deactivateDID', () => {
    it('should deactivate a DID', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const result = await client.deactivateDID(mockKeypair);
      expect(result.status).toBe('SUCCESS');
    });
  });

  describe('didExists', () => {
    it('should return true when DID exists', async () => {
      mockSimSuccess();
      stellarSdk.scValToNative.mockReturnValue(true);

      const exists = await client.didExists(VALID_DID);
      expect(exists).toBe(true);
    });
  });

  describe('getControllerDID', () => {
    it('should return null when no DID is registered', async () => {
      mockSimSuccess();
      stellarSdk.scValToNative.mockReturnValue(null);

      const did = await client.getControllerDID(VALID_ADDRESS);
      expect(did).toBeNull();
    });

    it('should return DID string when registered', async () => {
      mockSimSuccess();
      stellarSdk.scValToNative.mockReturnValue(new TextEncoder().encode(VALID_DID));

      const did = await client.getControllerDID(VALID_ADDRESS);
      expect(did).toBe(VALID_DID);
    });
  });

  describe('addAuthentication', () => {
    it('should add an authentication method', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const result = await client.addAuthentication(mockKeypair, '#auth-1');
      expect(result.status).toBe('SUCCESS');
    });
  });

  describe('removeAuthentication', () => {
    it('should remove an authentication method', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const result = await client.removeAuthentication(mockKeypair, '#auth-1');
      expect(result.status).toBe('SUCCESS');
    });
  });
});
