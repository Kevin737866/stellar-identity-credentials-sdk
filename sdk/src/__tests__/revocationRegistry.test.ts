import { RevocationRegistryClient } from '../revocationRegistry';
import { StellarIdentityConfig } from '../types';

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

const stellarSdk = require('stellar-sdk');

jest.mock('../cacheManager', () => ({
  CacheManager: jest.fn().mockImplementation(() => ({
    get: jest.fn().mockReturnValue(null),
    set: jest.fn(),
    invalidate: jest.fn(),
  })),
  DataType: {
    CREDENTIAL_STATUS: 'credential_status',
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

function mockWriteSuccess(hash = 'abc123') {
  return {
    getAccount: jest.fn().mockResolvedValue({
      accountId: () => VALID_ADDRESS,
      sequenceNumber: () => '12345',
      incrementSequenceNumber: () => {},
    }),
    prepareTransaction: jest.fn().mockResolvedValue({ sign: jest.fn() }),
    sendTransaction: jest.fn().mockResolvedValue({ status: 'SUCCESS', hash }),
  };
}

describe('RevocationRegistryClient', () => {
  let client: RevocationRegistryClient;
  let mockKeypair: any;
  let mockServer: any;

  beforeEach(() => {
    jest.clearAllMocks();
    mockServer = {
      simulateTransaction: jest.fn().mockResolvedValue({ result: { retval: {} } }),
      getAccount: jest.fn(),
      prepareTransaction: jest.fn(),
      sendTransaction: jest.fn(),
      getTransaction: jest.fn(),
    };
    stellarSdk.SorobanRpc.Server.mockReturnValue(mockServer);
    stellarSdk.Address.mockImplementation(() => ({ toScAddress: mockToScAddress }));
    stellarSdk.Address.fromString = jest.fn();
    stellarSdk.scValToNative.mockReturnValue(null);
    stellarSdk.SorobanRpc.Api.isSimulationError.mockReturnValue(false);

    const { Contract, Keypair } = require('stellar-sdk');
    Contract.mockImplementation(() => ({ call: jest.fn().mockReturnValue({}) }));
    Keypair.random.mockReturnValue({
      publicKey: jest.fn().mockReturnValue(VALID_ADDRESS),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    });

    client = new RevocationRegistryClient(validTestnetConfig);
    mockKeypair = {
      publicKey: jest.fn().mockReturnValue(VALID_ADDRESS),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    };
  });

  describe('createRevocationRegistry', () => {
    it('should create a revocation registry and return registry ID', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const registryId = await client.createRevocationRegistry(mockKeypair, 'KYC Registry');

      expect(registryId).toMatch(/^registry-/);
    });

    it('should create a revocation registry with metadata', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const registryId = await client.createRevocationRegistry(
        mockKeypair,
        'Compliance Registry',
        { department: 'compliance', version: '2.0' },
      );

      expect(registryId).toMatch(/^registry-/);
    });
  });

  describe('revokeWithRegistry', () => {
    it('should revoke a credential with registry proof', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      await expect(
        client.revokeWithRegistry(mockKeypair, 'cred-123', 'registry-1', 'Key compromised'),
      ).resolves.toBeUndefined();
    });

    it('should revoke without reason', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      await expect(
        client.revokeWithRegistry(mockKeypair, 'cred-456', 'registry-1'),
      ).resolves.toBeUndefined();
    });
  });

  describe('batchRevoke', () => {
    it('should revoke multiple credentials', async () => {
      Object.assign(mockServer, mockWriteSuccess());

      const result = await client.batchRevoke(
        mockKeypair,
        ['cred-1', 'cred-2', 'cred-3'],
        'registry-1',
        'Policy violation',
      );

      expect(result.revokedCount).toBe(3);
      expect(result.failedCount).toBe(0);
      expect(result.registryId).toBe('registry-1');
    });

    it('should capture failed revocations', async () => {
      const failingServer = {
        ...mockWriteSuccess(),
        sendTransaction: jest.fn().mockRejectedValue(new Error('Network error')),
      };
      Object.assign(mockServer, failingServer);

      const result = await client.batchRevoke(
        mockKeypair,
        ['cred-1', 'cred-2'],
        'registry-1',
      );

      expect(result.revokedCount).toBe(0);
      expect(result.failedCount).toBe(2);
    });
  });

  describe('getRevocationRegistry', () => {
    it('should retrieve a revocation registry', async () => {
      stellarSdk.scValToNative.mockReturnValue({
        id: new TextEncoder().encode('registry-1'),
        issuer: new TextEncoder().encode(VALID_ADDRESS),
        name: new TextEncoder().encode('KYC Registry'),
        credential_count: 50,
        revoked_count: 3,
        active: true,
        created: 1700000000n,
        updated: 1700000000n,
      });

      const registry = await client.getRevocationRegistry('registry-1');
      expect(registry.id).toBe('registry-1');
      expect(registry.name).toBe('KYC Registry');
      expect(registry.credentialCount).toBe(50);
      expect(registry.revokedCount).toBe(3);
    });
  });

  describe('verifyRevocationProof', () => {
    it('should verify a revocation proof', async () => {
      stellarSdk.scValToNative.mockReturnValue(true);

      const result = await client.verifyRevocationProof('cred-123', {
        registryId: 'registry-1',
        credentialId: 'cred-123',
        revokedAt: Date.now(),
        signature: 'abcdef',
        issuer: VALID_ADDRESS,
      });

      expect(result).toBe(true);
    });

    it('should return false for invalid proof', async () => {
      stellarSdk.scValToNative.mockReturnValue(false);

      const result = await client.verifyRevocationProof('cred-456', {
        registryId: 'registry-1',
        credentialId: 'cred-456',
        revokedAt: Date.now(),
        signature: 'invalid',
        issuer: VALID_ADDRESS,
      });

      expect(result).toBe(false);
    });
  });

  describe('checkRevocationStatus', () => {
    it('should return revoked status', async () => {
      stellarSdk.scValToNative.mockReturnValue({
        revoked: true,
        registry_id: new TextEncoder().encode('registry-1'),
        revoked_at: 1700000000000n,
        reason: new TextEncoder().encode('Key compromised'),
      });

      const status = await client.checkRevocationStatus('cred-123');
      expect(status.revoked).toBe(true);
      expect(status.registryId).toBe('registry-1');
      expect(status.reason).toBe('Key compromised');
    });

    it('should return non-revoked status', async () => {
      stellarSdk.scValToNative.mockReturnValue({
        revoked: false,
      });

      const status = await client.checkRevocationStatus('cred-456');
      expect(status.revoked).toBe(false);
      expect(status.registryId).toBeUndefined();
    });
  });
});
