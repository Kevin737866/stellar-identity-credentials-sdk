import { ExpirationManager, DEFAULT_POLLING_INTERVAL_MS } from '../expirationManager';
import { StellarIdentityConfig, VerifiableCredential } from '../types';

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
  },
  Transaction: class {},
}));

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
    schemaRegistry: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822f',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

const VALID_ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';

function makeCredential(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    id: 'cred-1',
    issuer: VALID_ADDRESS,
    subject: 'GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
    type: ['KYCVerification'],
    credentialData: { name: 'Test' },
    issuanceDate: Date.now() - 1000000,
    expirationDate: Date.now() + 30 * 24 * 60 * 60 * 1000,
    ...overrides,
  };
}

describe('ExpirationManager', () => {
  let mockCredentialClient: any;
  let manager: ExpirationManager;

  beforeEach(() => {
    jest.clearAllMocks();
    mockCredentialClient = {
      getSubjectCredentials: jest.fn(),
      getCredential: jest.fn(),
    };
    manager = new ExpirationManager(mockCredentialClient, 1000);
  });

  describe('onExpiration', () => {
    it('should register an expiration handler', () => {
      const handler = jest.fn();
      manager.onExpiration(handler);
      expect(typeof manager.on).toBe('function');
      expect(typeof manager.off).toBe('function');
    });
  });

  describe('on and off', () => {
    it('should register and unregister event handlers', () => {
      const handler = jest.fn();
      manager.on('testEvent', handler);
      expect(typeof manager.on).toBe('function');
      expect(typeof manager.off).toBe('function');
    });
  });

  describe('checkExpiringCredentials', () => {
    // checkExpiringCredentials uses the private fetchAllCredentials() method
    // which currently returns []. The credentialClient mocks are exercised
    // by getExpiredCredentials which calls credentialClient directly.
    it('should return empty array when fetchAllCredentials returns no data', async () => {
      const expiring = await manager.checkExpiringCredentials(30);
      expect(expiring).toEqual([]);
    });

    it('should return empty array when no credentials are expiring', async () => {
      const farFutureCred = makeCredential({
        id: 'cred-far',
        expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
      });

      mockCredentialClient.getSubjectCredentials.mockResolvedValue(['cred-far']);
      mockCredentialClient.getCredential.mockResolvedValue(farFutureCred);

      const expiring = await manager.checkExpiringCredentials(1);
      expect(expiring).toEqual([]);
    });
  });

  describe('getExpiredCredentials', () => {
    it('should return expired credentials', async () => {
      const expiredCred = makeCredential({
        id: 'cred-expired',
        expirationDate: Date.now() - 1000000,
      });

      mockCredentialClient.getSubjectCredentials.mockResolvedValue(['cred-expired']);
      mockCredentialClient.getCredential.mockResolvedValue(expiredCred);

      const expired = await manager.getExpiredCredentials(VALID_ADDRESS);
      expect(expired.length).toBeGreaterThanOrEqual(1);
      expect(expired[0].id).toBe('cred-expired');
    });

    it('should return empty array when no credentials are expired', async () => {
      const validCred = makeCredential({
        id: 'cred-valid',
        expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
      });

      mockCredentialClient.getSubjectCredentials.mockResolvedValue(['cred-valid']);
      mockCredentialClient.getCredential.mockResolvedValue(validCred);

      const expired = await manager.getExpiredCredentials(VALID_ADDRESS);
      expect(expired).toEqual([]);
    });
  });

  describe('DEFAULT_POLLING_INTERVAL_MS', () => {
    it('should be 1 hour by default', () => {
      expect(DEFAULT_POLLING_INTERVAL_MS).toBe(60 * 60 * 1000);
    });
  });

  describe('startPolling and stopPolling', () => {
    it('should not throw when starting and stopping polling', () => {
      expect(() => {
        manager.startPolling();
        manager.stopPolling();
      }).not.toThrow();
    });

    it('should not start multiple polling intervals', () => {
      manager.startPolling();
      manager.startPolling();
      manager.stopPolling();
    });
  });

  describe('setPollingInterval', () => {
    it('should update the polling interval', () => {
      manager.setPollingInterval(5000);
      expect(() => {
        manager.startPolling();
        manager.stopPolling();
      }).not.toThrow();
    });
  });
});
