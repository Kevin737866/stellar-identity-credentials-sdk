import { ReputationClient } from '../reputation';
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
    build: jest.fn().mockReturnValue({
      hash: () => ({ toString: () => 'abchash' }),
    }),
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
    ScMapEntry: jest.fn().mockImplementation((entry: any) => entry),
  },
  Transaction: class {},
}));

const stellarSdk = require('stellar-sdk');

jest.mock('crypto-js', () => ({
  SHA256: jest.fn().mockReturnValue({ toString: () => 'mockcommitmenthash' }),
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

const mockReputationData: Record<string, unknown> = {
  did: VALID_ADDRESS,
  score: 7500n,
  transaction_count: 100n,
  successful_transactions: 95n,
  credential_count: 5n,
  valid_credentials: 5n,
  last_updated: 1700000000n,
  created_at: 1690000000n,
  reputation_factors: {
    transaction_volume: 80n,
    transaction_consistency: 90n,
    credential_count: 70n,
    credential_diversity: 75n,
    account_age: 60n,
    dispute_history: 95n,
  },
  transaction_volume_sum: 100000n,
  counterparty_diversity: 20n,
  fee_consistency: 85n,
  contract_interactions: 50n,
  verified_kyc: 2n,
  employment_credentials: 1n,
  academic_credentials: 1n,
  self_claimed_credentials: 0n,
  sanctions_matches: 0n,
  credential_revocations: 0n,
  disputes: 0n,
};

function mockWriteFlow(mockServer: any) {
  mockServer.getAccount.mockResolvedValue({
    accountId: () => VALID_ADDRESS,
    sequenceNumber: () => '12345',
    incrementSequenceNumber: () => {},
  });
  mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
  mockServer.sendTransaction.mockResolvedValue({ status: 'PENDING', hash: 'abc' });
  // getTransaction returns SUCCESS with resultMetaXdr so invokeWrite returns simulated retval
  mockServer.getTransaction.mockResolvedValue({
    status: 'SUCCESS',
    ledger: 1000,
    resultMetaXdr: {},
  });
}

describe('ReputationClient', () => {
  let client: ReputationClient;
  let mockKeypair: any;
  let mockServer: any;

  beforeEach(() => {
    jest.clearAllMocks();
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
    stellarSdk.Address.mockImplementation(() => ({
      toScAddress: mockToScAddress,
    }));
    stellarSdk.Address.fromString = jest.fn();
    stellarSdk.scValToNative.mockReturnValue(null);
    stellarSdk.SorobanRpc.Api.isSimulationError.mockReturnValue(false);

    // Re-apply Contract mock factory
    const { Contract } = require('stellar-sdk');
    Contract.mockImplementation(() => ({
      call: jest.fn().mockReturnValue({}),
    }));

    client = new ReputationClient(validTestnetConfig);
    mockKeypair = {
      publicKey: jest.fn().mockReturnValue(VALID_ADDRESS),
      sign: jest.fn(),
    };
  });

  describe('initializeReputation', () => {
    it('should initialize reputation for a new address', async () => {
      mockWriteFlow(mockServer);
      stellarSdk.scValToNative.mockReturnValue(mockReputationData);

      const result = await client.initializeReputation(mockKeypair);
      expect(result.did).toBe(VALID_ADDRESS);
      expect(result.score).toBe(750.0);
    });
  });

  describe('updateTransactionReputation', () => {
    it('should update reputation after a successful transaction', async () => {
      mockWriteFlow(mockServer);
      stellarSdk.scValToNative.mockReturnValue(7600n);

      const score = await client.updateTransactionReputation(mockKeypair, VALID_ADDRESS, true, 5000);
      expect(typeof score).toBe('number');
    });
  });

  describe('updateCredentialReputation', () => {
    it('should update reputation after credential validation', async () => {
      mockWriteFlow(mockServer);
      stellarSdk.scValToNative.mockReturnValue(7700n);

      const score = await client.updateCredentialReputation(mockKeypair, VALID_ADDRESS, true, 'KYCVerification');
      expect(typeof score).toBe('number');
    });
  });

  describe('calculateReputation', () => {
    it('should calculate reputation score', async () => {
      stellarSdk.scValToNative.mockReturnValue(8000n);

      const score = await client.calculateReputation(VALID_ADDRESS);
      expect(score).toBe(800.0);
    });
  });

  describe('getReputationScore', () => {
    it('should return a reputation breakdown with score and tier', async () => {
      // getReputationData + getReputationPercentile
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return mockReputationData;
        return 85;
      });

      const breakdown = await client.getReputationScore(VALID_ADDRESS);
      expect(breakdown.score).toBe(750.0);
      expect(breakdown.percentile).toBe(85);
      expect(breakdown.tier).toBe('Strong');
    });
  });

  describe('getReputationScoreValue', () => {
    it('should return numeric score only', async () => {
      stellarSdk.scValToNative.mockReturnValue(7500n);

      const score = await client.getReputationScoreValue(VALID_ADDRESS);
      expect(score).toBe(750.0);
    });
  });

  describe('getReputationData', () => {
    it('should return raw reputation data', async () => {
      stellarSdk.scValToNative.mockReturnValue(mockReputationData);

      const data = await client.getReputationData(VALID_ADDRESS);
      expect(data.did).toBe(VALID_ADDRESS);
      expect(data.transactionCount).toBe(100);
      expect(data.credentialCount).toBe(5);
    });
  });

  describe('getReputationHistory', () => {
    it('should return reputation history points', async () => {
      const now = Math.floor(Date.now() / 1000);
      stellarSdk.scValToNative.mockReturnValue([
        { timestamp: BigInt(now - 10000), score: 7000n, event_type: 'transaction' },
        { timestamp: BigInt(now - 5000), score: 7300n, event_type: 'credential' },
      ]);

      const history = await client.getReputationHistory(VALID_ADDRESS, '180d');
      expect(history).toHaveLength(2);
      expect(history[0].score).toBe(700.0);
    });
  });

  describe('attestTrust', () => {
    it('should attest trust for another DID', async () => {
      mockWriteFlow(mockServer);
      stellarSdk.scValToNative.mockReturnValue({
        truster: VALID_ADDRESS,
        subject: 'GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
        weight: 800n,
        reason: new TextEncoder().encode('Trusted partner'),
        timestamp: 1700000000n,
      });

      const edge = await client.attestTrust(mockKeypair, 'GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5', 800, 'Trusted partner');
      expect(edge.truster).toBe(VALID_ADDRESS);
      expect(edge.weight).toBe(800);
    });
  });

  describe('getTrustGraph', () => {
    it('should return trust edges for a DID', async () => {
      stellarSdk.scValToNative.mockReturnValue([{
        truster: 'GA...', subject: 'GB...', weight: 500n,
        reason: new TextEncoder().encode('Good standing'), timestamp: 1700000000n,
      }]);

      const edges = await client.getTrustGraph(VALID_ADDRESS, 2);
      expect(edges).toHaveLength(1);
    });
  });

  describe('compareReputation', () => {
    it('should compare two reputation profiles', async () => {
      // 4 calls: data A, percentile A, data B, percentile B
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return mockReputationData;
        if (callIndex === 2) return 85;
        if (callIndex === 3) return { ...mockReputationData, score: 5000n };
        return 50;
      });

      const comparison = await client.compareReputation(VALID_ADDRESS, 'GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5');
      expect(comparison.winner).toBe('didA');
      expect(comparison.didA.score).toBe(750.0);
      expect(comparison.didB.score).toBe(500.0);
    });
  });

  describe('getReputationAnalysis', () => {
    it('should return comprehensive ReputationScoreResult', async () => {
      const now = Math.floor(Date.now() / 1000);
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return mockReputationData;
        if (callIndex === 2) return 85;
        // getReputationHistory
        return [{ timestamp: BigInt(now - 5000), score: 7000n, event_type: 'transaction' }];
      });

      const analysis = await client.getReputationAnalysis(VALID_ADDRESS);
      expect(analysis.score).toBe(750.0);
      expect(analysis.percentile).toBe(85);
      expect(analysis.history).toHaveLength(1);
    });
  });

  describe('getReputationTier', () => {
    it('should return Prime tier for score >= 900', () => {
      expect(client.getReputationTier(920).tier).toBe('Prime');
    });

    it('should return Strong tier for score >= 750', () => {
      expect(client.getReputationTier(800).tier).toBe('Strong');
    });

    it('should return Established tier for score >= 550', () => {
      expect(client.getReputationTier(600).tier).toBe('Established');
    });

    it('should return Emerging tier for score >= 300', () => {
      expect(client.getReputationTier(400).tier).toBe('Emerging');
    });

    it('should return Seedling tier for score < 300', () => {
      expect(client.getReputationTier(150).tier).toBe('Seedling');
    });
  });

  describe('meetsReputationThreshold', () => {
    it('should check if DID meets a threshold', async () => {
      stellarSdk.scValToNative.mockReturnValue(true);

      const meets = await client.meetsReputationThreshold(VALID_ADDRESS, 500);
      expect(meets).toBe(true);
    });
  });

  describe('getReputationFactors', () => {
    it('should return reputation factor values', async () => {
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return mockReputationData;
        return 85;
      });

      const factors = await client.getReputationFactors(VALID_ADDRESS);
      expect(factors.transactionVolume).toBe(80);
      expect(factors.transactionConsistency).toBe(90);
    });
  });

  describe('getReputationTierProof', () => {
    it('should generate a tier proof with commitment', async () => {
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return mockReputationData;
        return 85;
      });

      const proof = await client.getReputationTierProof(VALID_ADDRESS);
      expect(proof.tier).toBe('Strong');
      expect(proof.commitment).toBe('mockcommitmenthash');
    });
  });

  describe('calculateReputationTrend', () => {
    it('should detect upward trend', () => {
      const trend = client.calculateReputationTrend([500, 520, 540, 560, 580, 600, 620, 640, 660, 700, 780]);
      expect(trend.trend).toBe('up');
    });

    it('should detect downward trend', () => {
      const trend = client.calculateReputationTrend([800, 780, 760, 740, 720, 700, 680, 660, 640, 620, 580]);
      expect(trend.trend).toBe('down');
    });

    it('should detect stable trend', () => {
      const trend = client.calculateReputationTrend([500, 502, 501, 500, 503, 501, 502, 500, 501, 500, 502]);
      expect(trend.trend).toBe('stable');
    });

    it('should handle short history', () => {
      const trend = client.calculateReputationTrend([]);
      expect(trend.trend).toBe('stable');
    });
  });

  describe('resetReputation', () => {
    it('should reset reputation data', async () => {
      mockWriteFlow(mockServer);
      stellarSdk.scValToNative.mockReturnValue({ ...mockReputationData, score: 0n });

      const result = await client.resetReputation(mockKeypair);
      expect(result.score).toBe(0);
    });
  });
});
