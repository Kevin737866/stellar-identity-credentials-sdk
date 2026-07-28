import { PredicateType, PredicateInfo } from '../types';
import { ZKProofsClient } from '../zkProofs';
import { StellarIdentityConfig } from '../types';

jest.mock('stellar-sdk', () => ({
  SorobanRpc: {
    Server: jest.fn().mockImplementation(() => ({
      simulateTransaction: jest.fn().mockResolvedValue({
        result: { retval: {} },
      }),
      getAccount: jest.fn().mockResolvedValue({ sequenceNumber: jest.fn().mockReturnValue('0') }),
      prepareTransaction: jest.fn().mockImplementation((tx) => Promise.resolve(tx)),
      sendTransaction: jest.fn().mockResolvedValue({ hash: 'txhash', status: 'SUCCESS' }),
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
      hash: () => ({ toString: () => 'txhash' }),
    }),
  })),
  Networks: {
    PUBLIC: 'Public Global Stellar Network ; September 2015',
    TESTNET: 'Test SDF Network ; September 2015',
    FUTURENET: 'Test SDF Future Network ; October 2022',
  },
  nativeToScVal: jest.fn().mockReturnValue({}),
  scValToNative: jest.fn().mockReturnValue(true),
  xdr: {
    ScVal: {
      scvVoid: jest.fn().mockReturnValue({}),
    },
  },
}));

jest.mock('snarkjs', () => ({
  groth16: {
    fullProve: jest.fn().mockResolvedValue({
      proof: { pi_a: [], pi_b: [], pi_c: [] },
      publicSignals: ['1', '18'],
    }),
  },
}));

jest.mock('fs', () => ({
  readFileSync: jest.fn().mockReturnValue(Buffer.from('mock_data')),
}));

describe('SelectiveDisclosure', () => {
  const mockConfig: StellarIdentityConfig = {
    network: 'testnet',
    contracts: {
      didRegistry: 'CDIDREGISTRY',
      credentialIssuer: 'CCREDISSUER',
      reputationScore: 'CREPUTATION',
      zkAttestation: 'CZKATTESTATION',
      complianceFilter: 'CCOMPLIANCE',
    },
    rpcUrl: 'https://soroban-testnet.stellar.org',
    keypair: {
      publicKey: () => 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
      sign: jest.fn(),
    } as any,
  };

  let client: ZKProofsClient;
  const mockKeypair = {
    publicKey: () => 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
    sign: jest.fn(),
  } as any;

  beforeEach(() => {
    client = new ZKProofsClient(mockConfig);
  });

  describe('PredicateType enum', () => {
    it('has all predicate types defined', () => {
      expect(PredicateType.GreaterThan).toBe('GreaterThan');
      expect(PredicateType.LessThan).toBe('LessThan');
      expect(PredicateType.GreaterThanOrEqual).toBe('GreaterThanOrEqual');
      expect(PredicateType.LessThanOrEqual).toBe('LessThanOrEqual');
      expect(PredicateType.Equality).toBe('Equality');
      expect(PredicateType.Range).toBe('Range');
      expect(PredicateType.InSet).toBe('InSet');
      expect(PredicateType.NotInSet).toBe('NotInSet');
    });
  });

  describe('createSelectiveDisclosureProof', () => {
    it('submits a selective disclosure proof for range predicate', async () => {
      const proofId = await client.createRangeProof(
        mockKeypair,
        'age',
        25,
        18,
        65,
        'cred_123',
        'selective_disclosure',
      );
      expect(proofId).toBeDefined();
      expect(proofId).toContain('sd-proof');
    });

    it('submits a selective disclosure proof for greater-than predicate', async () => {
      const proofId = await client.createGreaterThanProof(
        mockKeypair,
        'income',
        75000,
        50000,
        'cred_456',
        'selective_disclosure',
      );
      expect(proofId).toBeDefined();
      expect(proofId).toContain('sd-proof');
    });

    it('submits an equality disclosure proof', async () => {
      const proofId = await client.createEqualityDisclosure(
        mockKeypair,
        'nationality',
        1,
        'cred_789',
        'selective_disclosure',
      );
      expect(proofId).toBeDefined();
      expect(proofId).toContain('sd-proof');
    });
  });

  describe('verifySelectiveDisclosure', () => {
    it('verifies a disclosure against expected predicates', async () => {
      const mockScValToNative = require('stellar-sdk').scValToNative;
      mockScValToNative.mockReturnValue(true);

      const expectedPredicates: PredicateInfo[] = [{
        attributeName: 'age',
        predicateType: PredicateType.Range,
        rangeMin: '18',
        rangeMax: '65',
      }];

      const result = await client.verifySelectiveDisclosure('proof_123', expectedPredicates);
      expect(result).toBeDefined();
    });
  });

  describe('combineSelectiveDisclosures', () => {
    it('combines multiple disclosure proofs', async () => {
      const proofIds = ['proof_1', 'proof_2'];
      const combinedId = await client.combineSelectiveDisclosures(
        mockKeypair,
        proofIds,
        { purpose: 'loan_application' },
      );
      expect(combinedId).toBeDefined();
      expect(combinedId).toContain('combined');
    });
  });

  describe('encodePredicates', () => {
    it('encodes predicate info correctly', () => {
      const predicates: PredicateInfo[] = [{
        attributeName: 'age',
        predicateType: PredicateType.Range,
        rangeMin: '18',
        rangeMax: '65',
      }];
      const encoded = (client as any).encodePredicates(predicates);
      expect(encoded).toHaveLength(1);
      expect(encoded[0].predicateType).toBe(5);
    });

    it('encodes greater-than predicate type as 0', () => {
      const predicates: PredicateInfo[] = [{
        attributeName: 'income',
        predicateType: PredicateType.GreaterThan,
        threshold: '50000',
      }];
      const encoded = (client as any).encodePredicates(predicates);
      expect(encoded[0].predicateType).toBe(0);
    });
  });

  describe('predicate info structure', () => {
    it('supports threshold-based predicates', () => {
      const predicate: PredicateInfo = {
        attributeName: 'score',
        predicateType: PredicateType.GreaterThanOrEqual,
        threshold: '650',
      };
      expect(predicate.attributeName).toBe('score');
      expect(predicate.predicateType).toBe(PredicateType.GreaterThanOrEqual);
      expect(predicate.threshold).toBe('650');
    });

    it('supports range predicates', () => {
      const predicate: PredicateInfo = {
        attributeName: 'credit_score',
        predicateType: PredicateType.Range,
        rangeMin: '300',
        rangeMax: '850',
      };
      expect(predicate.rangeMin).toBe('300');
      expect(predicate.rangeMax).toBe('850');
    });

    it('supports in-set predicates', () => {
      const predicate: PredicateInfo = {
        attributeName: 'country',
        predicateType: PredicateType.InSet,
        allowedValues: ['US', 'UK', 'CA', 'AU'],
      };
      expect(predicate.allowedValues).toHaveLength(4);
      expect(predicate.allowedValues).toContain('US');
    });
  });
});
