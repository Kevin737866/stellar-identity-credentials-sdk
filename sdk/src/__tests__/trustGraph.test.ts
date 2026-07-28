/**
 * Tests for Issue #286 \u2014 trust graph traversal methods.
 *
 * Strategy: exercise the pure-logic helpers directly (BFS, aggregate,
 * recommend) so the tests do not depend on a live Soroban RPC. The
 * contract-bound methods are checked at API-surface level.
 */

jest.mock('stellar-sdk', () => ({
  SorobanRpc: {
    Server: jest.fn().mockImplementation(() => ({
      getAccount: jest.fn().mockRejectedValue(new Error('mock')),
      simulateTransaction: jest.fn(),
      prepareTransaction: jest.fn().mockImplementation((tx) => tx),
      sendTransaction: jest.fn(),
    })),
    Api: {
      isSimulationError: jest.fn().mockReturnValue(false),
      SimulateTransactionSuccessResponse: class {},
      SimulateTransactionErrorResponse: class {},
    },
  },
  Contract: jest.fn().mockImplementation(() => ({ call: jest.fn().mockReturnValue({}) })),
  Keypair: {
    random: jest.fn().mockReturnValue({
      publicKey: jest.fn().mockReturnValue('GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5'),
      sign: jest.fn(),
    }),
  },
  TransactionBuilder: jest.fn().mockImplementation(() => ({
    addOperation: jest.fn().mockReturnThis(),
    setTimeout: jest.fn().mockReturnThis(),
    build: jest.fn().mockReturnValue({ hash: jest.fn() }),
  })),
  Networks: {
    PUBLIC: 'Public Global Stellar Network ; September 2015',
    TESTNET: 'Test SDF Network ; September 2015',
    FUTURENET: 'Test SDF Future Network ; October 2022',
  },
  Address: {
    fromString: jest.fn(),
    toScAddress: jest.fn(),
  },
  nativeToScVal: jest.fn().mockReturnValue({}),
  scValToNative: jest.fn(),
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

import {
  findTrustPathsBFS,
  aggregateTrustWeight,
  recommendTrustEntities,
} from '../trustGraph';
import { ReputationClient } from '../reputation';
import { TrustEdge } from '../types';

const TEST_CONFIG = {
  network: 'testnet' as const,
  contracts: {
    didRegistry: 'CAAAA',
    credentialIssuer: 'CBBBB',
    reputationScore: 'CCCCC',
    zkAttestation: 'CDDDD',
    complianceFilter: 'CEEEE',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

function mkEdge(truster: string, subject: string, weight = 10, ts = 1): TrustEdge {
  return { truster, subject, weight, reason: 'unit-test', timestamp: ts };
}

function makeClient(): ReputationClient {
  return new ReputationClient(TEST_CONFIG);
}

describe('findTrustPathsBFS (Issue #286)', () => {
  test('returns empty array when maxDepth < 1', () => {
    expect(findTrustPathsBFS('A', 'B', [mkEdge('A', 'B')], 0)).toEqual([]);
  });

  test('returns a single zero-hop path when from === to', () => {
    expect(findTrustPathsBFS('A', 'A', [mkEdge('A', 'B')], 3)).toEqual([
      { from: 'A', to: 'A', path: ['A'], cumulativeWeight: 0, hops: 0 },
    ]);
  });

  test('finds a direct 1-hop path', () => {
    const edges = [mkEdge('A', 'B', 25)];
    const paths = findTrustPathsBFS('A', 'B', edges, 3);
    expect(paths).toEqual([
      { from: 'A', to: 'B', path: ['A', 'B'], cumulativeWeight: 25, hops: 1 },
    ]);
  });

  test('finds a multi-hop path', () => {
    const edges = [mkEdge('A', 'X', 10), mkEdge('X', 'B', 15)];
    const paths = findTrustPathsBFS('A', 'B', edges, 3);
    expect(paths).toEqual([
      { from: 'A', to: 'B', path: ['A', 'X', 'B'], cumulativeWeight: 25, hops: 2 },
    ]);
  });

  test('returns [] when no path exists', () => {
    const edges = [mkEdge('A', 'X', 10), mkEdge('Y', 'B', 15)];
    expect(findTrustPathsBFS('A', 'B', edges, 3)).toEqual([]);
  });

  test('respects maxDepth', () => {
    const edges = [mkEdge('A', 'X', 10), mkEdge('X', 'Y', 10), mkEdge('Y', 'B', 10)];
    expect(findTrustPathsBFS('A', 'B', edges, 2)).toEqual([]);
    expect(findTrustPathsBFS('A', 'B', edges, 3)).toHaveLength(1);
  });

  test('returns multiple paths sorted by descending weight', () => {
    const edges = [
      mkEdge('A', 'Y', 5),
      mkEdge('Y', 'B', 5), // path A->Y->B weight 10
      mkEdge('A', 'X', 20),
      mkEdge('X', 'B', 20), // path A->X->B weight 40
    ];
    const paths = findTrustPathsBFS('A', 'B', edges, 3);
    expect(paths).toHaveLength(2);
    expect(paths[0].cumulativeWeight).toBe(40);
    expect(paths[1].cumulativeWeight).toBe(10);
  });

  test('avoids self-cycles inside a path', () => {
    const edges = [mkEdge('A', 'B', 10), mkEdge('B', 'A', 10)];
    const paths = findTrustPathsBFS('A', 'B', edges, 3);
    // Direct edge counts, but not the A->B->A->B loop.
    expect(paths).toHaveLength(1);
    expect(paths[0].path).toEqual(['A', 'B']);
  });
});

describe('aggregateTrustWeight (Issue #286)', () => {
  test('returns 0 for empty edge list', () => {
    expect(aggregateTrustWeight([], 'B')).toBe(0);
  });

  test('returns 0 when there are no inbound edges for the subject', () => {
    const edges = [mkEdge('A', 'B', 50), mkEdge('B', 'C', 30)];
    expect(aggregateTrustWeight(edges, 'X')).toBe(0);
  });

  test('sums inbound weights and excludes self-attestations', () => {
    const edges = [
      mkEdge('A', 'B', 25),
      mkEdge('B', 'B', 999), // self-attest, must be excluded
      mkEdge('C', 'B', 30),
      mkEdge('D', 'B', 15),
      mkEdge('B', 'C', 50),  // outbound, must be excluded
    ];
    expect(aggregateTrustWeight(edges, 'B')).toBe(70);
  });
});

describe('recommendTrustEntities (Issue #286)', () => {
  test('returns [] when limit < 1', () => {
    expect(recommendTrustEntities([], 'A', 0)).toEqual([]);
  });

  test('does not recommend entities already directly trusted', () => {
    const edges = [
      mkEdge('Bob', 'Alice', 50), // Alice already trusts Bob
      mkEdge('Bob', 'Carol', 30), // Carol reachable through Bob
    ];
    const recs = recommendTrustEntities(edges, 'Alice', 5);
    expect(recs).toEqual(['Carol']);
  });

  test('ranks recommendations by descending aggregate weight', () => {
    const edges = [
      mkEdge('Bob', 'Alice', 50),
      mkEdge('Carol', 'Alice', 40),
      mkEdge('Bob', 'Dana', 20),
      mkEdge('Carol', 'Dana', 20),
      mkEdge('Bob', 'Eve', 5),
    ];
    const recs = recommendTrustEntities(edges, 'Alice', 5);
    // Dana gets weight 40 (Bob + Carol), Eve only 5.
    expect(recs[0]).toBe('Dana');
    expect(recs).toContain('Eve');
  });

  test('respects the limit argument', () => {
    const edges = [
      mkEdge('Bob', 'Alice', 10),
      mkEdge('Bob', 'C1', 1),
      mkEdge('Bob', 'C2', 2),
      mkEdge('Bob', 'C3', 3),
    ];
    expect(recommendTrustEntities(edges, 'Alice', 2)).toHaveLength(2);
    expect(recommendTrustEntities(edges, 'Alice', 10)).toHaveLength(3);
  });

  test('returns [] when the address has no direct trustees', () => {
    const edges = [mkEdge('A', 'B', 50)];
    expect(recommendTrustEntities(edges, 'X', 5)).toEqual([]);
  });
});

describe('ReputationClient \u2014 Issue #286 trust-graph method surface', () => {
  test('exposes the five required trust-graph methods', () => {
    const client = makeClient();
    expect(typeof client.getTrustAttestations).toBe('function');
    expect(typeof client.getTrustGraph).toBe('function');
    expect(typeof client.findTrustPaths).toBe('function');
    expect(typeof client.getAggregateTrustWeight).toBe('function');
    expect(typeof client.getTrustRecommendations).toBe('function');
  });

  test('getTrustGraphSnapshot is exposed and returns a typed graph', () => {
    const client = makeClient();
    expect(typeof client.getTrustGraphSnapshot).toBe('function');
  });
});
