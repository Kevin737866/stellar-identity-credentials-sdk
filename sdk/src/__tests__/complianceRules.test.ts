/**
 * Tests for Issue #285 — compliance rule management methods.
 *
 * Strategy: focus on the testable pure-logic pieces
 *   - ancestorJurisdictions
 *   - evaluateRuleAgainstScreen
 *   - input validation on registerRule / updateRule
 * plus surface-level assertions that the CRUD methods exist on the client.
 * Network-bound contract calls are not exercised here; those paths will be
 * covered by integration tests once the on-chain spec is finalised.
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
      publicKey: jest.fn().mockReturnValue('GABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
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
  ComplianceClient,
  ancestorJurisdictions,
  evaluateRuleAgainstScreen,
} from '../compliance';
import { ComplianceError, ErrorCode } from '../errors';
import { Keypair } from 'stellar-sdk';
import { ComplianceRule, ComplianceResult } from '../types';

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

function makeClient(): ComplianceClient {
  return new ComplianceClient(TEST_CONFIG);
}

function makeRule(overrides: Partial<ComplianceRule> = {}): ComplianceRule {
  return {
    jurisdiction: 'US',
    requirement: 'KYC_REQUIRED',
    enforcement: 'mandatory',
    active: true,
    ...overrides,
  };
}

function makeScreening(overrides: Partial<ComplianceResult> = {}): ComplianceResult {
  return {
    address: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    status: 'cleared',
    riskScore: 10,
    sanctionsLists: [],
    lastChecked: Date.now(),
    recommendations: [],
    ...overrides,
  };
}

describe('ancestorJurisdictions (Issue #285 inheritance resolution)', () => {
  test('returns just GLOBAL for empty input', () => {
    expect(ancestorJurisdictions('')).toEqual(['GLOBAL']);
  });

  test('returns just GLOBAL when explicitly given', () => {
    expect(ancestorJurisdictions('GLOBAL')).toEqual(['GLOBAL']);
  });

  test('walks a single-segment path', () => {
    expect(ancestorJurisdictions('US')).toEqual(['GLOBAL', 'US']);
  });

  test('walks a four-segment path', () => {
    expect(ancestorJurisdictions('US-CA-SF')).toEqual([
      'GLOBAL',
      'US',
      'US-CA',
      'US-CA-SF',
    ]);
  });

  test('strips leading and trailing - separators', () => {
    expect(ancestorJurisdictions('-US-CA-')).toEqual([
      'GLOBAL',
      'US',
      'US-CA',
    ]);
  });
});

describe('evaluateRuleAgainstScreen (Issue #285 rule evaluation)', () => {
  test('cleared address with low risk satisfies any mandatory rule', () => {
    const rule = makeRule();
    const screen = makeScreening({ status: 'cleared', riskScore: 10 });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(false);
  });

  test('flagged address violates every mandatory rule', () => {
    const rule = makeRule();
    const screen = makeScreening({ status: 'flagged', riskScore: 75 });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(true);
  });

  test('blocked address violates every mandatory rule', () => {
    const rule = makeRule();
    const screen = makeScreening({ status: 'blocked', riskScore: 100 });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(true);
  });

  test('inactive rules are never reported as violations', () => {
    const rule = makeRule({ active: false });
    const screen = makeScreening({ status: 'blocked' });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(false);
  });

  test('advisory rules are never reported as hard violations', () => {
    const rule = makeRule({ enforcement: 'advisory' });
    const screen = makeScreening({ status: 'blocked' });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(false);
  });

  test('missing screening against a non-empty requirement is a violation', () => {
    const rule = makeRule({ requirement: 'KYC_REQUIRED' });
    expect(evaluateRuleAgainstScreen(rule, undefined)).toBe(true);
  });

  test('cleared address with elevated risk still satisfies rules', () => {
    const rule = makeRule();
    const screen = makeScreening({ status: 'cleared', riskScore: 60 });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(false);
  });

  test('unknown screen status but risk > 70 is a violation', () => {
    const rule = makeRule();
    const screen = makeScreening({ status: 'cleared', riskScore: 85 });
    expect(evaluateRuleAgainstScreen(rule, screen)).toBe(true);
  });
});

describe('ComplianceClient — Issue #285 CRUD surface', () => {
  test('exposes the five required CRUD methods', () => {
    const client = makeClient();
    expect(typeof client.registerRule).toBe('function');
    expect(typeof client.updateRule).toBe('function');
    expect(typeof client.deactivateRule).toBe('function');
    expect(typeof client.getRule).toBe('function');
    expect(typeof client.getEffectiveRules).toBe('function');
    expect(typeof client.evaluateRules).toBe('function');
  });

  test('registerRule rejects empty jurisdiction', async () => {
    const client = makeClient();
    await expect(
      client.registerRule(Keypair.random(), '', 'KYC_REQUIRED', 'mandatory'),
    ).rejects.toBeInstanceOf(ComplianceError);
  });

  test('registerRule rejects whitespace-only jurisdiction', async () => {
    const client = makeClient();
    await expect(
      client.registerRule(Keypair.random(), '   ', 'KYC_REQUIRED', 'mandatory'),
    ).rejects.toBeInstanceOf(ComplianceError);
  });

  test('registerRule rejects empty requirement', async () => {
    const client = makeClient();
    await expect(
      client.registerRule(Keypair.random(), 'US', '', 'mandatory'),
    ).rejects.toBeInstanceOf(ComplianceError);
  });

  test('updateRule rejects empty jurisdiction', async () => {
    const client = makeClient();
    await expect(
      client.updateRule(Keypair.random(), '', 'KYC_REQUIRED', 'mandatory', true),
    ).rejects.toBeInstanceOf(ComplianceError);
  });

  test('evaluateRules rejects empty address', async () => {
    const client = makeClient();
    await expect(client.evaluateRules('', 'US')).rejects.toBeInstanceOf(ComplianceError);
  });
});

describe('ComplianceRule error mapping (Issue #285 error handling)', () => {
  test('invalid input raises ComplianceError with ComplianceInvalidHash code', async () => {
    const client = makeClient();
    try {
      await client.registerRule(Keypair.random(), '', 'KYC_REQUIRED', 'mandatory');
      fail('expected registerRule to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ComplianceError);
      expect((err as ComplianceError).code).toBe(ErrorCode.ComplianceInvalidHash);
    }
  });
});
