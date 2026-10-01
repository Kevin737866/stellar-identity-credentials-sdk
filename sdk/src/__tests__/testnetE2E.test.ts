import { Keypair } from 'stellar-sdk';
import { StellarIdentitySDK } from '../index';
import { StellarIdentityConfig } from '../types';

jest.mock('stellar-sdk', () => {
  const original = jest.requireActual('stellar-sdk');
  const mockToScAddress = jest.fn().mockReturnValue(Buffer.alloc(32));
  return {
    ...original,
    SorobanRpc: {
      Server: jest.fn().mockImplementation(() => ({
        simulateTransaction: jest.fn().mockResolvedValue({ result: { retval: {} } }),
        getAccount: jest.fn().mockResolvedValue({ sequenceNumber: () => '100' }),
        prepareTransaction: jest.fn().mockResolvedValue({ sign: jest.fn() }),
        sendTransaction: jest.fn().mockResolvedValue({ hash: 'txhash_test', status: 'SUCCESS' }),
        getTransaction: jest.fn().mockResolvedValue({ status: 'SUCCESS', ledger: 12345 }),
      })),
      Api: {
        isSimulationError: jest.fn().mockReturnValue(false),
        GetTransactionStatus: { SUCCESS: 'SUCCESS', FAILED: 'FAILED', NOT_FOUND: 'NOT_FOUND' },
        SimulateTransactionSuccessResponse: class {},
        SimulateTransactionErrorResponse: class {},
      },
    },
    Contract: jest.fn().mockImplementation(() => ({ call: jest.fn().mockReturnValue({}) })),
    TransactionBuilder: jest.fn().mockImplementation(() => ({
      addOperation: jest.fn().mockReturnThis(),
      setTimeout: jest.fn().mockReturnThis(),
      build: jest.fn().mockReturnValue({}),
    })),
    Address: Object.assign(jest.fn().mockImplementation(() => ({ toScAddress: mockToScAddress })), {
      fromString: jest.fn(),
    }),
    nativeToScVal: jest.fn().mockReturnValue({}),
    scValToNative: jest.fn().mockReturnValue(true),
  };
});

describe('SDK client integration with an isolated Soroban RPC', () => {
  const config: StellarIdentityConfig = {
    network: 'testnet',
    contracts: {
      didRegistry: '1111111111111111111111111111111111111111111111111111111111111111',
      credentialIssuer: '2222222222222222222222222222222222222222222222222222222222222222',
      reputationScore: '3333333333333333333333333333333333333333333333333333333333333333',
      zkAttestation: '4444444444444444444444444444444444444444444444444444444444444444',
      complianceFilter: '5555555555555555555555555555555555555555555555555555555555555555',
      schemaRegistry: '6666666666666666666666666666666666666666666666666666666666666666',
    },
    rpcUrl: 'https://soroban-testnet.stellar.org',
  };

  it('constructs all configured registry clients', () => {
    const sdk = new StellarIdentitySDK(config);
    expect(sdk.did).toBeDefined();
    expect(sdk.credentials).toBeDefined();
    expect(sdk.reputation).toBeDefined();
    expect(sdk.schemaRegistry).toBeDefined();
  });

  it('creates a DID through the mocked transaction transport', async () => {
    const sdk = new StellarIdentitySDK(config);
    const keypair = Keypair.random();
    const did = await sdk.did.createDID(keypair, {
      verificationMethods: [{
        id: '#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: keypair.publicKey(),
        publicKey: 'a'.repeat(64),
      }],
      services: [],
    });
    expect(did).toBe(`did:stellar:${keypair.publicKey()}`);
  });

  it('issues a credential and accepts its transaction identifier', async () => {
    const sdk = new StellarIdentitySDK(config);
    const credentialId = await sdk.credentials.issueCredential(Keypair.random(), {
      subject: Keypair.random().publicKey(),
      credentialType: ['VerifiableCredential', 'KYCCredential'],
      credentialData: { kycLevel: 'Tier2' },
      proof: 'test-proof',
    });
    expect(credentialId).toEqual(expect.any(String));
    expect(credentialId.length).toBeGreaterThan(0);
  });

  it('keeps the established reputation score and tier APIs callable', () => {
    const sdk = new StellarIdentitySDK(config);
    expect(sdk.reputation.getReputationTier(800).tier).toBe('Strong');
    expect(sdk.reputation.calculateReputationTrend([500, 600, 700]).trend).toBe('stable');
  });
});
