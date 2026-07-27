import { SchemaRegistryClient } from '../schemaClient';
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
  },
  Transaction: class {},
}));

const stellarSdk = require('stellar-sdk');

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

const VALID_ISSUER = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';

function makeSchemaRaw(overrides: Record<string, unknown> = {}) {
  return {
    id: new TextEncoder().encode('KYC-Schema-v1'),
    issuer: new TextEncoder().encode(VALID_ISSUER),
    version: 1n,
    definition: new TextEncoder().encode('{"type":"object","required":["firstName","lastName"]}'),
    created: 1700000000n,
    updated: 1700000000n,
    ...overrides,
  };
}

describe('SchemaRegistryClient', () => {
  let client: SchemaRegistryClient;
  let mockIssuerKeypair: any;
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

    const { Contract, Keypair } = require('stellar-sdk');
    Contract.mockImplementation(() => ({
      call: jest.fn().mockReturnValue({}),
    }));
    Keypair.random.mockReturnValue({
      publicKey: jest.fn().mockReturnValue(VALID_ISSUER),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    });

    client = new SchemaRegistryClient(validTestnetConfig);
    mockIssuerKeypair = {
      publicKey: jest.fn().mockReturnValue(VALID_ISSUER),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    };
  });

  describe('registerSchema', () => {
    it('should register a new schema', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS', hash: 'abc123' });

      await expect(
        client.registerSchema(mockIssuerKeypair, 'KYC-Schema-v1', '{"type":"object"}')
      ).resolves.toBeUndefined();
    });

    it('should throw on failed registration', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'ERROR', errorResult: 'AlreadyExists' });

      await expect(
        client.registerSchema(mockIssuerKeypair, 'existing-schema', '{}')
      ).rejects.toThrow('Transaction failed');
    });
  });

  describe('updateSchema', () => {
    it('should update an existing schema', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS', hash: 'abc123' });

      await expect(
        client.updateSchema(mockIssuerKeypair, 'KYC-Schema-v1', '{"type":"object","required":["name"]}')
      ).resolves.toBeUndefined();
    });
  });

  describe('getSchema', () => {
    it('should retrieve a schema by ID', async () => {
      stellarSdk.scValToNative.mockReturnValue(makeSchemaRaw());

      const schema = await client.getSchema('KYC-Schema-v1');
      expect(schema.id).toBe('KYC-Schema-v1');
      expect(schema.issuer).toBe(VALID_ISSUER);
      expect(schema.version).toBe(1);
    });
  });

  describe('getSchema with version', () => {
    it('should retrieve a specific schema version', async () => {
      stellarSdk.scValToNative.mockReturnValue(makeSchemaRaw({ version: 2n }));

      const schema = await client.getSchema('KYC-Schema-v1', 2);
      expect(schema.version).toBe(2);
    });
  });

  describe('listSchemas', () => {
    it('should return a paginated list of schema IDs', async () => {
      stellarSdk.scValToNative.mockReturnValue([
        new TextEncoder().encode('schema-1'),
        new TextEncoder().encode('schema-2'),
      ]);

      const schemas = await client.listSchemas(1, 10);
      expect(schemas).toEqual(['schema-1', 'schema-2']);
    });

    it('should return empty array when no schemas', async () => {
      stellarSdk.scValToNative.mockReturnValue([]);

      const schemas = await client.listSchemas(1, 10);
      expect(schemas).toEqual([]);
    });
  });

  describe('validateData', () => {
    it('should validate data against a schema', async () => {
      stellarSdk.scValToNative.mockReturnValue(true);

      const schemaMock = makeSchemaRaw({
        definition: new TextEncoder().encode('{"type":"object","required":["firstName","lastName"]}'),
      });
      stellarSdk.scValToNative.mockReturnValue(schemaMock);

      const result = await client.validateData('KYC-Schema-v1', JSON.stringify({ firstName: 'John', lastName: 'Doe' }));
      expect(result.valid).toBe(true);
    });

    it('should return errors for missing required fields', async () => {
      stellarSdk.scValToNative.mockReturnValue(true);

      const schemaMock = makeSchemaRaw({
        definition: new TextEncoder().encode('{"type":"object","required":["firstName","lastName"]}'),
      });
      stellarSdk.scValToNative.mockReturnValue(schemaMock);

      const result = await client.validateData('KYC-Schema-v1', JSON.stringify({ firstName: 'John' }));
      expect(result.valid).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('getSchemaVersion', () => {
    it('should return version history', async () => {
      stellarSdk.scValToNative.mockReturnValue(makeSchemaRaw({ version: 3n }));

      const versions = await client.getSchemaVersion('KYC-Schema-v1');
      expect(versions.length).toBeGreaterThanOrEqual(1);
      expect(versions[0].schemaId).toBe('KYC-Schema-v1');
    });
  });

  describe('validateSchema', () => {
    it('should return true if schema exists', async () => {
      stellarSdk.scValToNative.mockReturnValue(true);

      const result = await client.validateSchema('KYC-Schema-v1');
      expect(result).toBe(true);
    });

    it('should return false if schema does not exist', async () => {
      stellarSdk.scValToNative.mockReturnValue(false);

      const result = await client.validateSchema('nonexistent');
      expect(result).toBe(false);
    });
  });
});
