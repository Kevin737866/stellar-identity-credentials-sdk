import { CredentialClient } from '../credentialClient';
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

jest.mock('../compression', () => ({
  compressPayload: jest.fn().mockResolvedValue('compressed_data'),
  decompressPayload: jest.fn().mockResolvedValue({}),
}));

jest.mock('../dataMinimization', () => ({
  DataMinimizationEngine: jest.fn().mockImplementation(() => ({
    applyDisclosurePolicy: jest.fn((cred: any) => cred),
  })),
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

const VALID_ISSUER = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const VALID_SUBJECT = 'GB5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';

function buildMockCredentialRaw(overrides: Record<string, unknown> = {}) {
  return {
    id: new TextEncoder().encode('cred-123'),
    issuer: new TextEncoder().encode(VALID_ISSUER),
    subject: new TextEncoder().encode(VALID_SUBJECT),
    type: [new TextEncoder().encode('KYCVerification')],
    credential_data: new TextEncoder().encode('{"name":"Test"}'),
    issuance_date: 1700000000n,
    expiration_date: undefined,
    revocation: undefined,
    proof: undefined,
    ...overrides,
  };
}

describe('CredentialClient', () => {
  let client: CredentialClient;
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

    // Re-apply Contract mock factory
    const { Contract, Keypair } = require('stellar-sdk');
    Contract.mockImplementation(() => ({
      call: jest.fn().mockReturnValue({}),
    }));
    Keypair.random.mockReturnValue({
      publicKey: jest.fn().mockReturnValue(VALID_ISSUER),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    });

    client = new CredentialClient(validTestnetConfig);
    mockIssuerKeypair = {
      publicKey: jest.fn().mockReturnValue(VALID_ISSUER),
      sign: jest.fn().mockReturnValue(Buffer.from([0x01, 0x02, 0x03])),
    };
  });

  describe('issueCredential', () => {
    it('should issue a credential and return credential ID', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS', hash: 'abc123' });

      const credentialId = await client.issueCredential(mockIssuerKeypair, {
        subject: VALID_SUBJECT,
        credentialType: ['KYCVerification', 'VerifiableCredential'],
        credentialData: { name: 'Test User' },
        proof: 'mockproof',
        expirationDate: Date.now() + 365 * 24 * 60 * 60 * 1000,
      });

      expect(credentialId).toMatch(/^cred-/);
    });

    it('should reject empty subject', async () => {
      await expect(client.issueCredential(mockIssuerKeypair, {
        subject: '',
        credentialType: ['Test'],
        credentialData: {},
        proof: 'proof',
      })).rejects.toThrow();
    });

    it('should reject empty credential types', async () => {
      await expect(client.issueCredential(mockIssuerKeypair, {
        subject: VALID_SUBJECT,
        credentialType: [],
        credentialData: {},
        proof: 'proof',
      })).rejects.toThrow();
    });

    it('should reject null credential data', async () => {
      await expect(client.issueCredential(mockIssuerKeypair, {
        subject: VALID_SUBJECT,
        credentialType: ['KYC'],
        credentialData: null as any,
        proof: 'proof',
      })).rejects.toThrow();
    });
  });

  describe('verifyCredential', () => {
    it('should verify a credential and return verification result', async () => {
      // verifyCredential calls getCredential -> verify_credential -> get_credential_status
      // Each is a simulateRead call
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return buildMockCredentialRaw(); // getCredential
        if (callIndex === 2) return true; // verify_credential
        return 'active'; // get_credential_status
      });

      const result = await client.verifyCredential('cred-123');
      expect(result.valid).toBe(true);
      expect(result.revoked).toBe(false);
    });
  });

  describe('revokeCredential', () => {
    it('should revoke a credential', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS' });

      await expect(
        client.revokeCredential(mockIssuerKeypair, 'cred-123', 'User requested')
      ).resolves.toBeUndefined();
    });
  });

  describe('getCredential', () => {
    it('should retrieve a credential by ID', async () => {
      stellarSdk.scValToNative.mockReturnValue(buildMockCredentialRaw());

      const credential = await client.getCredential('cred-123');
      expect(credential.id).toBe('cred-123');
      expect(credential.issuer).toBe(VALID_ISSUER);
    });
  });

  describe('getSubjectCredentials', () => {
    it('should return credentials for a subject', async () => {
      stellarSdk.scValToNative.mockReturnValue([
        new TextEncoder().encode('cred-1'),
        new TextEncoder().encode('cred-2'),
      ]);

      const creds = await client.getSubjectCredentials(VALID_SUBJECT);
      expect(creds).toEqual(['cred-1', 'cred-2']);
    });
  });

  describe('getIssuerCredentials', () => {
    it('should return credentials issued by an issuer', async () => {
      stellarSdk.scValToNative.mockReturnValue([
        new TextEncoder().encode('cred-1'),
      ]);

      const creds = await client.getIssuerCredentials(VALID_ISSUER);
      expect(creds).toEqual(['cred-1']);
    });
  });

  describe('getCredentialStatus', () => {
    it('should return credential status string', async () => {
      stellarSdk.scValToNative.mockReturnValue(new TextEncoder().encode('active'));

      const status = await client.getCredentialStatus('cred-123');
      expect(status).toBe('active');
    });
  });

  describe('getRevocationReason', () => {
    it('should return null when credential is not revoked', async () => {
      stellarSdk.scValToNative.mockReturnValue(null);

      const reason = await client.getRevocationReason('cred-123');
      expect(reason).toBeNull();
    });

    it('should return revocation reason when revoked', async () => {
      stellarSdk.scValToNative.mockReturnValue(new TextEncoder().encode('Key compromised'));

      const reason = await client.getRevocationReason('cred-123');
      expect(reason).toBe('Key compromised');
    });
  });

  describe('createPresentation', () => {
    it('should create a verifiable presentation', async () => {
      const credentials = [{
        id: 'cred-1', issuer: VALID_ISSUER, subject: VALID_SUBJECT,
        type: ['KYCVerification'], credentialData: {}, issuanceDate: Date.now(),
      }];

      const presentation = await client.createPresentation(
        credentials,
        mockIssuerKeypair,
        'example.com',
        'challenge123',
      );

      expect(presentation.type).toContain('VerifiablePresentation');
      expect(presentation.verifiableCredential).toHaveLength(1);
    });
  });

  describe('verifyPresentation', () => {
    it('should verify a valid presentation', async () => {
      // verifyPresentation calls verifyCredential for each cred
      // Each verifyCredential does: getCredential → verify → getStatus = 3 calls
      let callIndex = 0;
      stellarSdk.scValToNative.mockImplementation(() => {
        callIndex++;
        if (callIndex === 1) return buildMockCredentialRaw({ id: new TextEncoder().encode('cred-1') });
        if (callIndex === 2) return true;
        return 'active';
      });

      const result = await client.verifyPresentation({
        holder: VALID_ISSUER,
        verifiableCredential: [{
          id: 'cred-1', issuer: VALID_ISSUER, subject: VALID_SUBJECT,
          type: ['KYCVerification'], credentialData: {}, issuanceDate: Date.now(),
        }],
        proof: { type: 'Ed25519Signature2018', jws: 'sig123' },
      });

      expect(result).toBe(true);
    });

    it('should return false for presentation with missing proof', async () => {
      const result = await client.verifyPresentation({
        holder: VALID_ISSUER,
        verifiableCredential: [],
        proof: undefined,
      });
      expect(result).toBe(false);
    });
  });

  describe('issueKYCCredential', () => {
    it('should issue a KYC credential', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS', hash: 'abc123' });

      const credentialId = await client.issueKYCCredential(
        mockIssuerKeypair,
        VALID_SUBJECT,
        {
          firstName: 'John', lastName: 'Doe', dateOfBirth: '1990-01-01',
          nationality: 'US', documentType: 'Passport',
          documentNumber: '123456789', expiryDate: '2030-01-01',
        },
      );

      expect(credentialId).toMatch(/^cred-/);
    });
  });

  describe('issueEducationCredential', () => {
    it('should issue an education credential', async () => {
      mockServer.getAccount.mockResolvedValue({
        accountId: () => VALID_ISSUER,
        sequenceNumber: () => '12345',
        incrementSequenceNumber: () => {},
      });
      mockServer.prepareTransaction.mockResolvedValue({ sign: jest.fn() });
      mockServer.sendTransaction.mockResolvedValue({ status: 'SUCCESS', hash: 'abc123' });

      const credentialId = await client.issueEducationCredential(
        mockIssuerKeypair,
        VALID_SUBJECT,
        {
          degree: 'Bachelor of Science', institution: 'University of Stellar',
          fieldOfStudy: 'Computer Science', graduationDate: '2023-06-01', gpa: 3.8,
        },
      );

      expect(credentialId).toMatch(/^cred-/);
    });
  });

  describe('batchVerifyCredentials', () => {
    it('should verify multiple credentials in parallel', async () => {
      // Always return a valid credential raw regardless of call order
      // This avoids fragility from Promise.all interleaving
      stellarSdk.scValToNative.mockImplementation(() =>
        buildMockCredentialRaw({ id: new TextEncoder().encode('cred-x') })
      );

      const results = await client.batchVerifyCredentials(['cred-1', 'cred-2']);
      expect(results).toHaveLength(2);
    });
  });
});
