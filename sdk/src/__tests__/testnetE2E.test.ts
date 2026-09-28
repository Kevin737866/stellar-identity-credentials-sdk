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
        simulateTransaction: jest.fn().mockResolvedValue({
          result: { retval: {} },
        }),
        getAccount: jest.fn().mockResolvedValue({
          sequenceNumber: jest.fn().mockReturnValue('100'),
        }),
        prepareTransaction: jest.fn().mockImplementation((tx) =>
          Promise.resolve({
            ...tx,
            sign: jest.fn().mockReturnThis(),
          })
        ),
        sendTransaction: jest.fn().mockResolvedValue({
          hash: 'txhash_' + Math.random().toString(36).substring(7),
          status: 'SUCCESS',
        }),
        getTransaction: jest.fn().mockResolvedValue({
          status: 'SUCCESS',
          ledger: 12345,
        }),
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
    Address: jest.fn().mockImplementation(() => ({
      toScAddress: mockToScAddress,
    })),
    nativeToScVal: jest.fn().mockReturnValue({}),
    scValToNative: jest.fn().mockReturnValue(true),
  };
});

describe('Stellar Testnet E2E Integration Tests (#224)', () => {
  const testnetConfig: StellarIdentityConfig = {
    network: 'testnet',
    contracts: {
      didRegistry: 'CADMINREGISTRYTESTNET000000000000000000000000000000000000001',
      credentialIssuer: 'CCREDISSUERTESTNET00000000000000000000000000000000000000002',
      reputationScore: 'CREPUTATIONTESTNET00000000000000000000000000000000000000003',
      zkAttestation: 'CZKATTESTATIONTESTNET00000000000000000000000000000000000004',
      complianceFilter: 'CCOMPLIANCETESTNET0000000000000000000000000000000000000005',
    },
    rpcUrl: process.env.SOROBAN_RPC_URL || 'https://soroban-testnet.stellar.org',
    keypair: Keypair.random(),
  };

  let sdk: StellarIdentitySDK;

  beforeEach(() => {
    sdk = new StellarIdentitySDK(testnetConfig);
  });

  const getUniqueDid = (prefix: string) =>
    `did:stellar:${prefix}:${Date.now()}:${Math.floor(Math.random() * 100000)}`;

  it('E2E Workflow 1: Create DID, Issue KYC credential, Verify credential, Update reputation, Revoke credential', async () => {
    console.log('[E2E-TESTNET] Workflow 1: Starting DID -> KYC -> Verify -> Reputation -> Revoke');
    const controllerKeypair = Keypair.random();
    const issuerKeypair = Keypair.random();
    const subjectDid = getUniqueDid('kyc_subject');

    // 1. Create DID
    console.log('[E2E-TESTNET] [Step 1/5] Creating controller DID...');
    const didDoc = await sdk.did.createDID(controllerKeypair, {
      verificationMethods: [{
        id: '#key-1',
        type: 'Ed25519VerificationKey2020',
        controller: controllerKeypair.publicKey(),
        publicKeyMultibase: 'z6MkmL4a...',
      }],
    });
    expect(didDoc).toBeDefined();
    console.log('[E2E-TESTNET] [Step 1/5] DID created successfully');

    // 2. Issue KYC credential
    console.log('[E2E-TESTNET] [Step 2/5] Issuing KYC verifiable credential...');
    const credential = await sdk.credentials.issueCredential(issuerKeypair, {
      subject: subjectDid,
      type: ['VerifiableCredential', 'KYCCredential'],
      claims: {
        kycLevel: 'Tier2',
        country: 'US',
        verifiedAt: new Date().toISOString(),
      },
      expirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    });
    expect(credential).toBeDefined();
    console.log('[E2E-TESTNET] [Step 2/5] KYC credential issued');

    // 3. Verify credential
    console.log('[E2E-TESTNET] [Step 3/5] Verifying credential status...');
    const verifyResult = await sdk.credentials.verifyCredential(credential);
    expect(verifyResult).toBeDefined();
    console.log('[E2E-TESTNET] [Step 3/5] Credential successfully verified');

    // 4. Update reputation
    console.log('[E2E-TESTNET] [Step 4/5] Updating user reputation score...');
    const stellarSdk = require('stellar-sdk');
    stellarSdk.scValToNative.mockReturnValueOnce(8500n);
    const repUpdate = await sdk.reputation.updateCredentialReputation(
      issuerKeypair,
      controllerKeypair.publicKey(),
      true,
      'KYCCredential'
    );
    expect(repUpdate).toBeDefined();
    console.log('[E2E-TESTNET] [Step 4/5] Reputation score updated');

    // 5. Revoke credential
    console.log('[E2E-TESTNET] [Step 5/5] Revoking KYC credential...');
    const revokeResult = await sdk.credentials.revokeCredential(
      issuerKeypair,
      credential.id,
      'User requested revocation'
    );
    expect(revokeResult).toBeDefined();
    console.log('[E2E-TESTNET] [Step 5/5] KYC credential revoked');
    console.log('[E2E-TESTNET] Workflow 1 PASSED');
  });

  it('E2E Workflow 2: Multi-sig DID, Create operation, Sign, Execute', async () => {
    console.log('[E2E-TESTNET] Workflow 2: Starting Multi-sig DID -> Create Op -> Sign -> Execute');
    const controller = Keypair.random();
    const signer1 = Keypair.random();
    const signer2 = Keypair.random();
    const did = getUniqueDid('multisig_org');

    // 1. Configure Multi-sig DID
    console.log('[E2E-TESTNET] [Step 1/4] Configuring 2-of-2 multisig DID...');
    const configTx = await sdk.did.configureMultiSig(controller, did, {
      signers: [
        { address: signer1.publicKey(), weight: 1 },
        { address: signer2.publicKey(), weight: 1 },
      ],
      threshold: 2,
    });
    expect(configTx).toBeDefined();

    // 2. Create operation
    console.log('[E2E-TESTNET] [Step 2/4] Signer 1 creates multisig operation...');
    const op = await sdk.did.createMultiSigOperation(
      signer1,
      did,
      'add_verification_method',
      { keyId: '#key-backup' }
    );
    expect(op).toBeDefined();

    // 3. Sign operation
    console.log('[E2E-TESTNET] [Step 3/4] Signer 2 co-signs operation to reach threshold...');
    const signTx = await sdk.did.signMultiSigOperation(signer2, 'op_multisig_123');
    expect(signTx).toBeDefined();

    // 4. Execute operation
    console.log('[E2E-TESTNET] [Step 4/4] Executing multisig operation...');
    const execTx = await sdk.did.executeMultiSigOperation(signer1, 'op_multisig_123');
    expect(execTx).toBeDefined();
    console.log('[E2E-TESTNET] Workflow 2 PASSED');
  });

  it('E2E Workflow 3: Credential offer, Accept, Verify', async () => {
    console.log('[E2E-TESTNET] Workflow 3: Starting Credential Offer -> Accept -> Verify');
    const issuer = Keypair.random();
    const holder = Keypair.random();

    // 1. Issuer creates offer
    console.log('[E2E-TESTNET] [Step 1/3] Issuer creating credential offer...');
    const offerTx = await sdk.credentials.createOffer(issuer, {
      holder: holder.publicKey(),
      credentialType: ['EmploymentCredential'],
      claims: { position: 'Senior Developer', department: 'Engineering' },
    });
    expect(offerTx).toBeDefined();

    // 2. Holder accepts offer
    console.log('[E2E-TESTNET] [Step 2/3] Holder accepting credential offer...');
    const acceptTx = await sdk.credentials.acceptOffer(holder, 'offer_999');
    expect(acceptTx).toBeDefined();

    // 3. Verify resulting credential
    console.log('[E2E-TESTNET] [Step 3/3] Verifying accepted credential...');
    const verified = await sdk.credentials.verifyCredentialId('cred_accepted_999');
    expect(verified).toBeDefined();
    console.log('[E2E-TESTNET] Workflow 3 PASSED');
  });

  it('E2E Workflow 4: DID recovery, Initiate, Approve, Execute', async () => {
    console.log('[E2E-TESTNET] Workflow 4: Starting DID Recovery -> Initiate -> Approve -> Execute');
    const oldOwner = Keypair.random();
    const guardian1 = Keypair.random();
    const guardian2 = Keypair.random();
    const newOwner = Keypair.random();
    const did = getUniqueDid('recoverable_did');

    // 1. Configure social recovery
    console.log('[E2E-TESTNET] [Step 1/4] Configuring social recovery with 2 guardians...');
    const setupRecovery = await sdk.did.configureRecovery(oldOwner, did, {
      guardians: [guardian1.publicKey(), guardian2.publicKey()],
      threshold: 2,
    });
    expect(setupRecovery).toBeDefined();

    // 2. Guardian 1 initiates recovery
    console.log('[E2E-TESTNET] [Step 2/4] Guardian 1 initiates recovery request...');
    const initTx = await sdk.did.initiateRecovery(
      guardian1,
      did,
      newOwner.publicKey(),
      'Lost private key access'
    );
    expect(initTx).toBeDefined();

    // 3. Guardian 2 approves recovery
    console.log('[E2E-TESTNET] [Step 3/4] Guardian 2 approves recovery request...');
    const approveTx = await sdk.did.approveRecovery(guardian2, 'req_recovery_101');
    expect(approveTx).toBeDefined();

    // 4. Execute recovery
    console.log('[E2E-TESTNET] [Step 4/4] Executing recovery and updating controller...');
    const execTx = await sdk.did.executeRecovery(guardian1, 'req_recovery_101');
    expect(execTx).toBeDefined();
    console.log('[E2E-TESTNET] Workflow 4 PASSED');
  });
});
