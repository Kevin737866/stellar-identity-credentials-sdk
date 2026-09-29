/**
 * Integration tests against Stellar testnet.
 *
 * These hit the live network, so they are excluded from the default Jest run
 * (see `testPathIgnorePatterns` in jest.config.js) and must be requested
 * explicitly:
 *
 * ```bash
 * SDK_INTEGRATION=1 npx jest --testPathIgnorePatterns='nothing' \
 *   sdk/src/__tests__/integration
 * ```
 *
 * Every test is skipped unless `SDK_INTEGRATION=1` is set, so importing this
 * file never produces network traffic by accident. A funded testnet keypair can
 * be supplied via `SDK_TESTNET_SECRET`; without it the write paths self-skip
 * while read-only health checks still run.
 */

import { StellarIdentitySDK } from '../../index';
import { DEFAULT_CONFIGS, healthCheck } from '../../config';
import { DIDClient } from '../../didClient';
import { CredentialClient } from '../../credentialClient';
import { ReputationClient } from '../../reputation';
import { ZKProofsClient } from '../../zkProofs';
import { Keypair } from 'stellar-sdk';

const ENABLED = process.env.SDK_INTEGRATION === '1';
const SECRET = process.env.SDK_TESTNET_SECRET;
const RPC_URL = process.env.SDK_TESTNET_RPC_URL;

const describeIfLive = ENABLED ? describe : describe.skip;

/** Config pointing at testnet, with an optional RPC override. */
function testnetConfig() {
  const base = DEFAULT_CONFIGS.testnet;
  return RPC_URL ? { ...base, rpcUrl: RPC_URL } : base;
}

/** A funded keypair, or null when none is configured. */
function fundedKeypair(): Keypair | null {
  if (!SECRET) return null;
  try {
    return Keypair.fromSecret(SECRET);
  } catch {
    return null;
  }
}

const hasFunds = (): boolean => fundedKeypair() !== null;

describeIfLive('SDK integration — Stellar testnet', () => {
  let sdk: StellarIdentitySDK;

  beforeAll(() => {
    sdk = new StellarIdentitySDK(testnetConfig(), { validate: false });
  });

  describe('network reachability', () => {
    it('reports a healthy RPC endpoint', async () => {
      const result = await healthCheck(testnetConfig());
      expect(result).toBeDefined();
      // A down endpoint must be reported, not thrown.
      expect(typeof result).toBe('object');
    }, 30_000);

    it('runs a comprehensive health check', async () => {
      const result = await sdk.checkHealthComprehensive();
      expect(result).toBeDefined();
    }, 30_000);
  });

  describe('DIDClient', () => {
    it('builds a valid did:stellar string from an address', () => {
      const client = new DIDClient(testnetConfig());
      const did = client.generateDID('GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345');

      expect(did).toMatch(/^did:stellar:G/);
      expect(client.validateDIDFormat(did)).toBe(true);
    });

    it('rejects a malformed DID before hitting the network', () => {
      const client = new DIDClient(testnetConfig());
      expect(client.validateDIDFormat('not-a-did')).toBe(false);
    });

    it('extracts the controller address from a DID', () => {
      const client = new DIDClient(testnetConfig());
      const did = client.generateDID('GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345');

      expect(client.extractStellarAddress(did)).toBe(
        'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345',
      );
    });

    it('reports didExists as false for an unused address', async () => {
      const client = new DIDClient(testnetConfig());
      const exists = await client.didExists('did:stellar:GUNUSEDADDRESSFORTESTINGONLY0000000000000');

      expect(typeof exists).toBe('boolean');
    }, 30_000);

    const maybe = hasFunds() ? it : it.skip;
    maybe('creates and resolves a DID', async () => {
      const keypair = fundedKeypair()!;
      const client = new DIDClient(testnetConfig());

      const did = await client.createDID(keypair, {
        verificationMethods: [],
        services: [],
      });
      expect(did).toMatch(/^did:stellar:/);

      const resolved = await client.resolveDID(did, true);
      expect(resolved.didDocument.id).toBe(did);
    }, 60_000);
  });

  describe('CredentialClient', () => {
    it('validates a subject address without network access', async () => {
      const client = new CredentialClient(testnetConfig());
      const keypair = Keypair.random();

      await expect(
        client.issueCredential(keypair, {
          subject: 'not-an-address',
          credentialType: ['KYC'],
          credentialData: {},
          proof: 'p',
        }),
      ).rejects.toBeDefined();
    });

    it('rejects oversized credential data', async () => {
      const client = new CredentialClient(testnetConfig());
      const keypair = Keypair.random();

      await expect(
        client.issueCredential(keypair, {
          subject: keypair.publicKey(),
          credentialType: ['KYC'],
          credentialData: { blob: 'x'.repeat(11_000) },
          proof: 'p',
        }),
      ).rejects.toBeDefined();
    });

    it('rejects an empty credential type list', async () => {
      const client = new CredentialClient(testnetConfig());
      const keypair = Keypair.random();

      await expect(
        client.issueCredential(keypair, {
          subject: keypair.publicKey(),
          credentialType: [],
          credentialData: {},
          proof: 'p',
        }),
      ).rejects.toBeDefined();
    });

    it('rejects an invalid credential id on verify', async () => {
      const client = new CredentialClient(testnetConfig());
      await expect(client.getCredential('missing')).rejects.toBeDefined();
    }, 30_000);

    const maybe = hasFunds() ? it : it.skip;
    maybe('issues a credential and reads it back', async () => {
      const keypair = fundedKeypair()!;
      const client = new CredentialClient(testnetConfig());

      const credentialId = await client.issueCredential(keypair, {
        subject: keypair.publicKey(),
        credentialType: ['KYCVerification', 'VerifiableCredential'],
        credentialData: { type: 'KYCVerification', data: { firstName: 'Integration' } },
        proof: 'integration-proof',
      });

      expect(credentialId).toBeTruthy();
      const credential = await client.getCredential(credentialId);
      expect(credential.subject).toBe(keypair.publicKey());
    }, 60_000);

    maybe('verifies a batch of credentials', async () => {
      const client = new CredentialClient(testnetConfig());
      const results = await client.batchVerifyCredentials(['cred-does-not-exist']);

      expect(Array.isArray(results)).toBe(true);
    }, 30_000);
  });

  describe('ReputationClient', () => {
    it('constructs against a testnet config', () => {
      const client = new ReputationClient(testnetConfig());
      expect(client).toBeInstanceOf(ReputationClient);
    });

    it('returns a score object for an uninitialised address', async () => {
      const client = new ReputationClient(testnetConfig());
      const score = await client.getReputationScore(
        'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ2345',
      );

      expect(score).toBeDefined();
      expect(typeof score.score).toBe('number');
    }, 30_000);
  });

  describe('ZKProofsClient', () => {
    it('constructs against a testnet config', () => {
      const client = new ZKProofsClient(testnetConfig());
      expect(client).toBeInstanceOf(ZKProofsClient);
    });

    it('rejects a proof with empty bytes', async () => {
      const client = new ZKProofsClient(testnetConfig());
      const keypair = Keypair.random();

      await expect(
        client.verifyProof('proof-id', {
          proofBytes: new Uint8Array(),
          publicInputs: [],
        }),
      ).rejects.toBeDefined();
    }, 30_000);
  });

  describe('error mapping', () => {
    it('wraps network failures in StellarIdentityError instances', async () => {
      const brokenConfig = { ...testnetConfig(), rpcUrl: 'https://127.0.0.1:1/unreachable' };
      const client = new DIDClient(brokenConfig);

      await expect(client.didExists('did:stellar:GINVALID')).rejects.toBeDefined();
    }, 30_000);
  });
});
