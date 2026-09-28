import { BatchClient, paginate, MAX_CONTRACT_BATCH_SIZE, DEFAULT_PAGE_SIZE } from '../batch';
import { BatchProgress } from '../batch';
import { ValidationError } from '../errors';

jest.mock('../didClient', () => ({
  DIDClient: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('../credentialClient', () => ({
  CredentialClient: jest.fn().mockImplementation(() => ({})),
}));

jest.mock('../logger', () => ({
  Logger: jest.fn().mockImplementation(() => ({
    debug: jest.fn(),
    trace: jest.fn(),
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  })),
}));

const config = {
  network: 'testnet' as const,
  contracts: {
    didRegistry: 'CDID',
    credentialIssuer: 'CCRED',
    reputationScore: 'CREP',
    zkAttestation: 'CZK',
    complianceFilter: 'CCMP',
    schemaRegistry: 'CSCH',
  },
};

/** Build a BatchClient with stubbed clients injected. */
function makeClient(didClient: any, credentialClient: any) {
  return new BatchClient(config, { didClient, credentialClient });
}

describe('paginate', () => {
  it('splits items into fixed-size pages', () => {
    expect(paginate([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });

  it('returns a single page when items fit', () => {
    expect(paginate([1, 2], 10)).toEqual([[1, 2]]);
  });

  it('returns no pages for empty input', () => {
    expect(paginate([], 5)).toEqual([]);
  });

  it('throws for a non-positive page size', () => {
    expect(() => paginate([1], 0)).toThrow(ValidationError);
    expect(() => paginate([1], -1)).toThrow(/pageSize must be greater than 0/);
  });
});

describe('BatchClient', () => {
  describe('createDIDs', () => {
    it('creates a DID for every request', async () => {
      const didClient = { createDID: jest.fn().mockResolvedValue('did:stellar:G1') };
      const client = makeClient(didClient, {});

      const result = await client.createDIDs([
        { keypair: { publicKey: () => 'G1' } as any, options: { verificationMethods: [], services: [] } },
        { keypair: { publicKey: () => 'G2' } as any, options: { verificationMethods: [], services: [] } },
      ]);

      expect(didClient.createDID).toHaveBeenCalledTimes(2);
      expect(result.succeeded).toHaveLength(2);
      expect(result.failed).toHaveLength(0);
      expect(result.items.map(i => i.output)).toEqual(['did:stellar:G1', 'did:stellar:G1']);
    });

    it('captures per-item failures without aborting', async () => {
      const didClient = {
        createDID: jest.fn()
          .mockResolvedValueOnce('did:stellar:G1')
          .mockRejectedValueOnce(new Error('create_did reverted')),
      };
      const client = makeClient(didClient, {});

      const result = await client.createDIDs([
        { keypair: {} as any, options: { verificationMethods: [], services: [] } },
        { keypair: {} as any, options: { verificationMethods: [], services: [] } },
      ]);

      expect(result.succeeded).toHaveLength(1);
      expect(result.failed).toHaveLength(1);
      expect(result.failed[0].error?.message).toBe('create_did reverted');
    });

    it('wraps non-Error rejections', async () => {
      const didClient = { createDID: jest.fn().mockRejectedValue('string failure') };
      const client = makeClient(didClient, {});

      const result = await client.createDIDs([
        { keypair: {} as any, options: { verificationMethods: [], services: [] } },
      ]);

      expect(result.failed[0].error).toBeInstanceOf(Error);
      expect(result.failed[0].error?.message).toBe('string failure');
    });
  });

  describe('issueCredentials', () => {
    it('issues a credential for every request', async () => {
      const credentialClient = { issueCredential: jest.fn().mockResolvedValue('cred-1') };
      const client = makeClient({}, credentialClient);

      const result = await client.issueCredentials([
        { issuerKeypair: {} as any, options: { subject: 'G1', credentialType: ['KYC'], credentialData: {}, proof: 'p' } },
      ]);

      expect(credentialClient.issueCredential).toHaveBeenCalledTimes(1);
      expect(result.items[0].output).toBe('cred-1');
    });

    it('forwards txOptions to the underlying call', async () => {
      const credentialClient = { issueCredential: jest.fn().mockResolvedValue('cred-1') };
      const client = makeClient({}, credentialClient);
      const txOptions = { fee: 200, timeout: 60 };

      await client.issueCredentials(
        [{ issuerKeypair: {} as any, options: { subject: 'G1', credentialType: ['KYC'], credentialData: {}, proof: 'p' } }],
        { txOptions },
      );

      expect(credentialClient.issueCredential).toHaveBeenCalledWith(
        expect.anything(),
        expect.anything(),
        txOptions,
      );
    });
  });

  describe('verifyCredentials', () => {
    it('verifies every credential id', async () => {
      const verification = { valid: true, revoked: false, expired: false, issuer: 'G1', subject: 'G2', issuanceDate: 1 };
      const credentialClient = { verifyCredential: jest.fn().mockResolvedValue(verification) };
      const client = makeClient({}, credentialClient);

      const result = await client.verifyCredentials(['c1', 'c2', 'c3']);

      expect(credentialClient.verifyCredential).toHaveBeenCalledTimes(3);
      expect(result.succeeded).toHaveLength(3);
      expect(result.items.map(i => i.key)).toEqual(['c1', 'c2', 'c3']);
    });
  });

  describe('revokeCredentials', () => {
    it('revokes every credential and reports no output', async () => {
      const credentialClient = { revokeCredential: jest.fn().mockResolvedValue(undefined) };
      const client = makeClient({}, credentialClient);

      const result = await client.revokeCredentials([
        { issuerKeypair: {} as any, credentialId: 'c1', reason: 'expired' },
        { issuerKeypair: {} as any, credentialId: 'c2' },
      ]);

      expect(credentialClient.revokeCredential).toHaveBeenCalledTimes(2);
      expect(result.succeeded).toHaveLength(2);
      expect(result.items.every(i => i.output === undefined)).toBe(true);
    });
  });

  describe('pagination', () => {
    it('splits large batches into multiple pages', async () => {
      const didClient = { createDID: jest.fn().mockResolvedValue('did:stellar:G1') };
      const client = makeClient(didClient, {});

      const requests = Array.from({ length: 10 }, (_, i) => ({
        keypair: {} as any,
        options: { verificationMethods: [], services: [] },
        _i: i,
      }));

      const result = await client.createDIDs(requests as any, { pageSize: 3 });

      expect(result.pageCount).toBe(4);
      expect(didClient.createDID).toHaveBeenCalledTimes(10);
    });

    it('caps pageSize at the contract maximum', async () => {
      const didClient = { createDID: jest.fn().mockResolvedValue('did:stellar:G1') };
      const client = makeClient(didClient, {});

      const requests = Array.from({ length: 120 }, () => ({
        keypair: {} as any,
        options: { verificationMethods: [], services: [] },
      }));

      // 120 items at a capped page size of 50 => 3 pages.
      const result = await client.createDIDs(requests as any, { pageSize: 500 });

      expect(result.pageCount).toBe(Math.ceil(120 / MAX_CONTRACT_BATCH_SIZE));
      expect(MAX_CONTRACT_BATCH_SIZE).toBe(50);
    });

    it('defaults to DEFAULT_PAGE_SIZE when unspecified', async () => {
      const didClient = { createDID: jest.fn().mockResolvedValue('did:stellar:G1') };
      const client = makeClient(didClient, {});
      const requests = Array.from({ length: 60 }, () => ({
        keypair: {} as any,
        options: { verificationMethods: [], services: [] },
      }));

      const result = await client.createDIDs(requests as any);

      expect(result.pageCount).toBe(Math.ceil(60 / DEFAULT_PAGE_SIZE));
    });
  });

  describe('progress reporting', () => {
    it('reports monotonically increasing progress', async () => {
      const credentialClient = { verifyCredential: jest.fn().mockResolvedValue({ valid: true }) };
      const client = makeClient({}, credentialClient);
      const progress: BatchProgress[] = [];

      await client.verifyCredentials(['c1', 'c2', 'c3', 'c4'], {
        onProgress: p => progress.push(p),
      });

      expect(progress).toHaveLength(4);
      expect(progress.map(p => p.completed)).toEqual([1, 2, 3, 4]);
      progress.forEach(p => {
        expect(p.total).toBe(4);
        expect(p.operation).toBe('batchVerifyCredentials');
      });
      expect(progress[progress.length - 1].fraction).toBe(1);
    });

    it('reports failed items as progress too', async () => {
      const credentialClient = {
        verifyCredential: jest.fn()
          .mockResolvedValueOnce({ valid: true })
          .mockRejectedValueOnce(new Error('boom')),
      };
      const client = makeClient({}, credentialClient);
      const progress: BatchProgress[] = [];

      await client.verifyCredentials(['c1', 'c2'], { onProgress: p => progress.push(p) });

      expect(progress).toHaveLength(2);
      expect(progress[1].fraction).toBe(1);
    });
  });

  describe('optimistic updates', () => {
    it('applies, commits and rolls back appropriately', async () => {
      const didClient = {
        createDID: jest.fn()
          .mockResolvedValueOnce('did:stellar:G1')
          .mockRejectedValueOnce(new Error('reverted')),
      };
      const client = makeClient(didClient, {});
      const apply = jest.fn();
      const commit = jest.fn();
      const rollback = jest.fn();

      await client.createDIDs(
        [
          { keypair: {} as any, options: { verificationMethods: [], services: [] } },
          { keypair: {} as any, options: { verificationMethods: [], services: [] } },
        ],
        { optimistic: { apply, commit, rollback } },
      );

      expect(apply).toHaveBeenCalledTimes(2);
      expect(commit).toHaveBeenCalledTimes(1);
      expect(rollback).toHaveBeenCalledTimes(1);
      expect(rollback.mock.calls[0][1].message).toBe('reverted');
    });
  });

  describe('strict mode', () => {
    it('aborts on first failure and rolls back pending items', async () => {
      const didClient = { createDID: jest.fn().mockRejectedValue(new Error('reverted')) };
      const client = makeClient(didClient, {});
      const rollback = jest.fn();

      await expect(
        client.createDIDs(
          Array.from({ length: 4 }, () => ({ keypair: {} as any, options: { verificationMethods: [], services: [] } })),
          { continueOnError: false, pageSize: 4, concurrency: 1, optimistic: { rollback } },
        ),
      ).rejects.toThrow(/aborted after a failure/);

      expect(rollback).toHaveBeenCalledTimes(4);
    });
  });

  describe('edge cases', () => {
    it('returns an empty result for an empty batch', async () => {
      const client = makeClient({ createDID: jest.fn() }, {});

      const result = await client.createDIDs([]);

      expect(result.items).toEqual([]);
      expect(result.pageCount).toBe(0);
      expect(result.totalDurationMs).toBe(0);
    });

    it('preserves explicit keys on pre-built batch items', async () => {
      const didClient = { createDID: jest.fn().mockResolvedValue('did:stellar:G1') };
      const client = makeClient(didClient, {});

      const result = await client.createDIDs(
        [{ key: 'alice', input: { keypair: {} as any, options: { verificationMethods: [], services: [] } } }] as any,
      );

      expect(result.items[0].key).toBe('alice');
    });

    it('reports a non-negative totalDurationMs', async () => {
      const credentialClient = { verifyCredential: jest.fn().mockResolvedValue({ valid: true }) };
      const client = makeClient({}, credentialClient);

      const result = await client.verifyCredentials(['c1']);

      expect(result.totalDurationMs).toBeGreaterThanOrEqual(0);
    });
  });
});
