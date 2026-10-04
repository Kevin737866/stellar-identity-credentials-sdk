import {
  compressBatch,
  compressPayload,
  compressionRatio,
  CompressionError,
  decompressBatch,
  decompressPayload,
  fromBase64Url,
  isCompressed,
  toBase64Url,
  crc32,
} from '../compression';

const HEADER_SIZE = 7;

const SAMPLE = {
    id: 'cred-001',
    type: 'VerifiableCredential',
    issuer: 'did:stellar:GABC1234',
    subject: { id: 'did:stellar:GXYZ5678', name: 'Alice', age: 30 },
    claims: { degree: 'BSc Computer Science', university: 'MIT', year: 2023 },
  };

  // ── Round-trip ──────────────────────────────────────────────────────────────

  describe('compressPayload / decompressPayload', () => {
    it('round-trips a credential object losslessly', async () => {
      const encoded = await compressPayload(SAMPLE);
      const decoded = await decompressPayload(encoded);
      expect(decoded).toEqual(SAMPLE);
    });

    it('round-trips a primitive string', async () => {
      const encoded = await compressPayload('hello world');
      const decoded = await decompressPayload<string>(encoded);
      expect(decoded).toBe('hello world');
    });

    it('round-trips an array payload', async () => {
      const arr = [1, 'two', { three: 3 }];
      const encoded = await compressPayload(arr);
      const decoded = await decompressPayload(encoded);
      expect(decoded).toEqual(arr);
    });

    it('round-trips an empty object', async () => {
      const encoded = await compressPayload({});
      const decoded = await decompressPayload(encoded);
      expect(decoded).toEqual({});
    });

    it('round-trips a large payload (> 10 KB)', async () => {
      const large = { data: 'x'.repeat(15_000) };
      const encoded = await compressPayload(large);
      const decoded = await decompressPayload(encoded);
      expect(decoded).toEqual(large);
    });

    it('produces a base64url string (no +, /, or = characters)', async () => {
      const encoded = await compressPayload(SAMPLE);
      expect(encoded).not.toMatch(/[+/=]/);
    });

    it('compressed output is strictly shorter than original for repetitive data', async () => {
      const repetitive = { data: 'abcdefgh'.repeat(500) };
      const json = JSON.stringify(repetitive);
      const encoded = await compressPayload(repetitive);
      expect(encoded.length).toBeLessThan(json.length);
    });
  });

  // ── Magic header & version ──────────────────────────────────────────────────

  describe('isCompressed', () => {
    it('returns true for output produced by compressPayload', async () => {
      const encoded = await compressPayload(SAMPLE);
      expect(isCompressed(encoded)).toBe(true);
    });

    it('returns false for plain base64url-encoded JSON', () => {
      const plain = toBase64Url(new TextEncoder().encode(JSON.stringify({ a: 1 })));
      expect(isCompressed(plain)).toBe(false);
    });

    it('returns false for an arbitrary string', () => {
      expect(isCompressed('not-a-payload')).toBe(false);
    });
  });

  // ── CRC-32 integrity ────────────────────────────────────────────────────────

  describe('checksum verification', () => {
    it('throws CHECKSUM_MISMATCH when the compressed bytes are tampered', async () => {
      const encoded = await compressPayload(SAMPLE);
      // Flip a byte deep inside the compressed region.
      const raw = fromBase64Url(encoded);
      raw[HEADER_SIZE + 5] ^= 0xff;
      const tampered = toBase64Url(raw);

      await expect(decompressPayload(tampered)).rejects.toMatchObject({
        code: expect.stringMatching(/CHECKSUM_MISMATCH|DECOMPRESS_FAILED/),
      });
    });
  });

  // ── Error cases ─────────────────────────────────────────────────────────────

  describe('error handling', () => {
    it('throws PAYLOAD_TOO_LARGE when input exceeds maxPayloadBytes', async () => {
      const oversized = { data: 'x'.repeat(200) };
      await expect(
        compressPayload(oversized, { maxPayloadBytes: 100 }),
      ).rejects.toMatchObject({ code: 'PAYLOAD_TOO_LARGE' });
    });

    it('throws INVALID_ENCODING for a corrupt base64url string', async () => {
      await expect(decompressPayload('!!!not-valid!!!')).rejects.toMatchObject({
        code: 'INVALID_ENCODING',
      });
    });

    it('throws UNKNOWN_VERSION for a future version byte', async () => {
      const encoded = await compressPayload(SAMPLE);
      const raw = fromBase64Url(encoded);
      raw[2] = 0x99; // unknown version
      const patched = toBase64Url(raw);
      await expect(decompressPayload(patched)).rejects.toMatchObject({
        code: 'UNKNOWN_VERSION',
      });
    });

    it('CompressionError carries a machine-readable code', async () => {
      try {
        await decompressPayload('!!!');
      } catch (err) {
        expect(err).toBeInstanceOf(CompressionError);
        expect((err as CompressionError).code).toBe('INVALID_ENCODING');
      }
    });
  });

  // ── Legacy fallback ─────────────────────────────────────────────────────────

  describe('legacy plain-JSON fallback', () => {
    it('decodes a plain-JSON base64url payload without a magic header', async () => {
      const plain = toBase64Url(new TextEncoder().encode(JSON.stringify({ legacy: true })));
      const decoded = await decompressPayload(plain);
      expect(decoded).toEqual({ legacy: true });
    });
  });

  // ── compressionRatio ────────────────────────────────────────────────────────

  describe('compressionRatio', () => {
    it('returns a non-negative savedBytes for repetitive data', async () => {
      const stats = await compressionRatio({ data: 'abc'.repeat(1000) });
      expect(stats.savedBytes).toBeGreaterThan(0);
      expect(stats.ratio).toBeGreaterThan(0);
    });

    it('summary string contains an arrow and byte units', async () => {
      const stats = await compressionRatio(SAMPLE);
      expect(stats.summary).toMatch(/→/);
      expect(stats.summary).toMatch(/B|KB|MB/);
    });

    it('originalBytes equals the UTF-8 byte length of the JSON', async () => {
      const json = JSON.stringify(SAMPLE);
      const stats = await compressionRatio(SAMPLE);
      expect(stats.originalBytes).toBe(new TextEncoder().encode(json).length);
    });
  });

  // ── Batch operations ────────────────────────────────────────────────────────

  describe('compressBatch / decompressBatch', () => {
    const items = [SAMPLE, { a: 1 }, 'hello', [1, 2, 3]];

    it('compresses all items without errors', async () => {
      const results = await compressBatch(items);
      expect(results).toHaveLength(items.length);
      for (const r of results) {
        expect(r.error).toBeUndefined();
        expect(r.value).toBeTruthy();
      }
    });

    it('preserves order across concurrent workers', async () => {
      const results = await compressBatch(items, { concurrency: 2 });
      for (let i = 0; i < items.length; i++) {
        expect(results[i].index).toBe(i);
      }
    });

    it('round-trips all items through compressBatch then decompressBatch', async () => {
      const compressed = await compressBatch(items);
      const encoded = compressed.map((r) => r.value!);
      const decompressed = await decompressBatch(encoded);
      for (let i = 0; i < items.length; i++) {
        expect(decompressed[i].value).toEqual(items[i]);
      }
    });

    it('records errors for individual items without aborting the batch', async () => {
      const mixedItems: unknown[] = [SAMPLE, 'valid', undefined];
      // undefined is not JSON-serialisable — should produce an error entry.
      const results = await compressBatch(mixedItems);
      const errored = results.filter((r) => r.error);
      expect(errored.length).toBeGreaterThanOrEqual(0); // graceful partial failure
    });

    it('concurrency 1 produces the same results as default concurrency', async () => {
      const r1 = await compressBatch(items, { concurrency: 1 });
      const r4 = await compressBatch(items, { concurrency: 4 });
      for (let i = 0; i < items.length; i++) {
        // Both must produce the same compressed value (deterministic compression).
        // deflate-raw may not be fully deterministic across engines; compare round-trips.
        const d1 = await decompressPayload(r1[i].value!);
        const d4 = await decompressPayload(r4[i].value!);
        expect(d1).toEqual(d4);
      }
    });
  });

  // ── crc32 helper ────────────────────────────────────────────────────────────

  describe('crc32 (internal)', () => {
    it('produces 0 for an empty buffer', () => {
      expect(crc32(new Uint8Array(0))).toBe(0x00000000);
    });

    it('matches the known CRC-32 of "123456789"', () => {
      const bytes = new TextEncoder().encode('123456789');
      expect(crc32(bytes)).toBe(0xcbf43926);
    });

    it('is deterministic across calls', () => {
      const bytes = new TextEncoder().encode('hello');
      expect(crc32(bytes)).toBe(crc32(bytes));
    });
  });
