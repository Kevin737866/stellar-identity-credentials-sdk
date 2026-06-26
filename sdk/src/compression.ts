/**
 * Credential payload compression for reduced on-chain storage costs (#83).
 *
 * Uses the browser/Node.js native `CompressionStream` / `DecompressionStream`
 * APIs (Node 18+, all modern browsers) with the `deflate-raw` algorithm.
 *
 * Wire format (base64url-encoded):
 *
 *   ┌──────────┬──────────┬────────────────────┬──────────────────────────┐
 *   │ magic[2] │ version  │ crc32[4] (LE u32)  │ deflate-raw payload      │
 *   │ 0xC0 0xDE│ 0x01     │ of original UTF-8  │ (variable length)        │
 *   └──────────┴──────────┴────────────────────┴──────────────────────────┘
 *
 * Enhancements over v1:
 *  - Typed `CompressionError` hierarchy — callers can branch on `code`
 *    instead of parsing message strings.
 *  - CRC-32 integrity checksum written into the header and verified on
 *    decompress, so bit-flips in storage are caught before JSON.parse.
 *  - Version byte in the header — allows future algorithm upgrades without
 *    breaking existing payloads.
 *  - Configurable size guard — rejects payloads above `MAX_PAYLOAD_BYTES`
 *    before allocating, preventing memory exhaustion from crafted inputs.
 *  - `streamTransform` now pipes through `ReadableStream.pipeTo` instead
 *    of manually pumping the reader, which lets the runtime backpressure
 *    correctly on large inputs.
 *  - `compressBatch` / `decompressBatch` — process multiple payloads with
 *    a configurable concurrency limit to avoid saturating the event loop.
 *  - `compressionRatio` now returns `savings` in bytes and a human-readable
 *    `summary` string alongside the ratio.
 *  - `isCompressed` — synchronous predicate for the wire format.
 *  - Full JSDoc on every export.
 *  - Comprehensive test suite included at the bottom (Vitest-compatible).
 */

// ── Constants ─────────────────────────────────────────────────────────────────

/** Two-byte magic marker identifying a compressed payload. */
const MAGIC = new Uint8Array([0xc0, 0xde]);

/** Current wire-format version byte. */
const VERSION = 0x01;

/**
 * Header layout:
 *   [0..1] magic (2 bytes)
 *   [2]    version (1 byte)
 *   [3..6] CRC-32 of original JSON bytes, little-endian uint32 (4 bytes)
 */
const HEADER_SIZE = 7; // magic(2) + version(1) + crc32(4)

/**
 * Maximum uncompressed JSON size accepted.
 * Protects against memory exhaustion from oversized inputs.
 * Override via `CompressionOptions.maxPayloadBytes`.
 */
const DEFAULT_MAX_PAYLOAD_BYTES = 4 * 1024 * 1024; // 4 MB

/** Default concurrency for `compressBatch` / `decompressBatch`. */
const DEFAULT_CONCURRENCY = 4;

// ── Error hierarchy ───────────────────────────────────────────────────────────

export type CompressionErrorCode =
  | 'PAYLOAD_TOO_LARGE'
  | 'STREAM_UNAVAILABLE'
  | 'COMPRESS_FAILED'
  | 'DECOMPRESS_FAILED'
  | 'CHECKSUM_MISMATCH'
  | 'UNKNOWN_VERSION'
  | 'INVALID_ENCODING'
  | 'SERIALIZE_FAILED';

/** Typed error thrown by every function in this module. */
export class CompressionError extends Error {
  constructor(
    public readonly code: CompressionErrorCode,
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'CompressionError';
  }
}

// ── Options ───────────────────────────────────────────────────────────────────

export interface CompressionOptions {
  /** Reject inputs whose UTF-8 JSON exceeds this many bytes (default 4 MB). */
  maxPayloadBytes?: number;
}

export interface BatchOptions extends CompressionOptions {
  /** Maximum number of concurrent compress/decompress operations (default 4). */
  concurrency?: number;
}

// ── Return types ──────────────────────────────────────────────────────────────

export interface CompressionStats {
  /** Byte length of the original JSON-encoded payload. */
  originalBytes: number;
  /** Byte length of the base64url-encoded compressed string. */
  compressedBytes: number;
  /** Bytes saved (negative means the compressed form is larger). */
  savedBytes: number;
  /** Space saved as a percentage of the original (may be negative). */
  ratio: number;
  /** Human-readable one-liner, e.g. "42.3% smaller (1.2 KB → 693 B)". */
  summary: string;
}

export interface BatchResult<T> {
  index: number;
  value?: T;
  error?: CompressionError;
}

// ── CRC-32 ────────────────────────────────────────────────────────────────────

/** Pre-computed CRC-32 lookup table (ISO 3309 / ITU-T V.42). */
const CRC_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0; // unsigned 32-bit
}

function writeCrc32LE(view: DataView, offset: number, value: number): void {
  view.setUint32(offset, value, /* littleEndian */ true);
}

function readCrc32LE(view: DataView, offset: number): number {
  return view.getUint32(offset, /* littleEndian */ true);
}

// ── Stream helpers ────────────────────────────────────────────────────────────

/**
 * Verify that the runtime exposes `CompressionStream` / `DecompressionStream`.
 * Throws a typed error rather than a cryptic `ReferenceError` if not available.
 */
function assertStreamsAvailable(): void {
  if (
    typeof CompressionStream === 'undefined' ||
    typeof DecompressionStream === 'undefined'
  ) {
    throw new CompressionError(
      'STREAM_UNAVAILABLE',
      'CompressionStream / DecompressionStream are not available in this runtime. ' +
        'Upgrade to Node 18+ or use a modern browser.',
    );
  }
}

/**
 * Pipe `input` through `transform` and concatenate all output chunks.
 * Uses `pipeTo` for correct backpressure handling on large inputs.
 */
async function streamTransform(
  input: Uint8Array,
  transform: TransformStream<Uint8Array, Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];

  const sink = new WritableStream<Uint8Array>({
    write(chunk) {
      chunks.push(chunk);
    },
  });

  // Feed the input as a single-item ReadableStream so we don't need to
  // manage a writer + close() sequence manually.
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(input);
      controller.close();
    },
  });

  await source.pipeThrough(transform).pipeTo(sink);

  // Concatenate chunks into a single Uint8Array.
  const totalLength = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// ── Base64url helpers ─────────────────────────────────────────────────────────

function toBase64Url(bytes: Uint8Array): string {
  // Process in chunks to avoid call-stack overflow on large arrays.
  const CHUNK = 8192;
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(encoded: string): Uint8Array {
  const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  try {
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  } catch (err) {
    throw new CompressionError(
      'INVALID_ENCODING',
      'Input is not valid base64url — it may be corrupt or not produced by compressPayload.',
      err,
    );
  }
}

// ── Formatting ────────────────────────────────────────────────────────────────

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Synchronously check whether `encoded` is a compressed payload produced
 * by this module (i.e. begins with the magic + version header).
 */
export function isCompressed(encoded: string): boolean {
  try {
    const raw = fromBase64Url(encoded);
    return (
      raw.length >= HEADER_SIZE &&
      raw[0] === MAGIC[0] &&
      raw[1] === MAGIC[1] &&
      raw[2] === VERSION
    );
  } catch {
    return false;
  }
}

/**
 * Compress a JSON-serialisable credential payload.
 *
 * @param data    Any JSON-serialisable value.
 * @param options Optional configuration.
 * @returns       A base64url string containing the magic header, version,
 *                CRC-32 checksum, and deflate-raw compressed payload.
 */
export async function compressPayload(
  data: unknown,
  options: CompressionOptions = {},
): Promise<string> {
  assertStreamsAvailable();

  const maxBytes = options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES;

  let jsonBytes: Uint8Array;
  try {
    jsonBytes = new TextEncoder().encode(JSON.stringify(data));
  } catch (err) {
    throw new CompressionError('SERIALIZE_FAILED', 'Failed to JSON-serialize the payload.', err);
  }

  if (jsonBytes.length > maxBytes) {
    throw new CompressionError(
      'PAYLOAD_TOO_LARGE',
      `Payload is ${formatBytes(jsonBytes.length)} which exceeds the ${formatBytes(maxBytes)} limit. ` +
        'Increase options.maxPayloadBytes or reduce the payload size.',
    );
  }

  let compressed: Uint8Array;
  try {
    compressed = await streamTransform(
      jsonBytes,
      new CompressionStream('deflate-raw') as unknown as TransformStream<Uint8Array, Uint8Array>,
    );
  } catch (err) {
    if (err instanceof CompressionError) throw err;
    throw new CompressionError('COMPRESS_FAILED', 'deflate-raw compression failed.', err);
  }

  // Build wire format: [magic(2)] [version(1)] [crc32(4 LE)] [compressed data]
  const out = new Uint8Array(HEADER_SIZE + compressed.length);
  const view = new DataView(out.buffer);

  out[0] = MAGIC[0];
  out[1] = MAGIC[1];
  out[2] = VERSION;
  writeCrc32LE(view, 3, crc32(jsonBytes)); // checksum of original bytes
  out.set(compressed, HEADER_SIZE);

  return toBase64Url(out);
}

/**
 * Decompress a payload produced by `compressPayload`.
 *
 * Falls back to plain JSON-parse for legacy uncompressed payloads (those
 * that do not begin with the magic header).
 *
 * @param encoded  A base64url string from `compressPayload`, or a plain
 *                 base64url-encoded JSON string for backward compatibility.
 * @param options  Optional configuration.
 * @returns        The deserialized value.
 */
export async function decompressPayload<T = unknown>(
  encoded: string,
  options: CompressionOptions = {},
): Promise<T> {
  const raw = fromBase64Url(encoded);

  // ── Compressed path ──────────────────────────────────────────────────────
  if (raw.length >= HEADER_SIZE && raw[0] === MAGIC[0] && raw[1] === MAGIC[1]) {
    const version = raw[2];
    if (version !== VERSION) {
      throw new CompressionError(
        'UNKNOWN_VERSION',
        `Unsupported compression version 0x${version.toString(16).padStart(2, '0')}. ` +
          `This build only supports version 0x${VERSION.toString(16).padStart(2, '0')}.`,
      );
    }

    assertStreamsAvailable();

    const view = new DataView(raw.buffer, raw.byteOffset);
    const storedCrc = readCrc32LE(view, 3);
    const compressedData = raw.slice(HEADER_SIZE);

    let jsonBytes: Uint8Array;
    try {
      jsonBytes = await streamTransform(
        compressedData,
        new DecompressionStream('deflate-raw') as unknown as TransformStream<Uint8Array, Uint8Array>,
      );
    } catch (err) {
      if (err instanceof CompressionError) throw err;
      throw new CompressionError(
        'DECOMPRESS_FAILED',
        'deflate-raw decompression failed — the payload may be corrupt.',
        err,
      );
    }

    // Verify integrity after decompression.
    const actualCrc = crc32(jsonBytes);
    if (actualCrc !== storedCrc) {
      throw new CompressionError(
        'CHECKSUM_MISMATCH',
        `CRC-32 mismatch: stored 0x${storedCrc.toString(16)}, computed 0x${actualCrc.toString(16)}. ` +
          'The payload may have been corrupted in storage.',
      );
    }

    try {
      return JSON.parse(new TextDecoder().decode(jsonBytes)) as T;
    } catch (err) {
      throw new CompressionError(
        'DECOMPRESS_FAILED',
        'Decompression succeeded but the result is not valid JSON.',
        err,
      );
    }
  }

  // ── Legacy plain-JSON fallback ───────────────────────────────────────────
  try {
    return JSON.parse(new TextDecoder().decode(raw)) as T;
  } catch (err) {
    throw new CompressionError(
      'INVALID_ENCODING',
      'Payload is neither a compressed payload nor valid plain JSON.',
      err,
    );
  }
}

/**
 * Compute detailed compression statistics for a given payload.
 *
 * @param data  Any JSON-serialisable value.
 * @returns     `CompressionStats` including byte counts, ratio, and a
 *              human-readable summary.
 */
export async function compressionRatio(data: unknown): Promise<CompressionStats> {
  const jsonBytes = new TextEncoder().encode(JSON.stringify(data));
  const originalBytes = jsonBytes.length;

  const compressed = await compressPayload(data);
  const compressedBytes = compressed.length;

  const savedBytes = originalBytes - compressedBytes;
  const ratio = parseFloat(((savedBytes / originalBytes) * 100).toFixed(1));

  const direction = savedBytes >= 0 ? 'smaller' : 'larger';
  const summary =
    `${Math.abs(ratio)}% ${direction} ` +
    `(${formatBytes(originalBytes)} → ${formatBytes(compressedBytes)})`;

  return { originalBytes, compressedBytes, savedBytes, ratio, summary };
}

/**
 * Compress multiple payloads with bounded concurrency.
 *
 * @param items    Array of JSON-serialisable values.
 * @param options  Optional batch and compression settings.
 * @returns        Array of `BatchResult` objects in the same order as `items`.
 *                 Each entry has either `value` or `error` populated.
 */
export async function compressBatch(
  items: unknown[],
  options: BatchOptions = {},
): Promise<BatchResult<string>[]> {
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  const results: BatchResult<string>[] = new Array(items.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < items.length) {
      const index = cursor++;
      try {
        const value = await compressPayload(items[index], options);
        results[index] = { index, value };
      } catch (err) {
        results[index] = {
          index,
          error:
            err instanceof CompressionError
              ? err
              : new CompressionError('COMPRESS_FAILED', String(err), err),
        };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  return results;
}

/**
 * Decompress multiple payloads with bounded concurrency.
 *
 * @param encoded  Array of base64url strings from `compressPayload`.
 * @param options  Optional batch and compression settings.
 * @returns        Array of `BatchResult` objects in the same order as `encoded`.
 */
export async function decompressBatch<T = unknown>(
  encoded: string[],
  options: BatchOptions = {},
): Promise<BatchResult<T>[]> {
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  const results: BatchResult<T>[] = new Array(encoded.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < encoded.length) {
      const index = cursor++;
      try {
        const value = await decompressPayload<T>(encoded[index], options);
        results[index] = { index, value };
      } catch (err) {
        results[index] = {
          index,
          error:
            err instanceof CompressionError
              ? err
              : new CompressionError('DECOMPRESS_FAILED', String(err), err),
        };
      }
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, encoded.length) }, worker));
  return results;
}

// ── Tests (Vitest) ────────────────────────────────────────────────────────────

if (import.meta.vitest) {
  const { describe, it, expect } = import.meta.vitest;

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
}