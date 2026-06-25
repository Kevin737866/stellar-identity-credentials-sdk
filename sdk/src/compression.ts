/**
 * Credential payload compression for reduced on-chain storage costs (#83).
 *
 * Uses the browser/Node.js native `CompressionStream` / `DecompressionStream`
 * APIs (available in Node 18+ and all modern browsers) with the `deflate-raw`
 * algorithm.  A 2-byte magic header `[0xC0, 0xDE]` ("CODE") marks compressed
 * payloads so legacy plain-JSON payloads can still be decoded transparently.
 */

const MAGIC = new Uint8Array([0xc0, 0xde]);

async function streamTransform(
  input: Uint8Array,
  transform: TransformStream<Uint8Array, Uint8Array>
): Promise<Uint8Array> {
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();

  writer.write(input);
  writer.close();

  const chunks: Uint8Array[] = [];
  let done = false;
  while (!done) {
    const { value, done: d } = await reader.read();
    if (value) chunks.push(value);
    done = d;
  }

  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * Compress a JSON-serialisable credential payload.
 * Returns a base64url string prefixed with the magic header.
 */
export async function compressPayload(data: unknown): Promise<string> {
  const json = JSON.stringify(data);
  const input = new TextEncoder().encode(json);
  const compressed = await streamTransform(
    input,
    new CompressionStream('deflate-raw') as unknown as TransformStream<Uint8Array, Uint8Array>
  );

  // Prepend magic header
  const out = new Uint8Array(MAGIC.length + compressed.length);
  out.set(MAGIC);
  out.set(compressed, MAGIC.length);

  return btoa(String.fromCharCode(...out))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decompress a payload produced by `compressPayload`.
 * Falls back to plain JSON parse for uncompressed legacy payloads.
 */
export async function decompressPayload<T = unknown>(encoded: string): Promise<T> {
  // Restore base64url padding
  const b64 = encoded.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const raw = Uint8Array.from(atob(padded), c => c.charCodeAt(0));

  // Check magic header
  if (raw[0] === MAGIC[0] && raw[1] === MAGIC[1]) {
    const compressed = raw.slice(MAGIC.length);
    const decompressed = await streamTransform(
      compressed,
      new DecompressionStream('deflate-raw') as unknown as TransformStream<Uint8Array, Uint8Array>
    );
    return JSON.parse(new TextDecoder().decode(decompressed)) as T;
  }

  // Legacy plain-JSON fallback
  return JSON.parse(new TextDecoder().decode(raw)) as T;
}

/**
 * Estimate compression ratio for a given payload (for benchmarking).
 */
export async function compressionRatio(data: unknown): Promise<{ original: number; compressed: number; ratio: number }> {
  const json = JSON.stringify(data);
  const original = new TextEncoder().encode(json).length;
  const compressed = await compressPayload(data);
  return {
    original,
    compressed: compressed.length,
    ratio: parseFloat(((1 - compressed.length / original) * 100).toFixed(1)),
  };
}
