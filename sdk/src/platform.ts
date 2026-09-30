/**
 * Cross-platform runtime detection and primitives (#204).
 *
 * The SDK was originally written for browsers and Node.js and leaned on a few
 * globals that React Native does not provide:
 *
 * - `Buffer` — not a global in React Native's Hermes runtime
 * - `globalThis.crypto.subtle` — present on modern RN, absent on older
 *   engines and on Expo Go without a secure origin
 * - `process` — a Node-only global
 * - `localStorage` — a browser-only global
 *
 * Everything in this module is dependency-free and safe to import on any
 * platform. Platform integrations (AsyncStorage, biometrics) are wired in
 * lazily by {@link detectPlatform} so that merely importing the SDK never
 * pulls a native module into a web bundle.
 *
 * @module platform
 * @category Utilities
 */

// ── Platform detection ────────────────────────────────────────────────────────

/**
 * Runtime environments the SDK can execute in.
 */
export type RuntimePlatform =
  | 'node'
  | 'browser'
  | 'react-native'
  | 'expo'
  | 'deno'
  | 'bun'
  | 'worker'
  | 'unknown';

/**
 * Where a given API can be sourced from on the current platform.
 *
 * `true` means "available without a polyfill"; `false` means the caller must
 * supply a fallback.
 */
export interface PlatformCapabilities {
  /** `Buffer` is reachable as a global. */
  hasBuffer: boolean;
  /** `globalThis.crypto` is reachable. */
  hasCrypto: boolean;
  /** `globalThis.crypto.subtle` (WebCrypto) is reachable. */
  hasSubtleCrypto: boolean;
  /** `localStorage` is reachable. */
  hasLocalStorage: boolean;
  /** `process` is reachable. */
  hasProcess: boolean;
  /** `TextEncoder` / `TextDecoder` are reachable. */
  hasTextCodec: boolean;
}

/** The detected runtime, memoised after the first call. */
let cachedPlatform: RuntimePlatform | null = null;

/**
 * Identify the runtime the SDK is executing in.
 *
 * Detection is heuristic and ordered from most to least specific. React
 * Native sets `navigator.product === 'ReactNative'`; Expo additionally
 * exposes `navigator.product === 'Expo'`, which is checked first so an Expo Go
 * app is reported as `'expo'` rather than `'react-native'`.
 *
 * The result is cached because the platform cannot change within a process.
 * Call {@link resetPlatformCache} if you swap globals in a test.
 */
export function detectPlatform(): RuntimePlatform {
  if (cachedPlatform) return cachedPlatform;

  const g = globalThis as unknown as Record<string, unknown>;
  const nav = g.navigator as { product?: string; userAgent?: string } | undefined;

  // React Native and Expo both define navigator.product. Check Expo first
  // because Expo Go also reports 'ReactNative' in some versions.
  if (nav?.product === 'Expo') {
    cachedPlatform = 'expo';
  } else if (nav?.product === 'ReactNative') {
    cachedPlatform = 'react-native';
  } else if (typeof g.Deno !== 'undefined') {
    cachedPlatform = 'deno';
  } else if (typeof g.Bun !== 'undefined') {
    cachedPlatform = 'bun';
  } else if (typeof g.process !== 'undefined' && (g.process as { versions?: { node?: string } })?.versions?.node) {
    cachedPlatform = 'node';
  } else if (typeof g.window !== 'undefined' && typeof g.document !== 'undefined') {
    cachedPlatform = 'browser';
  } else if (typeof g.importScripts === 'function') {
    cachedPlatform = 'worker';
  } else {
    cachedPlatform = 'unknown';
  }

  return cachedPlatform;
}

/**
 * Clear the memoised platform detection.
 *
 * Intended for tests that stub `navigator` or `process` between cases.
 */
export function resetPlatformCache(): void {
  cachedPlatform = null;
}

/**
 * `true` when running under React Native or Expo.
 */
export function isReactNative(): boolean {
  const p = detectPlatform();
  return p === 'react-native' || p === 'expo';
}

/**
 * `true` when running in a browser DOM.
 */
export function isBrowser(): boolean {
  return detectPlatform() === 'browser';
}

/**
 * `true` when running under Node.js.
 */
export function isNode(): boolean {
  return detectPlatform() === 'node';
}

/**
 * Report which platform primitives are available without polyfilling them.
 *
 * Useful for surfacing a clear diagnostic to developers when an operation
 * fails because, say, WebCrypto is missing on their RN version.
 */
export function getCapabilities(): PlatformCapabilities {
  const g = globalThis as unknown as Record<string, unknown>;
  const cryptoObj = g.crypto as { subtle?: unknown; getRandomValues?: unknown } | undefined;

  let hasLocalStorage = false;
  try {
    // Touching localStorage can throw in sandboxed iframes and in some RN
    // webview shims, so the probe is guarded.
    hasLocalStorage = typeof g.localStorage !== 'undefined' && g.localStorage !== null;
  } catch {
    hasLocalStorage = false;
  }

  return {
    hasBuffer: typeof g.Buffer !== 'undefined',
    hasCrypto: typeof cryptoObj !== 'undefined' && cryptoObj !== null,
    hasSubtleCrypto: typeof cryptoObj?.subtle !== 'undefined' && cryptoObj?.subtle !== null,
    hasLocalStorage,
    hasProcess: typeof g.process !== 'undefined',
    hasTextCodec: typeof g.TextEncoder !== 'undefined' && typeof g.TextDecoder !== 'undefined',
  };
}

// ── Bytes / encoding helpers ──────────────────────────────────────────────────

const HEX_ALPHABET = '0123456789abcdef';

/**
 * Encode bytes as a lowercase hex string without requiring `Buffer`.
 *
 * `Buffer.from(bytes).toString('hex')` is the Node idiom, but `Buffer` is not
 * a global in React Native's Hermes runtime. This implementation is pure
 * JavaScript and works everywhere.
 */
export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    out += HEX_ALPHABET[byte >> 4] + HEX_ALPHABET[byte & 0x0f];
  }
  return out;
}

/**
 * Decode a hex string into bytes without requiring `Buffer`.
 *
 * Throws on odd-length input or non-hex characters so a malformed key is
 * caught at the call site rather than producing silent garbage.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('hexToBytes: input length must be even');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: invalid hex character at index ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Encode bytes as standard (padded) base64 without requiring `Buffer`.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];

    out += BASE64_ALPHABET[b0 >> 2];
    out += BASE64_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? '=' : BASE64_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? '=' : BASE64_ALPHABET[b2 & 0x3f];
  }
  return out;
}

/**
 * Decode a standard base64 string into bytes without requiring `Buffer`.
 */
export function base64ToBytes(base64: string): Uint8Array {
  const clean = base64.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let outIndex = 0;

  for (let i = 0; i < clean.length; i += 4) {
    const c0 = BASE64_ALPHABET.indexOf(clean[i]);
    const c1 = BASE64_ALPHABET.indexOf(clean[i + 1]);
    const c2 = i + 2 < clean.length ? BASE64_ALPHABET.indexOf(clean[i + 2]) : -1;
    const c3 = i + 3 < clean.length ? BASE64_ALPHABET.indexOf(clean[i + 3]) : -1;

    // The first two sextets of a quad are always present, so a bad value
    // there means genuinely corrupt input. The trailing two may legitimately
    // be absent, which is why they are only validated when present.
    if (c0 < 0 || c1 < 0) {
      throw new Error('base64ToBytes: invalid base64 character');
    }
    if ((i + 2 < clean.length && c2 < 0) || (i + 3 < clean.length && c3 < 0)) {
      throw new Error('base64ToBytes: invalid base64 character');
    }

    if (outIndex < out.length) out[outIndex++] = (c0 << 2) | (c1 >> 4);
    if (c2 >= 0 && outIndex < out.length) out[outIndex++] = ((c1 & 0x0f) << 4) | (c2 >> 2);
    if (c3 >= 0 && outIndex < out.length) out[outIndex++] = ((c2 & 0x03) << 6) | c3;
  }
  return out;
}

/**
 * Encode a string as UTF-8 bytes, falling back to a manual encoder when
 * `TextEncoder` is unavailable (older Hermes builds).
 */
export function stringToBytes(input: string): Uint8Array {
  const g = globalThis as unknown as Record<string, unknown>;
  const Encoder = g.TextEncoder as (new () => { encode(s: string): Uint8Array }) | undefined;
  if (typeof Encoder === 'function') {
    return new Encoder().encode(input);
  }
  return manualUtf8Encode(input);
}

/**
 * Decode UTF-8 bytes into a string, falling back to a manual decoder when
 * `TextDecoder` is unavailable.
 */
export function bytesToString(bytes: Uint8Array): string {
  const g = globalThis as unknown as Record<string, unknown>;
  const Decoder = g.TextDecoder as (new () => { decode(b: Uint8Array): string }) | undefined;
  if (typeof Decoder === 'function') {
    return new Decoder().decode(bytes);
  }
  return manualUtf8Decode(bytes);
}

/**
 * Minimal UTF-8 encoder used only when `TextEncoder` is missing.
 *
 * Handles the full 4-byte range including surrogate pairs, so emoji and other
 * astral-plane characters survive the round trip.
 */
function manualUtf8Encode(input: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < input.length; i++) {
    let codePoint = input.charCodeAt(i);

    if (codePoint >= 0xd800 && codePoint <= 0xdbff && i + 1 < input.length) {
      const low = input.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        codePoint = ((codePoint - 0xd800) << 10) + (low - 0xdc00) + 0x10000;
        i++;
      }
    }

    if (codePoint < 0x80) {
      out.push(codePoint);
    } else if (codePoint < 0x800) {
      out.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      out.push(
        0xe0 | (codePoint >> 12),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f)
      );
    } else {
      out.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f)
      );
    }
  }
  return Uint8Array.from(out);
}

/**
 * Minimal UTF-8 decoder used only when `TextDecoder` is missing.
 */
function manualUtf8Decode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const byte = bytes[i];
    let codePoint: number;

    if (byte < 0x80) {
      codePoint = byte;
      i += 1;
    } else if ((byte & 0xe0) === 0xc0) {
      codePoint = ((byte & 0x1f) << 6) | (bytes[i + 1] & 0x3f);
      i += 2;
    } else if ((byte & 0xf0) === 0xe0) {
      codePoint = ((byte & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f);
      i += 3;
    } else {
      codePoint =
        ((byte & 0x07) << 18) |
        ((bytes[i + 1] & 0x3f) << 12) |
        ((bytes[i + 2] & 0x3f) << 6) |
        (bytes[i + 3] & 0x3f);
      i += 4;
    }

    if (codePoint > 0xffff) {
      const adjusted = codePoint - 0x10000;
      out += String.fromCharCode(0xd800 + (adjusted >> 10), 0xdc00 + (adjusted & 0x3ff));
    } else {
      out += String.fromCharCode(codePoint);
    }
  }
  return out;
}

// ── Randomness and hashing ────────────────────────────────────────────────────

/**
 * Fill a byte array with cryptographically secure random values.
 *
 * Prefers WebCrypto (`crypto.getRandomValues`), which React Native provides on
 * all currently supported versions. When it is missing — some bare-bones
 * Hermes builds — the caller must pass `fallback`, because `Math.random` is
 * not acceptable for key generation and silently downgrading would be a
 * security problem.
 *
 * @param length - number of bytes to produce.
 * @param fallback - CSPRNG to use when WebCrypto is unavailable. Required in
 *   that case; omitting it throws rather than degrading to a weak source.
 */
export function randomBytes(length: number, fallback?: RandomSource): Uint8Array {
  const g = globalThis as unknown as Record<string, unknown>;
  const cryptoObj = g.crypto as { getRandomValues?: (a: Uint8Array) => Uint8Array } | undefined;

  if (typeof cryptoObj?.getRandomValues === 'function') {
    return cryptoObj.getRandomValues(new Uint8Array(length));
  }
  if (fallback) {
    return fallback(length);
  }
  throw new Error(
    'randomBytes: no cryptographically secure random source available. ' +
      'Install expo-crypto or react-native-get-random-values, or pass a fallback.'
  );
}

/**
 * A pluggable source of cryptographically secure random bytes.
 *
 * React Native apps supply this to bridge to a native module such as
 * `react-native-get-random-values` or `expo-crypto`.
 */
export type RandomSource = (length: number) => Uint8Array;

/**
 * SHA-256 over arbitrary bytes.
 *
 * Uses WebCrypto where available. The pure-JS fallback is intentionally not
 * provided: implementing SHA-256 by hand in an SDK would be a liability, and
 * silently substituting a weaker hash is worse than failing loudly. Callers
 * should install a polyfill (`react-native-quick-crypto`,
 * `expo-crypto`) when WebCrypto is absent.
 */
export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const g = globalThis as unknown as Record<string, unknown>;
  const subtle = (g.crypto as { subtle?: SubtleCryptoLike } | undefined)?.subtle;
  if (!subtle) {
    throw new Error(
      'sha256: WebCrypto is unavailable on this platform. ' +
        'Install react-native-quick-crypto or expo-crypto before calling the SDK.'
    );
  }
  const digest = await subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return new Uint8Array(digest);
}

/** Minimal structural type for the WebCrypto `SubtleCrypto` surface we use. */
interface SubtleCryptoLike {
  digest(algorithm: string, data: unknown): Promise<ArrayBuffer>;
}

// ── Network reachability ──────────────────────────────────────────────────────

/**
 * Options for {@link assertNetworkReachable}.
 */
export interface NetworkCheckOptions {
  /** Milliseconds to wait before giving up. Defaults to 10000. */
  timeoutMs?: number;
  /** Endpoint to probe. Defaults to Soroban testnet's `getHealth`. */
  endpoint?: string;
}

/**
 * Perform a reachability probe against a Soroban RPC endpoint.
 *
 * React Native apps frequently run on networks where DNS is slow or captive
 * portals intercept requests, so an explicit preflight before an identity
 * flow is worthwhile. The probe uses `getHealth`, which every Soroban RPC
 * implements and which does not require authentication.
 */
export async function assertNetworkReachable(
  options: NetworkCheckOptions = {}
): Promise<boolean> {
  const { timeoutMs = 10_000, endpoint = 'https://soroban-testnet.stellar.org' } = options;
  const g = globalThis as unknown as Record<string, unknown>;
  const fetchFn = g.fetch as typeof fetch | undefined;
  if (typeof fetchFn !== 'function') {
    throw new Error('assertNetworkReachable: fetch is unavailable on this platform');
  }

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : undefined;
  const timer = controller
    ? setTimeout(() => controller.abort(), timeoutMs)
    : undefined;

  try {
    const response = await fetchFn(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth' }),
      signal: controller?.signal,
    });
    return response.ok;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
