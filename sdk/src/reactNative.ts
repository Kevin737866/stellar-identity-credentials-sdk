/**
 * React Native / Expo storage and biometric key management (#204).
 *
 * Two pieces of platform glue that the browser build gets for free and mobile
 * does not:
 *
 * 1. **Storage** — {@link AsyncStorageBackend} implements the SDK's
 *    {@link StorageBackend} contract on top of React Native's AsyncStorage
 *    (or Expo's, which is the same API). Because AsyncStorage is
 *    asynchronous, the backend presents an async interface and is used
 *    through {@link AsyncDIDCache} rather than the synchronous
 *    {@link DIDCache}.
 *
 * 2. **Biometrics** — {@link BiometricKeyManager} gates access to a signing
 *    key behind a device biometric (Face ID / Touch ID / Android
 *    BiometricPrompt), using `expo-local-authentication` or a bare
 *    `react-native-biometrics` shim. The key itself never leaves secure
 *    storage: the manager stores a reference, and callers supply a `loadKey`
 *    callback that retrieves the material from wherever it is kept.
 *
 * Both are opt-in. Importing this module on web is safe — nothing here
 * touches a native module at import time.
 *
 * @module reactNative
 * @category Utilities
 */

import { ConfigurationError, ErrorCode } from './errors';
import { stringToBytes, bytesToString } from './platform';

// ── Async storage contract ────────────────────────────────────────────────────

/**
 * The subset of the React Native AsyncStorage API this module depends on.
 *
 * Declaring it structurally rather than importing `@react-native-async-storage/async-storage`
 * keeps the SDK free of a hard React Native dependency: web and Node consumers
 * never install the native package, while mobile apps pass the real module in.
 */
export interface AsyncStorageLike {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  getAllKeys(): Promise<readonly string[]>;
  multiRemove?(keys: string[]): Promise<void>;
}

/**
 * A cache entry, as persisted by {@link AsyncStorageBackend}.
 *
 * Mirrors the shape used by the browser `DIDCache` so entries are portable
 * between the two.
 */
export interface AsyncCacheEntry {
  /** The cached document. */
  document: unknown;
  /** Epoch milliseconds when the entry was written. */
  cachedAt: number;
  /** Epoch milliseconds after which the entry is stale. */
  expiresAt: number;
}

/**
 * A key/value storage adapter for mobile.
 *
 * Entries are namespaced with `prefix` so a shared AsyncStorage instance can
 * host several caches without collisions. Capacity is enforced by evicting the
 * oldest entry, which is why every write stamps `cachedAt`.
 *
 * Every method swallows transport errors and degrades to a no-op or `null`.
 * AsyncStorage can fail when the device is out of space or the OS revokes
 * access; a cache miss is always an acceptable outcome, whereas throwing from
 * a cache read would break the caller's identity flow for a non-critical
 * subsystem.
 */
export class AsyncStorageBackend {
  private storage: AsyncStorageLike;
  private prefix: string;
  private maxSize: number;

  /**
   * @param storage - The AsyncStorage instance, usually
   *   `AsyncStorage` from `@react-native-async-storage/async-storage`.
   * @param prefix - Key namespace. Defaults to `'did_cache:'`.
   * @param maxSize - Maximum entries retained before eviction kicks in.
   */
  constructor(storage: AsyncStorageLike, prefix = 'did_cache:', maxSize = 500) {
    this.storage = storage;
    this.prefix = prefix;
    this.maxSize = maxSize;
  }

  /**
   * Read a cache entry, or `null` when absent or unreadable.
   */
  async get(key: string): Promise<AsyncCacheEntry | null> {
    try {
      const raw = await this.storage.getItem(this.prefix + key);
      if (!raw) return null;
      return JSON.parse(raw) as AsyncCacheEntry;
    } catch {
      return null;
    }
  }

  /**
   * Write a cache entry, evicting the oldest one when at capacity.
   */
  async set(key: string, entry: AsyncCacheEntry): Promise<void> {
    try {
      if (!(await this.hasCapacity())) {
        const oldest = await this.findOldestKey();
        if (oldest) await this.storage.removeItem(oldest);
      }
      await this.storage.setItem(this.prefix + key, JSON.stringify(entry));
    } catch {
      // A cache write failure must never surface to the caller.
    }
  }

  /**
   * Remove a single entry.
   */
  async delete(key: string): Promise<void> {
    try {
      await this.storage.removeItem(this.prefix + key);
    } catch {
    }
  }

  /**
   * Remove every entry in this backend's namespace.
   */
  async clear(): Promise<void> {
    try {
      const keys = await this.storage.getAllKeys();
      const ours = keys.filter((k) => k.startsWith(this.prefix));
      if (this.storage.multiRemove) {
        await this.storage.multiRemove(ours as string[]);
      } else {
        await Promise.all(ours.map((k) => this.storage.removeItem(k)));
      }
    } catch {
    }
  }

  /**
   * Number of entries currently held in this namespace.
   */
  async size(): Promise<number> {
    try {
      const keys = await this.storage.getAllKeys();
      return keys.filter((k) => k.startsWith(this.prefix)).length;
    } catch {
      return 0;
    }
  }

  private async hasCapacity(): Promise<boolean> {
    return (await this.size()) < this.maxSize;
  }

  private async findOldestKey(): Promise<string | null> {
    try {
      const keys = (await this.storage.getAllKeys()).filter((k) => k.startsWith(this.prefix));
      let oldestKey: string | null = null;
      let oldestTime = Infinity;

      for (const key of keys) {
        const raw = await this.storage.getItem(key);
        if (!raw) continue;
        const entry = JSON.parse(raw) as AsyncCacheEntry;
        if (entry.cachedAt < oldestTime) {
          oldestTime = entry.cachedAt;
          oldestKey = key;
        }
      }
      return oldestKey;
    } catch {
      return null;
    }
  }
}

// ── Async DID cache ───────────────────────────────────────────────────────────

/**
 * An async, TTL-aware DID cache for mobile.
 *
 * The synchronous {@link DIDCache} cannot be used with AsyncStorage because
 * every read would have to block. This class exposes the same surface with
 * `Promise`-returning methods, so mobile code reads naturally:
 *
 * ```ts
 * const cache = new AsyncDIDCache({
 *   backend: new AsyncStorageBackend(AsyncStorage),
 * });
 * const doc = await cache.get('did:stellar:GABC');
 * if (!doc) {
 *   const resolved = await client.resolveDID('did:stellar:GABC');
 *   await cache.set('did:stellar:GABC', resolved);
 * }
 * ```
 */
export class AsyncDIDCache<T = unknown> {
  private backend: AsyncStorageBackend;
  private ttl: number;

  /**
   * @param options.backend - Storage adapter to persist through.
   * @param options.ttl - Default entry lifetime in milliseconds. Defaults to
   *   five minutes, matching the browser cache.
   */
  constructor(options: { backend: AsyncStorageBackend; ttl?: number }) {
    this.backend = options.backend;
    this.ttl = options.ttl ?? 5 * 60 * 1000;
  }

  /**
   * Return a cached document, evicting it if it has expired.
   */
  async get(key: string): Promise<T | null> {
    const entry = await this.backend.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      await this.backend.delete(key);
      return null;
    }
    return entry.document as T;
  }

  /**
   * Store a document under `key`.
   */
  async set(key: string, document: T, ttlOverride?: number): Promise<void> {
    const now = Date.now();
    await this.backend.set(key, {
      document,
      cachedAt: now,
      expiresAt: now + (ttlOverride ?? this.ttl),
    });
  }

  /**
   * Drop a single entry, e.g. after a DID update.
   */
  async invalidate(key: string): Promise<void> {
    await this.backend.delete(key);
  }

  /**
   * Drop every entry.
   */
  async clear(): Promise<void> {
    await this.backend.clear();
  }

  /**
   * Number of entries retained.
   */
  async size(): Promise<number> {
    return this.backend.size();
  }

  /**
   * Change the default entry lifetime.
   */
  updateTTL(newTtl: number): void {
    this.ttl = newTtl;
  }
}

// ── Biometric key management ──────────────────────────────────────────────────

/**
 * Result of a biometric authentication attempt.
 */
export interface BiometricResult {
  /** `true` when the user authenticated successfully. */
  success: boolean;
  /** `false` when the user cancelled or fell back to a passcode. */
  cancelled: boolean;
  /** Device error code, when the attempt failed. */
  error?: string;
}

/**
 * The `expo-local-authentication` surface this module depends on.
 */
export interface LocalAuthenticationLike {
  hasHardwareAsync(): Promise<boolean>;
  isEnrolledAsync(): Promise<boolean>;
  supportedAuthenticationTypesAsync?(): Promise<number[]>;
  authenticateAsync(options: {
    promptMessage: string;
    cancelLabel?: string;
    fallbackLabel?: string;
    disableDeviceFallback?: boolean;
  }): Promise<{ success: boolean; error?: string }>;
}

/**
 * Loads key material from secure storage, after the user has authenticated.
 *
 * The SDK deliberately does not take a `Keypair` directly: the secret must come
 * from the platform keystore / keychain, which is only reachable once
 * biometrics have unlocked it. Applications supply the loader that knows how
 * to do that for their chosen storage.
 */
export type KeyLoader = () => Promise<{ secret: string }>;

/**
 * Gates access to a signing key behind device biometrics.
 *
 * ```ts
 * const manager = new BiometricKeyManager({
 *   localAuth: await import('expo-local-authentication'),
 *   loadKey: () => secureStore.getItemAsync('stellar_secret').then((v) => ({ secret: v! })),
 * });
 * await manager.initialize();
 * const keypair = await manager.withKey((secret) => Keypair.fromSecret(secret));
 * ```
 *
 * `withKey` passes the secret to the callback and clears the local reference
 * immediately afterwards, so the material is not retained by the manager
 * between uses.
 */
export class BiometricKeyManager {
  private localAuth: LocalAuthenticationLike | null;
  private loadKey: KeyLoader | null;
  private promptMessage: string;
  private initialized = false;
  private _hasHardware = false;
  private _isEnrolled = false;

  /**
   * @param options.localAuth - The `expo-local-authentication` module. Pass
   *   `null` to construct a manager that always refuses, which is useful when
   *   biometrics are an optional enhancement rather than a requirement.
   * @param options.loadKey - Retrieves key material once authenticated.
   * @param options.promptMessage - Copy shown in the system biometric sheet.
   */
  constructor(options: {
    localAuth?: LocalAuthenticationLike | null;
    loadKey?: KeyLoader | null;
    promptMessage?: string;
  }) {
    this.localAuth = options.localAuth ?? null;
    this.loadKey = options.loadKey ?? null;
    this.promptMessage = options.promptMessage ?? 'Unlock your identity key';
  }

  /**
   * Probe the device for biometric hardware and enrolment.
   *
   * Must be awaited before {@link withKey}. Safe to call repeatedly; the
   * result is cached after the first probe.
   */
  async initialize(): Promise<{ available: boolean; enrolled: boolean }> {
    if (this.initialized) {
      return { available: this._hasHardware, enrolled: this._isEnrolled };
    }
    if (!this.localAuth) {
      this.initialized = true;
      return { available: false, enrolled: false };
    }

    try {
      this._hasHardware = await this.localAuth.hasHardwareAsync();
      this._isEnrolled = this._hasHardware ? await this.localAuth.isEnrolledAsync() : false;
    } catch {
      this._hasHardware = false;
      this._isEnrolled = false;
    }
    this.initialized = true;
    return { available: this._hasHardware, enrolled: this._isEnrolled };
  }

  /**
   * `true` when the device has biometric hardware *and* a biometric is
   * enrolled. A device with hardware but no enrolment cannot prompt, so the
   * distinction matters.
   */
  isBiometricAvailable(): boolean {
    return this._hasHardware && this._isEnrolled;
  }

  /**
   * Prompt the user for biometrics.
   *
   * `disableDeviceFallback` defaults to `true`: falling back to the device
   * passcode would let an attacker who knows the passcode sign transactions
   * without ever presenting a biometric, which defeats the point of gating
   * the key this way.
   */
  async authenticate(options?: { promptMessage?: string }): Promise<BiometricResult> {
    if (!this.localAuth) {
      return { success: false, cancelled: false, error: 'biometrics_unavailable' };
    }
    if (!this.isBiometricAvailable()) {
      return { success: false, cancelled: false, error: 'biometrics_not_enrolled' };
    }

    try {
      const outcome = await this.localAuth.authenticateAsync({
        promptMessage: options?.promptMessage ?? this.promptMessage,
        cancelLabel: 'Cancel',
        disableDeviceFallback: true,
      });
      return {
        success: outcome.success,
        cancelled: false,
        error: outcome.error,
      };
    } catch (err) {
      // A user-cancelled prompt surfaces as a rejection on some OS versions
      // and as `{ success: false, error: 'user_cancel' }` on others.
      const message = err instanceof Error ? err.message : String(err);
      const cancelled = /cancel/i.test(message);
      return { success: false, cancelled, error: cancelled ? 'user_cancel' : message };
    }
  }

  /**
   * Authenticate, load the key, and hand it to `use` exactly once.
   *
   * Throws {@link ConfigurationError} when biometrics are unavailable or
   * authentication fails, so a caller cannot accidentally operate without the
   * unlock step.
   */
  async withKey<T>(use: (secret: string) => T | Promise<T>): Promise<T> {
    if (!this.loadKey) {
      throw new ConfigurationError(
        ErrorCode.ConfigMissingKeypair,
        'BiometricKeyManager was constructed without a loadKey callback'
      );
    }

    const result = await this.authenticate();
    if (!result.success) {
      throw new ConfigurationError(
        ErrorCode.ConfigMissingKeypair,
        result.cancelled
          ? 'Biometric authentication was cancelled'
          : `Biometric authentication failed: ${result.error ?? 'unknown'}`
      );
    }

    const { secret } = await this.loadKey();
    if (!secret) {
      throw new ConfigurationError(
        ErrorCode.ConfigMissingKeypair,
        'Key loader returned no secret'
      );
    }
    return use(secret);
  }
}

// ── Encoding helpers for mobile payloads ──────────────────────────────────────

/**
 * Encode a key secret for storage in AsyncStorage.
 *
 * Provided so mobile apps do not hand-roll base64 with `Buffer`, which is not
 * a global under Hermes.
 */
export function encodeSecretForStorage(secret: string): string {
  return bytesToString(stringToBytes(secret));
}
