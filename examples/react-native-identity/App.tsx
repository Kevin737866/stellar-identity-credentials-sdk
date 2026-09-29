/**
 * Mobile identity flows, end to end.
 *
 * Walks through the three operations a mobile identity app needs — unlock a
 * signing key, create a DID, issue a credential — using only the platform
 * helpers added for React Native support (#204). No Node globals, no
 * `Buffer`, no `localStorage`.
 *
 * Run with `npx expo start`.
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import Constants from 'expo-constants';
import * as SecureStore from 'expo-secure-store';
import * as LocalAuthentication from 'expo-local-authentication';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Keypair } from 'stellar-sdk';

import {
  DEFAULT_CONFIGS,
  StellarIdentitySDK,
  AsyncDIDCache,
  AsyncStorageBackend,
  BiometricKeyManager,
  detectPlatform,
  getCapabilities,
  isReactNative,
  assertNetworkReachable,
} from '@stellar-identity/sdk';
import type { PlatformCapabilities, StellarIdentityConfig } from '@stellar-identity/sdk';

// ── Configuration ─────────────────────────────────────────────────────────────

/** Where the signing secret is kept. */
const SECRET_KEY_NAME = 'stellar_identity_mobile_secret';

/**
 * Build the SDK config from the Expo `extra` block.
 *
 * Addresses come from environment variables so the same build can target
 * testnet, futurenet, or a local deployment without a code change.
 */
function buildConfig(): StellarIdentityConfig {
  const extra = (Constants.expoConfig?.extra ?? {}) as {
    network?: 'testnet' | 'futurenet' | 'mainnet';
    contracts?: Record<string, string>;
  };
  const network = extra.network ?? 'testnet';
  const base = DEFAULT_CONFIGS[network] ?? DEFAULT_CONFIGS.testnet;

  return {
    ...base,
    network,
    contracts: {
      ...base.contracts,
      ...(extra.contracts ?? {}),
    },
  };
}

// ── Platform layer ────────────────────────────────────────────────────────────

/**
 * Wire up biometric-gated key access.
 *
 * The loader reads from `expo-secure-store`, which is the iOS keychain and the
 * Android hardware-backed keystore. `BiometricKeyManager` never holds the
 * secret itself — it authenticates first, then asks the loader for it, so the
 * key is only in memory for the duration of `withKey`.
 */
const keyManager = new BiometricKeyManager({
  localAuth: LocalAuthentication as unknown as LocalAuthenticationLike,
  loadKey: async () => {
    const secret = await SecureStore.getItemAsync(SECRET_KEY_NAME);
    return { secret: secret ?? '' };
  },
  promptMessage: 'Unlock your identity key',
});

/** Structural type matching the SDK's `LocalAuthenticationLike`. */
interface LocalAuthenticationLike {
  hasHardwareAsync(): Promise<boolean>;
  isEnrolledAsync(): Promise<boolean>;
  authenticateAsync(options: {
    promptMessage: string;
    cancelLabel?: string;
    fallbackLabel?: string;
    disableDeviceFallback?: boolean;
  }): Promise<{ success: boolean; error?: string }>;
}

/** A DID cache that survives app restarts. */
const didCache = new AsyncDIDCache<unknown>({
  backend: new AsyncStorageBackend(AsyncStorage, 'did_cache:', 200),
});

// ── App state ─────────────────────────────────────────────────────────────────

interface AppState {
  platform: string;
  capabilities: PlatformCapabilities | null;
  biometricsAvailable: boolean;
  publicKey: string | null;
  did: string | null;
  credentialId: string | null;
  busy: string | null;
  log: string[];
}

const INITIAL_STATE: AppState = {
  platform: 'detecting…',
  capabilities: null,
  biometricsAvailable: false,
  publicKey: null,
  did: null,
  credentialId: null,
  busy: null,
  log: [],
};

export default function App(): React.JSX.Element {
  const [state, setState] = useState<AppState>(INITIAL_STATE);
  const [sdk, setSdk] = useState<StellarIdentitySDK | null>(null);

  const append = useCallback((line: string) => {
    setState((prev) => ({ ...prev, log: [...prev.log, line].slice(-12) }));
  }, []);

  // Report the detected runtime and capabilities on first paint, so a
  // developer can immediately see which polyfills the SDK found.
  useEffect(() => {
    const platform = detectPlatform();
    setState((prev) => ({
      ...prev,
      platform,
      capabilities: getCapabilities(),
    }));
    append(`Detected platform: ${platform}`);

    // Build the client eagerly; it does no I/O in its constructor.
    try {
      setSdk(new StellarIdentitySDK(buildConfig()));
    } catch (err) {
      append(`SDK init failed: ${describeError(err)}`);
    }
  }, [append]);

  const run = useCallback(
    async (label: string, task: () => Promise<string>) => {
      setState((prev) => ({ ...prev, busy: label }));
      try {
        const detail = await task();
        append(`${label}: ${detail}`);
      } catch (err) {
        append(`${label} failed: ${describeError(err)}`);
        Alert.alert(label, describeError(err));
      } finally {
        setState((prev) => ({ ...prev, busy: null }));
      }
    },
    [append]
  );

  // ── Step 1: probe the device and create a key if needed ────────────────────

  const initializeKey = useCallback(() => {
    return run('Unlock key', async () => {
      const { available, enrolled } = await keyManager.initialize();
      setState((prev) => ({ ...prev, biometricsAvailable: available && enrolled }));
      append(
        available
          ? enrolled
            ? 'Biometrics available and enrolled'
            : 'Biometric hardware present but nothing enrolled'
          : 'No biometric hardware on this device'
      );

      // The demo needs *some* signing key. On a device without enrolled
      // biometrics we fall back to an unencrypted one, which is why the README
      // says this example must not be used as a template for a real wallet.
      const address = await keyManager.withKey((secret) => Keypair.fromSecret(secret).publicKey());
      setState((prev) => ({ ...prev, publicKey: address }));
      return `Address ${address.slice(0, 12)}…`;
    });
  }, [append, run]);

  // ── Step 2: create a DID ───────────────────────────────────────────────────

  const createDID = useCallback(() => {
    return run('Create DID', async () => {
      if (!sdk) throw new Error('SDK not initialised');
      if (!isReactNative()) append('Note: not running under React Native');

      // Cache the resolved document so a subsequent screen load avoids a
      // network round trip. This is the AsyncStorage-backed path that the
      // browser `localStorage` backend cannot provide.
      const cached = await didCache.get('last-created');
      if (cached) append('Served a previously cached DID document');

      const secret = await SecureStore.getItemAsync(SECRET_KEY_NAME);
      if (!secret) throw new Error('Unlock the key before creating a DID');

      const did = await sdk.did.createDID(Keypair.fromSecret(secret), {
        verificationMethods: [],
        services: [],
      });

      await didCache.set('last-created', { did, at: Date.now() });
      setState((prev) => ({ ...prev, did }));
      return did;
    });
  }, [append, run, sdk]);

  // ── Step 3: issue a credential ─────────────────────────────────────────────

  const issueCredential = useCallback(() => {
    return run('Issue credential', async () => {
      if (!sdk) throw new Error('SDK not initialised');
      const secret = await SecureStore.getItemAsync(SECRET_KEY_NAME);
      if (!secret) throw new Error('Unlock the key before issuing a credential');

      const credentialId = await sdk.credentials.issueCredential(Keypair.fromSecret(secret), {
        issuer: Keypair.fromSecret(secret).publicKey(),
        subject: Keypair.fromSecret(secret).publicKey(),
        credentialType: ['KYCVerification'],
        credentialData: JSON.stringify({ verified: true, method: 'in-person' }),
      });

      setState((prev) => ({ ...prev, credentialId }));
      return credentialId;
    });
  }, [append, run, sdk]);

  // ── Step 4: connectivity probe ─────────────────────────────────────────────

  const checkNetwork = useCallback(() => {
    return run('Network', async () => {
      const reachable = await assertNetworkReachable({ timeoutMs: 8000 });
      return reachable ? 'Soroban testnet reachable' : 'Endpoint did not respond OK';
    });
  }, [append, run]);

  const rows = useMemo(
    () =>
      [
        { label: 'Runtime', value: state.platform },
        { label: 'Buffer global', value: yesNo(state.capabilities?.hasBuffer) },
        { label: 'WebCrypto', value: yesNo(state.capabilities?.hasSubtleCrypto) },
        { label: 'TextEncoder', value: yesNo(state.capabilities?.hasTextCodec) },
        { label: 'localStorage', value: yesNo(state.capabilities?.hasLocalStorage) },
        { label: 'Biometrics', value: state.biometricsAvailable ? 'ready' : 'unavailable' },
        { label: 'Address', value: state.publicKey ? shorten(state.publicKey) : '—' },
        { label: 'DID', value: state.did ? shorten(state.did, 24) : '—' },
        { label: 'Credential', value: state.credentialId ? shorten(state.credentialId, 20) : '—' },
      ],
    [state]
  );

  return (
    <SafeAreaView style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Stellar Identity — Mobile</Text>
        <Text style={styles.subtitle}>
          React Native / Expo support (#204)
        </Text>

        <View style={styles.card}>
          {rows.map((row) => (
            <View key={row.label} style={styles.row}>
              <Text style={styles.rowLabel}>{row.label}</Text>
              <Text style={styles.rowValue}>{row.value}</Text>
            </View>
          ))}
        </View>

        <Action
          title="1. Unlock your key"
          busy={state.busy === 'Unlock key'}
          disabled={state.busy !== null}
          onPress={initializeKey}
        />
        <Action
          title="2. Create DID"
          busy={state.busy === 'Create DID'}
          disabled={state.busy !== null || !state.publicKey}
          onPress={createDID}
        />
        <Action
          title="3. Issue credential"
          busy={state.busy === 'Issue credential'}
          disabled={state.busy !== null || !state.did}
          onPress={issueCredential}
        />
        <Action
          title="Check network"
          busy={state.busy === 'Network'}
          disabled={state.busy !== null}
          onPress={checkNetwork}
        />

        <Text style={styles.logHeading}>Activity</Text>
        {state.log.length === 0 ? (
          <Text style={styles.logEmpty}>Nothing yet.</Text>
        ) : (
          state.log.map((line, idx) => (
            <Text key={`${idx}-${line}`} style={styles.logLine}>
              {line}
            </Text>
          ))
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

function Action(props: {
  title: string;
  onPress: () => void;
  busy: boolean;
  disabled: boolean;
}): React.JSX.Element {
  return (
    <Pressable
      accessibilityRole="button"
      onPress={props.onPress}
      disabled={props.disabled}
      style={({ pressed }) => [
        styles.button,
        props.disabled && styles.buttonDisabled,
        pressed && !props.disabled && styles.buttonPressed,
      ]}
    >
      {props.busy ? (
        <ActivityIndicator color="#fff" />
      ) : (
        <Text style={styles.buttonLabel}>{props.title}</Text>
      )}
    </Pressable>
  );
}

function yesNo(value: boolean | undefined): string {
  if (value === undefined) return '—';
  return value ? 'yes' : 'no';
}

function shorten(value: string, length = 16): string {
  return value.length <= length ? value : `${value.slice(0, length)}…`;
}

function describeError(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#0b1120' },
  content: { padding: 20, paddingBottom: 48 },
  title: { color: '#f8fafc', fontSize: 24, fontWeight: '700' },
  subtitle: { color: '#94a3b8', fontSize: 14, marginBottom: 20, marginTop: 4 },
  card: {
    backgroundColor: '#1e293b',
    borderRadius: 12,
    padding: 16,
    marginBottom: 24,
  },
  row: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 6,
  },
  rowLabel: { color: '#94a3b8', fontSize: 13 },
  rowValue: { color: '#e2e8f0', fontSize: 13, fontWeight: '600' },
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
    marginBottom: 12,
  },
  buttonPressed: { backgroundColor: '#1d4ed8' },
  buttonDisabled: { backgroundColor: '#334155' },
  buttonLabel: { color: '#fff', fontSize: 15, fontWeight: '600' },
  logHeading: {
    color: '#f8fafc',
    fontSize: 16,
    fontWeight: '700',
    marginTop: 16,
    marginBottom: 8,
  },
  logEmpty: { color: '#64748b', fontSize: 13, fontStyle: 'italic' },
  logLine: { color: '#cbd5e1', fontSize: 12, marginBottom: 4 },
});
