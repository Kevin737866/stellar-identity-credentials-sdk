# React Native / Expo mobile identity example (#204)

Demonstrates the mobile platform support added in
[`sdk/src/platform.ts`](../../sdk/src/platform.ts) and
[`sdk/src/reactNative.ts`](../../sdk/src/reactNative.ts):

- runtime detection across React Native, Expo, browser, and Node
- cross-platform encoding that does not rely on the Node-only `Buffer` global
- an `AsyncStorage`-backed DID document cache
- biometric-gated access to a signing key
- a full mobile identity flow: create a DID, issue a credential, verify it

## Running it

```bash
cd examples/react-native-identity
npm install
npx expo start
```

Scan the QR code with Expo Go, or run on a simulator with `i` / `a`.

The app talks to **Soroban testnet**, so it works without any local contract
deployment — but the contract addresses in `app.config.ts` must point at
deployments that exist on the network you select. Testnet addresses ship as
defaults.

## Native dependencies

Three optional native modules are used. Each is loaded lazily so the app still
runs if one is missing, reporting reduced capability instead of crashing.

| Module | Used for | Without it |
| --- | --- | --- |
| `expo-secure-store` | storing the signing secret | falls back to AsyncStorage; **not** recommended for production |
| `expo-local-authentication` | Face ID / Touch ID prompt | key access is refused; use `signWithoutBiometrics` for the demo flow |
| `@react-native-async-storage/async-storage` | DID document cache | falls back to the in-memory cache |

Install them with:

```bash
npx expo install expo-secure-store expo-local-authentication \
  @react-native-async-storage/async-storage
```

## What to look at

1. **Startup diagnostics** — the header reports the detected runtime and which
   platform capabilities are present, so you can see exactly which polyfills the
   SDK found.
2. **Unlock your key** — prompts for biometrics, then shows the public address.
   On a simulator without enrolled biometrics this reports
   `biometrics_not_enrolled`, which is the expected result.
3. **Create DID** — issues a `did:stellar:` identifier through the SDK and
   caches the resolved document in AsyncStorage.
4. **Issue credential** — issues a verifiable credential, exercising the
   XDR-encoding paths that previously assumed a Node `Buffer`.

## Security notes

The example stores the signing secret in `expo-secure-store` when available,
which on iOS is the keychain and on Android is the hardware-backed keystore.
The in-memory fallback exists purely so the demo runs unconfigured — it must
not be used in a real wallet, since AsyncStorage is plain text and survives
app restarts.
