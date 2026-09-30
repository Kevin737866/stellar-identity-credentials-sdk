import type { ExpoConfig, ConfigContext } from 'expo/config';

/**
 * Expo app configuration.
 *
 * The SDK contract addresses default to the testnet deployment. To point this
 * example at a different network, change `EXTRA_NETWORK` and supply matching
 * addresses in the extra fields below.
 */
export default ({ config }: ConfigContext): ExpoConfig => ({
  ...config,
  name: 'Stellar Identity Mobile',
  slug: 'stellar-identity-react-native-example',
  version: '0.1.0',
  orientation: 'portrait',
  userInterfaceStyle: 'automatic',
  newArchEnabled: false,
  ios: {
    supportsTablet: true,
    bundleIdentifier: 'org.stellaridentity.mobileexample',
    // Face ID usage copy, required before iOS will prompt.
    infoPlist: {
      NSFaceIDUsageDescription:
        'Your biometric unlocks the key that signs your identity transactions.',
    },
  },
  android: {
    package: 'org.stellaridentity.mobileexample',
    permissions: ['USE_BIOMETRIC'],
  },
  extra: {
    network: process.env.EXTRA_NETWORK ?? 'testnet',
    contracts: {
      didRegistry: process.env.EXTRA_DID_REGISTRY ?? '',
      credentialIssuer: process.env.EXTRA_CREDENTIAL_ISSUER ?? '',
      reputationScore: process.env.EXTRA_REPUTATION_SCORE ?? '',
      zkAttestation: process.env.EXTRA_ZK_ATTESTATION ?? '',
      complianceFilter: process.env.EXTRA_COMPLIANCE_FILTER ?? '',
      schemaRegistry: process.env.EXTRA_SCHEMA_REGISTRY ?? '',
    },
  },
});
