/**
 * Storybook-only stand-in for `@stellar-identity/sdk`.
 *
 * The UI components are rendered in isolation in Storybook, so the chain SDK is
 * aliased to this module (see `.storybook/main.ts`) instead of pulling in network
 * clients. Stories always inject their own mock SDK instance through the `sdk`
 * prop, so nothing here performs I/O — it only needs to satisfy module imports.
 */

export interface StellarIdentityConfig {
  network: 'mainnet' | 'testnet' | 'futurenet';
  [key: string]: unknown;
}

class NotAvailableInStorybook {
  constructor(..._args: unknown[]) {
    // no-op: Storybook renders components against injected mock SDKs
  }
}

export class StellarIdentitySDK extends NotAvailableInStorybook {}
export class DIDClient extends NotAvailableInStorybook {}
export class CredentialClient extends NotAvailableInStorybook {}
export class ZKProofsClient extends NotAvailableInStorybook {}
export class ReputationClient extends NotAvailableInStorybook {}
export class ComplianceClient extends NotAvailableInStorybook {}

export const DEFAULT_CONFIGS = {
  mainnet: { network: 'mainnet' } as StellarIdentityConfig,
  testnet: { network: 'testnet' } as StellarIdentityConfig,
  futurenet: { network: 'futurenet' } as StellarIdentityConfig,
};

export default {
  StellarIdentitySDK,
  DIDClient,
  CredentialClient,
  ZKProofsClient,
  ReputationClient,
  ComplianceClient,
  DEFAULT_CONFIGS,
};
