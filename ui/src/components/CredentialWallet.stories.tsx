import type { Meta, StoryObj } from '@storybook/react';
import { CredentialWallet } from './CredentialWallet';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const ISSUER = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';

const now = Date.now();

const validCredential = {
  id: 'cred-kyc-001',
  subject: ADDRESS,
  issuer: ISSUER,
  type: ['VerifiableCredential', 'KYCCredential'],
  credentialType: ['KYCCredential'],
  credentialData: { name: 'Ada Lovelace', nationality: 'GB', verified: true },
  issuanceDate: now - 1000 * 60 * 60 * 24 * 10,
  expirationDate: now + 1000 * 60 * 60 * 24 * 355,
  proof: { type: 'Ed25519Signature2018', created: now - 1000 * 60 * 60 * 24 * 10 },
};

const expiredCredential = {
  ...validCredential,
  id: 'cred-age-002',
  type: ['VerifiableCredential', 'AgeCredential'],
  credentialType: ['AgeCredential'],
  credentialData: { over18: true },
  issuanceDate: now - 1000 * 60 * 60 * 24 * 400,
  expirationDate: now - 1000 * 60 * 60 * 24 * 35,
};

const revokedCredential = {
  ...validCredential,
  id: 'cred-addr-003',
  type: ['VerifiableCredential', 'AddressCredential'],
  credentialType: ['AddressCredential'],
  credentialData: { country: 'GB', city: 'London' },
};

const verificationByCredential: Record<string, Record<string, boolean>> = {
  'cred-kyc-001': { valid: true, revoked: false, expired: false },
  'cred-age-002': { valid: false, revoked: false, expired: true },
  'cred-addr-003': { valid: false, revoked: true, expired: false },
};

const credentialById: Record<string, unknown> = {
  'cred-kyc-001': validCredential,
  'cred-age-002': expiredCredential,
  'cred-addr-003': revokedCredential,
};

// ─── Mock SDK builders ────────────────────────────────────────────────────────

function makeSdk(ids: string[] = Object.keys(credentialById), overrides: Record<string, unknown> = {}) {
  return {
    credentials: {
      getSubjectCredentials: () => Promise.resolve(ids),
      getCredential: (id: string) => Promise.resolve(credentialById[id]),
      verifyCredential: (id: string) => Promise.resolve(verificationByCredential[id]),
      issueCredential: () => Promise.resolve('cred-new-004'),
      revokeCredential: () => Promise.resolve(),
      createPresentation: () => Promise.resolve({ verifiablePresentation: {} }),
      ...overrides,
    },
  };
}

const mockKeypair = { publicKey: () => ADDRESS } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof CredentialWallet> = {
  title: 'Components/CredentialWallet',
  component: CredentialWallet,
  tags: ['autodocs'],
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Lists the verifiable credentials held by an address, together with the result of ' +
          'verifying each one (valid, expired or revoked).',
      },
    },
  },
  argTypes: {
    address: { control: 'text' },
    sdk: { control: false },
    keypair: { control: false },
  },
  args: {
    sdk: makeSdk(),
    address: ADDRESS,
    keypair: mockKeypair,
  },
};

export default meta;
type Story = StoryObj<typeof CredentialWallet>;

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: one valid, one expired and one revoked credential. */
export const Default: Story = {};

/** A single healthy credential. */
export const SingleValidCredential: Story = {
  args: { sdk: makeSdk(['cred-kyc-001']) },
};

/** Expired credential: the status badge degrades to `Expired`. */
export const ExpiredCredential: Story = {
  args: { sdk: makeSdk(['cred-age-002']) },
};

/** Revoked credential: sharing is disabled and revocation is offered. */
export const RevokedCredential: Story = {
  args: { sdk: makeSdk(['cred-addr-003']) },
};

/** Loading: the credential list is still being fetched. */
export const Loading: Story = {
  args: {
    sdk: makeSdk([], { getSubjectCredentials: () => new Promise(() => {}) }),
  },
};

/** Empty: the address holds no credentials yet. */
export const Empty: Story = {
  args: { sdk: makeSdk([]) },
};

/** Error: loading the credential list fails. */
export const ErrorState: Story = {
  args: {
    sdk: makeSdk([], {
      getSubjectCredentials: () => Promise.reject(new Error('Failed to load credentials')),
    }),
  },
};
