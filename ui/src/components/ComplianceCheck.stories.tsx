import type { Meta, StoryObj } from '@storybook/react';
import { ComplianceCheck } from './ComplianceCheck';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const now = Date.now();

const clearedResult = {
  status: 'cleared' as const,
  riskScore: 12,
  sanctionsLists: [] as string[],
  lastChecked: now,
  complianceScore: 94,
  totalCredentials: 4,
  validCredentials: 4,
  recommendations: [
    'Keep credentials up to date to preserve your compliance score.',
    'Renew your KYC credential before it expires.',
  ],
};

const flaggedResult = {
  ...clearedResult,
  status: 'flagged' as const,
  riskScore: 64,
  sanctionsLists: ['PEP-Screening'],
  complianceScore: 61,
  validCredentials: 2,
  recommendations: [
    'Provide an additional proof of address.',
    'One credential expires within 30 days.',
  ],
};

const blockedResult = {
  ...clearedResult,
  status: 'blocked' as const,
  riskScore: 91,
  sanctionsLists: ['OFAC-SDN', 'EU-Consolidated'],
  complianceScore: 18,
  totalCredentials: 1,
  validCredentials: 0,
  recommendations: ['Contact your issuer to resolve the sanctions match.'],
};

// ─── Mock SDK builders ────────────────────────────────────────────────────────

function makeSdk(result: unknown = clearedResult, overrides: Record<string, unknown> = {}) {
  return {
    performComplianceCheck: () => Promise.resolve(result),
    did: {
      validateDIDFormat: (did: string) => /^did:stellar:G[A-Z0-9]{20,}$/.test(did),
    },
    ...overrides,
  };
}

const mockKeypair = { publicKey: () => ADDRESS } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof ComplianceCheck> = {
  title: 'Components/ComplianceCheck',
  component: ComplianceCheck,
  tags: ['autodocs'],
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Screens a Stellar address for sanctions exposure and summarises the compliance posture ' +
          'of the credentials held by that address.',
      },
    },
  },
  argTypes: {
    address: { control: 'text' },
    disabled: { control: 'boolean' },
    sdk: { control: false },
    keypair: { control: false },
  },
  args: {
    sdk: makeSdk(),
    address: ADDRESS,
    keypair: mockKeypair,
    disabled: false,
  },
};

export default meta;
type Story = StoryObj<typeof ComplianceCheck>;

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: the address clears screening with a low risk score. */
export const Default: Story = {};

/** Flagged: a PEP screening hit raises the risk score into the medium band. */
export const Flagged: Story = {
  args: { sdk: makeSdk(flaggedResult) },
};

/** Blocked: sanctions matches push the address into the high-risk band. */
export const Blocked: Story = {
  args: { sdk: makeSdk(blockedResult) },
};

/** Loading: the screening request is still in flight. */
export const Loading: Story = {
  args: {
    sdk: makeSdk(undefined, { performComplianceCheck: () => new Promise(() => {}) }),
  },
};

/** Error: the screening request fails. */
export const ErrorState: Story = {
  args: {
    sdk: makeSdk(undefined, {
      performComplianceCheck: () => Promise.reject(new Error('Compliance provider unavailable')),
    }),
  },
};

/** Disabled: the address field and actions are locked. */
export const Disabled: Story = {
  args: { disabled: true },
};
