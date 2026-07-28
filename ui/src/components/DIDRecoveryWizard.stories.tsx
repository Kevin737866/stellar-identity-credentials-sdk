import type { Meta, StoryObj } from '@storybook/react';
import { DIDRecoveryWizard } from '../DIDRecoveryWizard';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const socialConfig = {
  method: 'social' as const,
  threshold: 3,
  total: 5,
  guardians: [
    { address: 'GA1111111111111111111111111111111111111111111111111111111111', approved: true },
    { address: 'GA2222222222222222222222222222222222222222222222222222222222', approved: true },
    { address: 'GA3333333333333333333333333333333333333333333333333333333333', approved: false },
    { address: 'GA4444444444444444444444444444444444444444444444444444444444', approved: false },
    { address: 'GA5555555555555555555555555555555555555555555555555555555555', approved: false },
  ],
};

const multisigConfig = {
  method: 'multisig' as const,
  threshold: 2,
  total: 3,
  guardians: [
    { address: 'GA6666666666666666666666666666666666666666666666666666666666', approved: false },
    { address: 'GA7777777777777777777777777777777777777777777777777777777777', approved: false },
    { address: 'GA8888888888888888888888888888888888888888888888888888888888', approved: false },
  ],
};

// ─── Mock SDK builders ────────────────────────────────────────────────────────

function makeSdk(overrides: Partial<{
  resolveDID: () => unknown;
  getRecoveryConfig: () => unknown;
  submitApproval: () => unknown;
  submitRecoveryKey: () => unknown;
  executeRecovery: () => unknown;
}> = {}) {
  return {
    did: {
      resolveDID: overrides.resolveDID ?? (() =>
        Promise.resolve({ didDocument: { id: 'did:stellar:GABCDE' } })
      ),
      getRecoveryConfig: overrides.getRecoveryConfig ?? (() =>
        Promise.resolve(socialConfig)
      ),
      submitApproval: overrides.submitApproval ?? (() => Promise.resolve()),
      submitRecoveryKey: overrides.submitRecoveryKey ?? (() => Promise.resolve()),
      executeRecovery: overrides.executeRecovery ?? (() =>
        Promise.resolve('did:stellar:GABCDE')
      ),
    },
  };
}

const mockKeypair = { publicKey: () => 'GABCDE' } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof DIDRecoveryWizard> = {
  title: 'Components/DIDRecoveryWizard',
  component: DIDRecoveryWizard,
  tags: ['autodocs'],
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'A four-step wizard that guides users through recovering access to their DID using social recovery, multi-sig recovery, or a pre-configured recovery key.',
      },
    },
  },
  argTypes: {
    did: { control: 'text' },
    onSuccess: { action: 'onSuccess' },
    onCancel: { action: 'onCancel' },
  },
};

export default meta;
type Story = StoryObj<typeof DIDRecoveryWizard>;

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: user must enter a DID. Recovery config uses social recovery (3-of-5). */
export const Default: Story = {
  args: {
    sdk: makeSdk(),
    keypair: mockKeypair,
  },
};

/** DID is pre-filled — e.g. launched from a wallet with a known DID. */
export const WithPrefilledDID: Story = {
  args: {
    sdk: makeSdk(),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};

/** Social recovery with 3-of-5 guardians; 2 already approved. */
export const SocialRecovery: Story = {
  args: {
    sdk: makeSdk({ getRecoveryConfig: () => Promise.resolve(socialConfig) }),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};

/** Multi-sig recovery with 2-of-3 required. */
export const MultisigRecovery: Story = {
  args: {
    sdk: makeSdk({ getRecoveryConfig: () => Promise.resolve(multisigConfig) }),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};

/** Recovery key flow. */
export const RecoveryKeyFlow: Story = {
  args: {
    sdk: makeSdk({
      getRecoveryConfig: () =>
        Promise.resolve({ method: 'recovery-key' as const, threshold: 1, total: 1 }),
    }),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};

/** DID not found — shows error on Step 1. */
export const DIDNotFound: Story = {
  args: {
    sdk: makeSdk({
      resolveDID: () => Promise.reject(new Error('DID not found')),
    }),
    keypair: mockKeypair,
    did: 'did:stellar:DOESNOTEXIST',
  },
};

/** Recovery not configured for this DID. */
export const RecoveryNotConfigured: Story = {
  args: {
    sdk: makeSdk({
      getRecoveryConfig: () => Promise.resolve(null),
    }),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};

/** Execution fails — insufficient approvals or contract error. */
export const InsufficientApprovals: Story = {
  args: {
    sdk: makeSdk({
      executeRecovery: () =>
        Promise.reject(new Error('Insufficient approvals: 2 of 3 required')),
    }),
    keypair: mockKeypair,
    did: 'did:stellar:GABCDE123456',
  },
};
