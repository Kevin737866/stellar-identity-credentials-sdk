import type { Meta, StoryObj } from '@storybook/react';
import { userEvent, within } from '@storybook/test';
import { DIDManager } from './DIDManager';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const DID = `did:stellar:${ADDRESS}`;

const didDocument = {
  id: DID,
  controller: ADDRESS,
  created: Date.now() - 1000 * 60 * 60 * 24 * 30,
  updated: Date.now() - 1000 * 60 * 60 * 24 * 2,
  verificationMethod: [
    {
      id: `${DID}#key-1`,
      type: 'Ed25519VerificationKey2018',
      controller: ADDRESS,
      publicKey: 'z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP',
    },
    {
      id: `${DID}#key-2`,
      type: 'Ed25519VerificationKey2018',
      controller: ADDRESS,
      publicKey: 'z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
    },
  ],
  service: [
    {
      id: `${DID}#identity-hub`,
      type: 'IdentityHub',
      endpoint: 'https://hub.example.com/dids/stellar',
    },
  ],
};

// ─── Mock SDK builders ────────────────────────────────────────────────────────

function makeSdk(overrides: Record<string, unknown> = {}) {
  const did = {
    generateDID: () => DID,
    resolveDID: () => Promise.resolve({ didDocument }),
    createDID: () => Promise.resolve(DID),
    updateDID: () => Promise.resolve(),
    deactivateDID: () => Promise.resolve(),
    ...overrides,
  };
  return { did };
}

const mockKeypair = { publicKey: () => ADDRESS } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof DIDManager> = {
  title: 'Components/DIDManager',
  component: DIDManager,
  tags: ['autodocs'],
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Create, resolve, update and deactivate a Stellar DID. The component drives all of its ' +
          'state from the injected SDK, so every visual state can be reproduced with a mock client.',
      },
    },
  },
  argTypes: {
    address: { control: 'text' },
    keypair: { control: false },
    sdk: { control: false },
  },
  args: {
    sdk: makeSdk(),
    address: ADDRESS,
    keypair: mockKeypair,
  },
};

export default meta;
type Story = StoryObj<typeof DIDManager>;

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: a DID already exists, so the document and its keys are displayed. */
export const Default: Story = {};

/** Loading: `resolveDID` is still in flight. */
export const Loading: Story = {
  args: {
    sdk: makeSdk({ resolveDID: () => new Promise(() => {}) }),
  },
};

/** Empty: no DID has been registered for this address yet. */
export const NoDID: Story = {
  args: {
    sdk: makeSdk({ resolveDID: () => Promise.reject(new Error('DID not found')) }),
  },
};

/** A DID with no verification methods or services attached. */
export const MinimalDocument: Story = {
  args: {
    sdk: makeSdk({
      resolveDID: () =>
        Promise.resolve({
          didDocument: { ...didDocument, verificationMethod: [], service: [] },
        }),
    }),
  },
};

/**
 * Error: updating the document fails, so the destructive alert is rendered at the
 * top of the component.
 */
export const UpdateError: Story = {
  args: {
    sdk: makeSdk({ updateDID: () => Promise.reject(new Error('Failed to update DID')) }),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole('button', { name: /update/i }));
  },
};

/** Actions are disabled while a document load is in flight. */
export const ActionsBusy: Story = {
  args: {
    sdk: makeSdk({ updateDID: () => new Promise(() => {}) }),
  },
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.click(canvas.getByRole('button', { name: /update/i }));
  },
};
