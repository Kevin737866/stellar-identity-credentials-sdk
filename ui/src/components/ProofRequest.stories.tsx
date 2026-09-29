import type { Meta, StoryObj } from '@storybook/react';
import { userEvent, within } from '@storybook/test';
import { ProofRequest } from './ProofRequest';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const now = Date.now();

const validProof = {
  proofId: 'proof-age-001',
  circuitId: 'age_verification',
  publicInputs: ['18'],
  proofBytes: '0x1a2b3c4d5e6f',
  verifierAddress: ADDRESS,
  createdAt: now - 1000 * 60 * 60 * 24 * 3,
  expiresAt: now + 1000 * 60 * 60 * 24 * 27,
  metadata: { type: 'age_over', jurisdiction: 'GB' },
};

const invalidProof = {
  ...validProof,
  proofId: 'proof-income-002',
  circuitId: 'income_verification',
  publicInputs: ['50000'],
  createdAt: now - 1000 * 60 * 60 * 24 * 12,
  metadata: { type: 'income_over' },
};

const circuits = [
  {
    circuitId: 'age_verification',
    name: 'Age Verification',
    description: 'Prove you are over a threshold without revealing your date of birth.',
    publicInputCount: 1,
    privateInputCount: 2,
    active: true,
  },
  {
    circuitId: 'income_verification',
    name: 'Income Verification',
    description: 'Prove a minimum income without revealing the exact amount.',
    publicInputCount: 1,
    privateInputCount: 3,
    active: true,
  },
  {
    circuitId: 'legacy_residency',
    name: 'Residency (deprecated)',
    description: 'Superseded by the address credential circuit.',
    publicInputCount: 2,
    privateInputCount: 1,
    active: false,
  },
];

// ─── Mock SDK builders ────────────────────────────────────────────────────────

interface SdkOptions {
  proofIds?: string[];
  verification?: Record<string, { valid: boolean }>;
  proofById?: Record<string, unknown>;
  overrides?: Record<string, unknown>;
}

function makeSdk({
  proofIds = [validProof.proofId, invalidProof.proofId],
  verification = {
    [validProof.proofId]: { valid: true },
    [invalidProof.proofId]: { valid: false },
  },
  proofById = { [validProof.proofId]: validProof, [invalidProof.proofId]: invalidProof },
  overrides = {},
}: SdkOptions = {}) {
  return {
    zkProofs: {
      getCircuitProofs: () => Promise.resolve(proofIds),
      getProof: (id: string) => Promise.resolve(proofById[id]),
      verifyProof: (id: string) => Promise.resolve(verification[id]),
      getActiveCircuits: () => Promise.resolve(circuits.map((c) => c.circuitId)),
      getCircuit: (id: string) => Promise.resolve(circuits.find((c) => c.circuitId === id)),
      submitProof: () => Promise.resolve('proof-new-003'),
      generateCommitment: () => '0xcommitment',
      createAgeProof: () => Promise.resolve('proof-age-004'),
      createIncomeProof: () => Promise.resolve('proof-income-005'),
      ...overrides,
    },
  };
}

const mockKeypair = { publicKey: () => ADDRESS } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof ProofRequest> = {
  title: 'Components/ProofRequest',
  component: ProofRequest,
  tags: ['autodocs'],
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Create and inspect zero-knowledge proofs. Opens on the quick-action shortcuts; the ' +
          '"My Proofs" and "Available Circuits" tabs list submitted proofs and registered circuits.',
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
type Story = StoryObj<typeof ProofRequest>;

const openTab = (name: RegExp) => async ({ canvasElement }: { canvasElement: HTMLElement }) => {
  const canvas = within(canvasElement);
  await userEvent.click(canvas.getByRole('tab', { name }));
};

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: the quick-action shortcuts shown on first render. */
export const Default: Story = {};

/** The proof list, mixing verified and unverified proofs. */
export const MyProofs: Story = {
  play: openTab(/my proofs/i),
};

/** A single proof whose verification has failed. */
export const InvalidProof: Story = {
  args: {
    sdk: makeSdk({
      proofIds: [invalidProof.proofId],
      verification: { [invalidProof.proofId]: { valid: false } },
      proofById: { [invalidProof.proofId]: invalidProof },
    }),
  },
  play: openTab(/my proofs/i),
};

/** The registered circuits, including one inactive circuit. */
export const AvailableCircuits: Story = {
  play: openTab(/available circuits/i),
};

/** Loading: proofs are still being fetched. */
export const Loading: Story = {
  args: {
    sdk: makeSdk({ overrides: { getCircuitProofs: () => new Promise(() => {}) } }),
  },
};

/** Empty: no proofs have been created for this address. */
export const Empty: Story = {
  args: { sdk: makeSdk({ proofIds: [] }) },
  play: openTab(/my proofs/i),
};

/** Error: the proof list request fails. */
export const ErrorState: Story = {
  args: {
    sdk: makeSdk({
      overrides: { getCircuitProofs: () => Promise.reject(new Error('Failed to load proofs')) },
    }),
  },
};
