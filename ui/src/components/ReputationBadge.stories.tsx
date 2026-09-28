import type { Meta, StoryObj } from '@storybook/react';
import { userEvent, within } from '@storybook/test';
import { ReputationBadge } from './ReputationBadge';

// ─── Shared mock data ─────────────────────────────────────────────────────────

const ADDRESS = 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5';
const now = Date.now();

const factors = {
  transactionCount: 142,
  successRate: 0.982,
  credentialCount: 4,
  accountAge: 210,
};

function makeScore(score: number, trend: 'up' | 'down' | 'stable' = 'up') {
  const history =
    trend === 'up' ? [58, 63, 69, 74, score] : trend === 'down' ? [92, 88, 83, 79, score] : [74, 74, 75, 74, score];

  return {
    score,
    percentile: Math.min(99, Math.max(5, score - 3)),
    lastUpdated: now - 1000 * 60 * 60 * 6,
    factors,
    history,
  };
}

// ─── Mock SDK builders ────────────────────────────────────────────────────────

function makeSdk(
  result: unknown = makeScore(82),
  trend: 'up' | 'down' | 'stable' = 'up'
) {
  return {
    reputation: {
      getReputationAnalysis: () => Promise.resolve(result),
      calculateReputationTrend: () => ({
        trend,
        change: trend === 'up' ? 8.2 : trend === 'down' ? -6.4 : 0,
        percentage: trend === 'up' ? 11.1 : trend === 'down' ? -7.8 : 0,
      }),
    },
  };
}

const mockKeypair = { publicKey: () => ADDRESS } as any;

// ─── Meta ─────────────────────────────────────────────────────────────────────

const meta: Meta<typeof ReputationBadge> = {
  title: 'Components/ReputationBadge',
  component: ReputationBadge,
  tags: ['autodocs'],
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'Renders the on-chain reputation score, the tier it falls into, the trend since the ' +
          'previous reading and the factors contributing to the score.',
      },
    },
  },
  argTypes: {
    address: { control: 'text' },
    size: { control: 'inline-radio', options: ['sm', 'md', 'lg'] },
    sdk: { control: false },
    keypair: { control: false },
  },
  args: {
    sdk: makeSdk(),
    address: ADDRESS,
    keypair: mockKeypair,
    size: 'md',
  },
};

export default meta;
type Story = StoryObj<typeof ReputationBadge>;

// ─── Stories ──────────────────────────────────────────────────────────────────

/** Default: a Gold tier score (75–89) trending upwards. */
export const Default: Story = {};

/** Platinum tier (score >= 90). */
export const Platinum: Story = {
  args: { sdk: makeSdk(makeScore(96, 'stable'), 'stable') },
};

/** Silver tier (50–74). */
export const Silver: Story = {
  args: { sdk: makeSdk(makeScore(61, 'stable'), 'stable') },
};

/** Bronze tier (25–49). */
export const Bronze: Story = {
  args: { sdk: makeSdk(makeScore(31, 'down'), 'down') },
};

/** Unranked (score < 25) — shows the fallback tier styling. */
export const Unranked: Story = {
  args: { sdk: makeSdk(makeScore(8, 'down'), 'down') },
};

/** Declining reputation, which changes the trend indicator and the insights list. */
export const Declining: Story = {
  args: { sdk: makeSdk(makeScore(58, 'down'), 'down') },
};

/** Small variant, suited to sidebars. */
export const SizeSmall: Story = {
  args: { size: 'sm' },
};

/** Large variant, suited to a full-width dashboard panel. */
export const SizeLarge: Story = {
  args: { size: 'lg' },
};

/** Loading: the profile skeleton is shown while the score is fetched. */
export const Loading: Story = {
  args: {
    sdk: {
      reputation: {
        getReputationAnalysis: () => new Promise(() => {}),
        calculateReputationTrend: () => ({ trend: 'stable', change: 0, percentage: 0 }),
      },
    },
  },
};

/** Empty: the address has no reputation history yet. */
export const NoData: Story = {
  args: { sdk: makeSdk(null) },
};

/** Error: the reputation lookup fails. */
export const ErrorState: Story = {
  args: {
    sdk: {
      reputation: {
        getReputationAnalysis: () => Promise.reject(new Error('Failed to load reputation data')),
        calculateReputationTrend: () => ({ trend: 'stable', change: 0, percentage: 0 }),
      },
    },
  },
};

/** The tier tooltip, which explains how the current score was reached. */
export const TierTooltip: Story = {
  play: async ({ canvasElement }) => {
    const canvas = within(canvasElement);
    await userEvent.hover(canvas.getAllByText('Gold')[0]);
  },
};
