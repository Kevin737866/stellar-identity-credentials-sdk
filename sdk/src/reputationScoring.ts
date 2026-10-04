import {
  DecayOptions,
  DecayedReputationResult,
  ReputationCategoryScores,
  ReputationCategoryWeights,
  ReputationCategoryBreakdown,
  ReputationEvent,
  ReputationTier,
} from './types';

const DEFAULT_CATEGORY_WEIGHTS: ReputationCategoryWeights = {
  transaction_reliability: 0.4,
  credential_trustworthiness: 0.3,
  community_trust: 0.2,
  activity_volume: 0.1,
};

/** Computes a normalized aggregate from configurable category weights. */
export function aggregateReputationCategories(
  scores: ReputationCategoryScores,
  weights: ReputationCategoryWeights = DEFAULT_CATEGORY_WEIGHTS,
): number {
  const categories = Object.keys(DEFAULT_CATEGORY_WEIGHTS) as Array<keyof ReputationCategoryScores>;
  for (const category of categories) {
    if (!Number.isFinite(scores[category]) || scores[category] < 0 || scores[category] > 1000) {
      throw new RangeError(`${category} must be between 0 and 1000`);
    }
    if (!Number.isFinite(weights[category]) || weights[category] < 0) {
      throw new RangeError(`${category} weight must be a non-negative finite number`);
    }
  }
  const totalWeight = categories.reduce((sum, category) => sum + weights[category], 0);
  if (totalWeight <= 0) throw new RangeError('At least one category weight must be positive');
  return Math.round(categories.reduce((sum, category) => sum + scores[category] * weights[category], 0) / totalWeight);
}

/** Returns the component subscores and the configurable weighted aggregate together. */
export function getReputationCategoryBreakdown(
  scores: ReputationCategoryScores,
  weights: ReputationCategoryWeights = DEFAULT_CATEGORY_WEIGHTS,
): ReputationCategoryBreakdown {
  return { subscores: { ...scores }, weights: { ...weights }, aggregateScore: aggregateReputationCategories(scores, weights) };
}

/** Recalculates the event score with exponential time decay, retaining factors for audit/export. */
export function recalculateDecayedScore(
  events: ReputationEvent[],
  options: DecayOptions,
): DecayedReputationResult {
  if (!Number.isFinite(options.decayRatePerDay) || options.decayRatePerDay < 0) {
    throw new RangeError('decayRatePerDay must be a non-negative finite number');
  }
  const now = options.now ?? Date.now();
  if (!Number.isFinite(now)) throw new RangeError('now must be a finite timestamp');
  const history = events.map(event => {
    if (!Number.isFinite(event.score) || !Number.isFinite(event.timestamp)) {
      throw new RangeError('Reputation events must have finite scores and timestamps');
    }
    const ageDays = Math.max(0, now - event.timestamp) / 86_400_000;
    const decayFactor = Math.exp(-options.decayRatePerDay * ageDays);
    return { ...event, decayFactor, weightedScore: event.score * decayFactor };
  });
  const factorSum = history.reduce((sum, item) => sum + item.decayFactor, 0);
  const score = factorSum === 0
    ? (options.fallbackScore ?? 0)
    : Math.round(history.reduce((sum, item) => sum + item.weightedScore, 0) / factorSum);
  return { score, history };
}

export interface ReputationTierDefinition {
  tier: ReputationTier;
  minScore: number;
  maxScore: number;
  badge: string;
}

export const DEFAULT_REPUTATION_TIERS: ReputationTierDefinition[] = [
  { tier: ReputationTier.Bronze, minScore: 0, maxScore: 250, badge: '🥉' },
  { tier: ReputationTier.Silver, minScore: 251, maxScore: 500, badge: '🥈' },
  { tier: ReputationTier.Gold, minScore: 501, maxScore: 750, badge: '🥇' },
  { tier: ReputationTier.Platinum, minScore: 751, maxScore: 1000, badge: '💎' },
];

export function getReputationTier(
  score: number,
  definitions: ReputationTierDefinition[] = DEFAULT_REPUTATION_TIERS,
): ReputationTierDefinition {
  if (!Number.isFinite(score) || score < 0 || score > 1000) {
    throw new RangeError('Reputation score must be between 0 and 1000');
  }
  const tier = definitions.find(item => score >= item.minScore && score <= item.maxScore);
  if (!tier) throw new RangeError('Tier definitions must cover the reputation score');
  return tier;
}

/** Emits local tier-boundary transitions; applications may bridge this callback to their event bus. */
export class ReputationTierChangeEmitter {
  private readonly listeners = new Set<(event: { previous: ReputationTierDefinition; current: ReputationTierDefinition }) => void>();

  onTierChanged(listener: (event: { previous: ReputationTierDefinition; current: ReputationTierDefinition }) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  update(score: number, definitions: ReputationTierDefinition[] = DEFAULT_REPUTATION_TIERS): ReputationTierDefinition {
    const current = getReputationTier(score, definitions);
    const previous = this.lastTier;
    this.lastTier = current;
    if (previous && previous.tier !== current.tier) {
      const event = { previous, current };
      this.listeners.forEach(listener => listener(event));
    }
    return current;
  }

  private lastTier?: ReputationTierDefinition;
}
