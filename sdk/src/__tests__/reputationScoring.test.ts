import {
  aggregateReputationCategories,
  getReputationCategoryBreakdown,
  getReputationTier,
  ReputationTierChangeEmitter,
  recalculateDecayedScore,
} from '../reputationScoring';
import { ReputationTier } from '../types';

describe('reputation scoring helpers', () => {
  it('normalizes configurable category weights into a composite score', () => {
    expect(aggregateReputationCategories({
      transaction_reliability: 1000,
      credential_trustworthiness: 500,
      community_trust: 250,
      activity_volume: 0,
    }, {
      transaction_reliability: 2,
      credential_trustworthiness: 1,
      community_trust: 1,
      activity_volume: 0,
    })).toBe(688);
    expect(getReputationCategoryBreakdown({
      transaction_reliability: 1000,
      credential_trustworthiness: 500,
      community_trust: 250,
      activity_volume: 0,
    }).aggregateScore).toBe(600);
  });

  it('weights newer events more heavily and includes decay metadata', () => {
    const result = recalculateDecayedScore([
      { score: 1000, timestamp: 0, eventType: 'old' },
      { score: 0, timestamp: 86_400_000, eventType: 'recent' },
    ], { decayRatePerDay: Math.log(2), now: 86_400_000 });
    expect(result.score).toBe(333);
    expect(result.history[0].decayFactor).toBeCloseTo(0.5);
    expect(result.history[1].decayFactor).toBe(1);
    expect(recalculateDecayedScore([], { decayRatePerDay: 0.2, fallbackScore: 50 }).score).toBe(50);
  });

  it('maps configurable score ranges to badges and emits boundary transitions', () => {
    expect(getReputationTier(751).tier).toBe(ReputationTier.Platinum);
    const emitter = new ReputationTierChangeEmitter();
    const listener = jest.fn();
    emitter.onTierChanged(listener);
    emitter.update(200);
    emitter.update(300);
    expect(listener).toHaveBeenCalledWith(expect.objectContaining({
      previous: expect.objectContaining({ tier: ReputationTier.Bronze }),
      current: expect.objectContaining({ tier: ReputationTier.Silver }),
    }));
  });
});
