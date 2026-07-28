/**
 * Pure-function helpers for trust-graph traversal.
 *
 * These helpers back the public ReputationClient methods but are exported
 * separately so they can be unit-tested without touching the network or
 * instantiating a StellarIdentityConfig.
 */

import { TrustEdge, TrustPath } from './types';

/**
 * Depth-bounded breadth-first search across a directed truster -> subject
 * edge list, returning every distinct path from `from` to `to` capped at
 * `maxDepth` hops. Cycles are broken by never revisiting a node within the
 * current path.
 *
 * Output is sorted by descending cumulativeWeight so the strongest path is
 * at index 0 (deterministic for the test suite).
 */
export function findTrustPathsBFS(
  from: string,
  to: string,
  edges: TrustEdge[],
  maxDepth: number,
): TrustPath[] {
  if (maxDepth < 1) return [];
  if (from === to) {
    return [{ from, to, path: [from], cumulativeWeight: 0, hops: 0 }];
  }

  const results: TrustPath[] = [];

  type Frame = { node: string; path: string[]; weight: number };
  const initial: Frame = { node: from, path: [from], weight: 0 };
  const queue: Frame[] = [initial];

  while (queue.length > 0) {
    const frame = queue.shift()!;
    if (frame.path.length - 1 >= maxDepth) continue;

    for (const edge of edges) {
      if (edge.truster !== frame.node) continue;
      if (frame.path.includes(edge.subject)) continue; // cycle guard

      const nextPath = [...frame.path, edge.subject];
      const nextWeight = frame.weight + (edge.weight || 0);

      if (edge.subject === to) {
        results.push({
          from,
          to,
          path: nextPath,
          cumulativeWeight: nextWeight,
          hops: nextPath.length - 1,
        });
      } else if (nextPath.length - 1 < maxDepth) {
        queue.push({ node: edge.subject, path: nextPath, weight: nextWeight });
      }
    }
  }

  results.sort((a, b) => {
    if (b.cumulativeWeight !== a.cumulativeWeight) {
      return b.cumulativeWeight - a.cumulativeWeight;
    }
    if (a.hops !== b.hops) return a.hops - b.hops;
    return a.path.join('>').localeCompare(b.path.join('>'));
  });

  return results;
}

/**
 * Return the sum of inbound trust weights for `subject`. Self-attestations
 * (where truster === subject) are excluded.
 */
export function aggregateTrustWeight(edges: TrustEdge[], subject: string): number {
  let total = 0;
  for (const edge of edges) {
    if (edge.subject !== subject) continue;
    if (edge.truster === subject) continue;
    total += edge.weight || 0;
  }
  return total;
}

/**
 * Recommend entities that `address` does not already directly trust but
 * which are strongly vouched for by entities `address` already trusts.
 *
 * Algorithm:
 *   - collect every direct truster of `address` (1-hop trustees)
 *   - look at every 2-hop subject reachable from those trustees via a shared edge
 *   - filter out `address` itself, its 1-hop trustees, and self-attestations
 *   - aggregate score = sum of weights along each trusted-of-trusted edge
 *   - return the top `limit` entities, sorted by descending aggregate score
 */
export function recommendTrustEntities(
  edges: TrustEdge[],
  address: string,
  limit: number,
): string[] {
  if (limit < 1) return [];

  const directTrusters = new Set<string>();
  for (const edge of edges) {
    if (edge.subject === address && edge.truster !== address) {
      directTrusters.add(edge.truster);
    }
  }

  const scores = new Map<string, number>();
  for (const edge of edges) {
    if (!directTrusters.has(edge.truster)) continue;
    if (edge.subject === address) continue; // self
    if (directTrusters.has(edge.subject)) continue; // already direct
    scores.set(edge.subject, (scores.get(edge.subject) ?? 0) + (edge.weight || 0));
  }

  return Array.from(scores.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([subject]) => subject);
}
