import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EventStream,
  EventFilters,
  IdentityEvent,
  IdentityEventType,
  StreamStatus,
  StreamMetrics,
  EventSubscription,
  WebSocketLike,
  IDENTITY_EVENT_TYPES,
} from '../../sdk/src/eventStream';

export type { EventFilters, IdentityEvent, IdentityEventType, StreamStatus };

/** Credential lifecycle events surfaced by the hook. */
export const CREDENTIAL_EVENT_TYPES: readonly IdentityEventType[] = [
  'CredentialIssued',
  'CredentialRevoked',
  'CredentialExpired',
] as const;

export interface UseCredentialEventsOptions {
  /** Restrict to these event types. Defaults to {@link CREDENTIAL_EVENT_TYPES}. */
  types?: readonly IdentityEventType[];
  /** Only events referencing this Stellar address. */
  address?: string;
  /** Only events with this credential type. */
  credentialType?: string;
  /** Only events for this credential. */
  credentialId?: string;
  /** Only events for this DID. */
  did?: string;
  /** Only events from this contract. */
  contractAddress?: string;
  /** Only events with a reputation score at or above this value. */
  minScore?: number;
  /** Only events with a reputation score at or below this value. */
  maxScore?: number;
  /** Custom predicate applied after the declarative filters. */
  predicate?: (event: IdentityEvent) => boolean;
  /** Override the WebSocket URL. */
  url?: string;
  /** Injectable WebSocket factory for tests and non-browser runtimes. */
  webSocketFactory?: (url: string) => WebSocketLike;
  /** Events retained in component state. Default 100. */
  maxEvents?: number;
  /** Replay recent stream events immediately on mount. */
  replayHistory?: boolean;
  /** Subscribe on mount. Default true. */
  enabled?: boolean;
  /** Called for every matching event, in addition to state updates. */
  onEvent?: (event: IdentityEvent) => void;
  /** Called when the stream status changes. */
  onStatusChange?: (status: StreamStatus) => void;
  /** Stream instance to reuse. When omitted, one is created and closed per mount. */
  stream?: EventStream;
}

export interface UseCredentialEventsResult {
  events: IdentityEvent[];
  latest: IdentityEvent | null;
  status: StreamStatus;
  metrics: StreamMetrics | null;
  /** Replay events already in stream history. */
  replay: () => void;
  /** Remove all buffered events. */
  clear: () => void;
  /** Pause delivery without tearing down the subscription. */
  pause: () => void;
  /** Resume a paused subscription. */
  resume: () => void;
  isPaused: boolean;
}

/** Stable JSON key for the filter fields, used to avoid resubscribing. */
function filterKey(options: UseCredentialEventsOptions): string {
  return JSON.stringify({
    types: options.types ?? null,
    address: options.address ?? null,
    credentialType: options.credentialType ?? null,
    credentialId: options.credentialId ?? null,
    did: options.did ?? null,
    contractAddress: options.contractAddress ?? null,
    minScore: options.minScore ?? null,
    maxScore: options.maxScore ?? null,
  });
}

/**
 * Subscribe to credential lifecycle events with automatic cleanup.
 *
 * The hook owns a subscription for the lifetime of the component: it
 * subscribes on mount, replaces the subscription when the filter changes, and
 * unsubscribes on unmount so a re-render loop cannot leak sockets. Reconnection
 * is handled by {@link EventStream}, so the hook never needs to manage it.
 *
 * @example
 * ```tsx
 * const { events, status } = useCredentialEvents({ address, types: ['CredentialRevoked'] });
 * return <ul>{events.map(e => <li key={e.id}>{e.data.credentialId}</li>)}</ul>;
 * ```
 */
export function useCredentialEvents(
  options: UseCredentialEventsOptions = {},
): UseCredentialEventsResult {
  const {
    types = CREDENTIAL_EVENT_TYPES as readonly IdentityEventType[],
    maxEvents = 100,
    replayHistory = false,
    enabled = true,
  } = options;

  const [events, setEvents] = useState<IdentityEvent[]>([]);
  const [status, setStatus] = useState<StreamStatus>('idle');
  const [metrics, setMetrics] = useState<StreamMetrics | null>(null);
  const [isPaused, setIsPaused] = useState(false);

  // Latest-value refs keep the effect free of the caller's callback identity so
  // an inline arrow does not tear down the subscription on every render.
  const onEventRef = useRef(options.onEvent);
  const onStatusChangeRef = useRef(options.onStatusChange);
  onEventRef.current = options.onEvent;
  onStatusChangeRef.current = options.onStatusChange;

  // A caller-supplied stream outlives the component; we must not close it.
  const ownsStreamRef = useRef(!options.stream);
  const externalStreamRef = useRef(options.stream);
  const streamRef = useRef<EventStream | null>(options.stream ?? null);

  if (!streamRef.current && enabled) {
    streamRef.current = options.stream
      ?? EventStream.fromUrl(
        options.url ?? 'wss://soroban-testnet.stellar.org/events',
        options.webSocketFactory ? { webSocketFactory: options.webSocketFactory } : {},
      );
  }

  const key = filterKey({ ...options, types });
  const subscriptionRef = useRef<EventSubscription | null>(null);

  useEffect(() => {
    if (!enabled) return;

    const stream = streamRef.current ?? externalStreamRef.current;
    if (!stream) return;

    // Snapshot metrics on a timer rather than on every event: reading them per
    // event would re-render the component once per event with no benefit.
    const metricsTimer = setInterval(() => {
      setMetrics(stream.getMetrics());
    }, 1000);

    const removeStatusListener = stream.onStatusChange((nextStatus: StreamStatus) => {
      setStatus(nextStatus);
      onStatusChangeRef.current?.(nextStatus);
    });
    setStatus(stream.getStatus());

    const subscription = stream.subscribeToEvents(
      {
        types: [...types],
        ...(options.address ? { address: options.address } : {}),
        ...(options.credentialType ? { credentialType: options.credentialType } : {}),
        ...(options.credentialId ? { credentialId: options.credentialId } : {}),
        ...(options.did ? { did: options.did } : {}),
        ...(options.contractAddress ? { contractAddress: options.contractAddress } : {}),
        ...(options.minScore !== undefined ? { minScore: options.minScore } : {}),
        ...(options.maxScore !== undefined ? { maxScore: options.maxScore } : {}),
        ...(options.predicate ? { predicate: options.predicate } : {}),
      },
      (event: IdentityEvent) => {
        setEvents((current: IdentityEvent[]) => [event, ...current].slice(0, maxEvents));
        onEventRef.current?.(event);
      },
      { replayHistory },
    );
    subscriptionRef.current = subscription;

    return () => {
      subscription.unsubscribe();
      subscriptionRef.current = null;
      removeStatusListener();
      clearInterval(metricsTimer);
      // Only tear down a stream this hook created.
      if (ownsStreamRef.current) stream.close();
    };
    // `key` collapses the declarative filter fields into one dependency.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, key, maxEvents, replayHistory]);

  const latest = events.length > 0 ? events[0] : null;

  const replay = useCallback(() => {
    const stream = streamRef.current ?? externalStreamRef.current;
    if (!stream) return;
    const history = stream.getHistory();
    setEvents(history.slice(-maxEvents).reverse());
  }, [maxEvents]);

  const clear = useCallback(() => {
    setEvents([]);
  }, []);

  const pause = useCallback(() => {
    subscriptionRef.current?.pause();
    setIsPaused(true);
  }, []);

  const resume = useCallback(() => {
    subscriptionRef.current?.resume();
    setIsPaused(false);
  }, []);

  return useMemo(
    () => ({ events, latest, status, metrics, replay, clear, pause, resume, isPaused }),
    [events, latest, status, metrics, replay, clear, pause, resume, isPaused],
  );
}

export { IDENTITY_EVENT_TYPES };
