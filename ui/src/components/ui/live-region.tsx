import React, { useCallback, useEffect, useRef, useState } from 'react';

export type Politeness = 'polite' | 'assertive';

export interface LiveAnnouncerProps {
  /**
   * Message to announce. Changing this value triggers an announcement.
   * Use `undefined` or an empty string for nothing to announce.
   */
  message?: string;
  /**
   * `polite` (default) waits for a pause in speech; `assertive` interrupts.
   * Reserve `assertive` for errors and time-sensitive alerts.
   */
  politeness?: Politeness;
  /**
   * Re-announce even when the text is unchanged. Needed when the same error
   * occurs twice in a row and a screen reader user would otherwise hear nothing.
   */
  forceAnnounce?: boolean;
  /** Additional context appended to the message, e.g. a count. */
  className?: string;
}

/**
 * A visually hidden ARIA live region for announcing dynamic changes.
 *
 * Loading an error into a form, finishing a batch, or switching to a detail
 * view are all changes a screen reader user would otherwise miss entirely,
 * because the DOM change happens somewhere they are not currently reading.
 * Rendering the message into a live region is what makes it audible.
 *
 * The region is always present in the DOM and only its text changes — an
 * empty live region is not reliably announced by all screen readers, so
 * mounting it alongside the message would drop the first announcement.
 *
 * @example
 * ```tsx
 * <LiveAnnouncer message={error ? `Error: ${error}` : ''} politeness="assertive" />
 * ```
 */
export const LiveAnnouncer: React.FC<LiveAnnouncerProps> = ({
  message,
  politeness = 'polite',
  forceAnnounce = false,
  className,
}) => {
  const [announced, setAnnounced] = useState('');
  const previousRef = useRef<string | undefined>(undefined);

  useEffect(() => {
    const next = message ?? '';
    if (!next) {
      setAnnounced('');
      previousRef.current = next;
      return;
    }

    if (next !== previousRef.current || forceAnnounce) {
      setAnnounced(next);
      previousRef.current = next;
    }
  }, [message, forceAnnounce]);

  return (
    <div
      role="status"
      aria-live={politeness}
      aria-atomic="true"
      data-testid="live-announcer"
      className={['sr-only', className].filter(Boolean).join(' ')}
    >
      {announced}
    </div>
  );
};
LiveAnnouncer.displayName = 'LiveAnnouncer';

export interface UseAnnouncerResult {
  /** Announce a message. */
  announce: (message: string, politeness?: Politeness) => void;
  /** Clear the current message. */
  clear: () => void;
  /** Render at the root of the tree. */
  LiveRegion: React.FC;
  message: string;
  politeness: Politeness;
}

/**
 * Hook that owns an announcer, for components that need to announce from
 * several places or from an async callback.
 *
 * @example
 * ```tsx
 * const { announce, LiveRegion } = useAnnouncer();
 * const submit = async () => {
 *   try { await save(); announce('Credential saved'); }
 *   catch { announce('Could not save credential', 'assertive'); }
 * };
 * return <>{<LiveRegion />}<button onClick={submit}>Save</button></>;
 * ```
 */
export function useAnnouncer(initialPoliteness: Politeness = 'polite'): UseAnnouncerResult {
  const [message, setMessage] = useState('');
  const [politeness, setPoliteness] = useState<Politeness>(initialPoliteness);

  const announce = useCallback((next: string, nextPoliteness?: Politeness) => {
    if (nextPoliteness) {
      setPoliteness(nextPoliteness);
    }
    setMessage(next);
  }, []);

  const clear = useCallback(() => {
    setMessage('');
  }, []);

  const LiveRegion = useCallback(() => (
    <LiveAnnouncer message={message} politeness={politeness} forceAnnounce />
    // `LiveAnnouncer` is a stable module-level component; re-creating this
    // wrapper on every render would remount the live region and drop the
    // announcement.
  ), [message, politeness]);

  return { announce, clear, LiveRegion, message, politeness };
}
