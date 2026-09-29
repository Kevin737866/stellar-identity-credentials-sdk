import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Keypair } from 'stellar-sdk';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress, ProgressWithLabel } from '@/components/ui/progress';
import { Skeleton, SkeletonDetail } from '@/components/ui/skeleton';
import { LiveAnnouncer } from '@/components/ui/live-region';
import { useFocusTrap } from '@/hooks/useFocusTrap';
import {
  Wallet,
  Fingerprint,
  BadgeCheck,
  LayoutDashboard,
  CheckCircle2,
  ChevronRight,
  ChevronLeft,
  X,
  AlertCircle,
  KeyRound,
} from 'lucide-react';

export type OnboardingStepId = 'wallet' | 'did' | 'credential' | 'explore';

export interface OnboardingStep {
  id: OnboardingStepId;
  title: string;
  description: string;
  Icon: React.ComponentType<{ className?: string; 'aria-hidden'?: boolean | 'true' | 'false' }>;
}

/** The wizard's fixed sequence. */
export const ONBOARDING_STEPS: readonly OnboardingStep[] = [
  {
    id: 'wallet',
    title: 'Connect your wallet',
    description:
      'Link a Stellar wallet or generate a fresh keypair. Nothing leaves your browser — the secret key is never sent anywhere.',
    Icon: Wallet,
  },
  {
    id: 'did',
    title: 'Create your decentralized identifier',
    description:
      'Register a did:stellar identifier so your credentials have a stable, portable identity to attach to.',
    Icon: Fingerprint,
  },
  {
    id: 'credential',
    title: 'Receive your first credential',
    description:
      'Issue a demo KYC credential to yourself. It is a real credential on the network and you can revoke it at any time.',
    Icon: BadgeCheck,
  },
  {
    id: 'explore',
    title: 'Explore your dashboard',
    description:
      'Your identity is ready. Take a look around: manage credentials, request proofs, and check your reputation.',
    Icon: LayoutDashboard,
  },
] as const;

export interface OnboardingProgress {
  /** Step ids already completed, in order. */
  completed: OnboardingStepId[];
  /** Whether the user chose to skip. */
  skipped: boolean;
  /** Epoch ms the flow was first started. */
  startedAt: number;
  /** Epoch ms the flow was completed or skipped. */
  finishedAt?: number;
}

export interface OnboardingWizardProps {
  /**
   * Create a keypair for a user without an existing wallet.
   * Defaults to `Keypair.random()`.
   */
  generateKeypair?: () => Keypair;
  /** Create the DID. Resolves with the DID string. */
  onCreateDID?: (keypair: Keypair) => Promise<string>;
  /** Issue the demo KYC credential. Resolves with the credential id. */
  onIssueCredential?: (keypair: Keypair) => Promise<string>;
  /** Called when the user finishes or skips. */
  onComplete?: (progress: OnboardingProgress) => void;
  /** Called when the user dismisses via the skip button or the close control. */
  onSkip?: (progress: OnboardingProgress) => void;
  /**
   * `localStorage` key for persisting progress. Omit to disable persistence.
   */
  storageKey?: string;
  /** Show only when the user has not onboarded before. Default false. */
  show?: boolean;
  /** Called when the close (X) control is pressed. */
  onClose?: () => void;
  /** Injectable for tests and non-browser runtimes. */
  storage?: StorageLike;
}

/** The subset of the Storage API the wizard needs. */
export type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

/** Read persisted progress, tolerating corrupt or unavailable storage. */
export function readProgress(
  storageKey: string | undefined,
  storage: StorageLike | undefined,
): OnboardingProgress | null {
  if (!storageKey || !storage) return null;
  try {
    const raw = storage.getItem(storageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OnboardingProgress;
    if (!Array.isArray(parsed?.completed)) return null;
    return parsed;
  } catch {
    // A private-mode or quota-blocked store must not break the wizard.
    return null;
  }
}

/** Persist progress, ignoring quota and privacy-mode failures. */
function writeProgress(
  storageKey: string | undefined,
  storage: StorageLike | undefined,
  progress: OnboardingProgress,
): void {
  if (!storageKey || !storage) return;
  try {
    storage.setItem(storageKey, JSON.stringify(progress));
  } catch {
    /* best effort */
  }
}

/** Default step index, resuming past any already-completed steps. */
export function resolveInitialStep(
  progress: OnboardingProgress | null,
  stepIds: readonly OnboardingStepId[],
): number {
  if (!progress || progress.skipped) return 0;
  const lastCompleted = stepIds.reduce((acc, id, index) =>
    progress.completed.includes(id) ? index : acc, -1);
  return Math.min(lastCompleted + 1, stepIds.length - 1);
}

/**
 * Step-by-step onboarding for first-time users.
 *
 * Progress is persisted as each step completes, so a reload resumes where the
 * user left off rather than restarting the flow. A skip control is always
 * available for users who already know what they are doing.
 *
 * @example
 * ```tsx
 * <OnboardingWizard
 *   show={!hasOnboarded}
 *   storageKey="stellar-identity:onboarding"
 *   onCreateDID={kp => sdk.did.createDID(kp, { verificationMethods: [], services: [] })}
 *   onIssueCredential={kp => sdk.credentials.issueKYCCredential(kp, kp.publicKey(), demoKyc)}
 *   onComplete={() => setHasOnboarded(true)}
 * />
 * ```
 */
export const OnboardingWizard: React.FC<OnboardingWizardProps> = ({
  generateKeypair,
  onCreateDID,
  onIssueCredential,
  onComplete,
  onSkip,
  storageKey,
  show = false,
  onClose,
  storage,
}) => {
  const stepIds = useMemo(() => ONBOARDING_STEPS.map(step => step.id), []);

  // A caller-supplied store wins; otherwise fall back to localStorage.
  const resolvedStorage = useMemo<StorageLike | undefined>(() => {
    if (storage) return storage;
    if (typeof window === 'undefined') return undefined;
    return window.localStorage ?? undefined;
  }, [storage]);

  const [currentStep, setCurrentStep] = useState(0);
  const [keypair, setKeypair] = useState<Keypair | null>(null);
  const [did, setDid] = useState<string | null>(null);
  const [credentialId, setCredentialId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState('');
  const [restored, setRestored] = useState(false);

  const isOpen = show;
  const trapRef = useFocusTrap<HTMLDivElement>(isOpen, {
    onEscape: () => handleSkip(),
  });

  // Restore persisted progress on open.
  useEffect(() => {
    if (!isOpen || restored) return;
    const saved = readProgress(storageKey, resolvedStorage);
    if (saved) {
      setCurrentStep(resolveInitialStep(saved, stepIds));
      if (!saved.skipped) {
        setAnnouncement(
          `Resumed onboarding at step ${resolveInitialStep(saved, stepIds) + 1} of ${stepIds.length}.`,
        );
      }
    }
    setRestored(true);
  }, [isOpen, restored, storageKey, resolvedStorage, stepIds]);

  const step = ONBOARDING_STEPS[currentStep];
  const isLastStep = currentStep === ONBOARDING_STEPS.length - 1;
  const progressPercent = ((currentStep + 1) / ONBOARDING_STEPS.length) * 100;

  const persist = useCallback(
    (completed: OnboardingStepId[], skipped: boolean, finishedAt?: number) => {
      const progress: OnboardingProgress = {
        completed,
        skipped,
        startedAt: Date.now(),
        ...(finishedAt ? { finishedAt } : {}),
      };
      writeProgress(storageKey, resolvedStorage, progress);
      return progress;
    },
    [storageKey, resolvedStorage],
  );

  const completedSteps = useCallback(
    (throughIndex: number): OnboardingStepId[] =>
      stepIds.slice(0, throughIndex + 1),
    [stepIds],
  );

  const handleSkip = useCallback(() => {
    const progress = persist([], true, Date.now());
    setAnnouncement('Onboarding skipped.');
    onSkip?.(progress);
    onClose?.();
  }, [persist, onSkip, onClose]);

  const handleFinish = useCallback(() => {
    const progress = persist(completedSteps(currentStep), false, Date.now());
    setAnnouncement('Onboarding complete.');
    onComplete?.(progress);
    onClose?.();
  }, [persist, completedSteps, currentStep, onComplete, onClose]);

  const goNext = useCallback(() => {
    if (isLastStep) {
      handleFinish();
      return;
    }
    const next = currentStep + 1;
    setCurrentStep(next);
    persist(completedSteps(currentStep), false);
    setAnnouncement(`Step ${next + 1} of ${ONBOARDING_STEPS.length}: ${ONBOARDING_STEPS[next].title}`);
  }, [isLastStep, handleFinish, currentStep, persist, completedSteps]);

  const goBack = useCallback(() => {
    if (currentStep === 0) return;
    setCurrentStep(currentStep - 1);
    setError(null);
    setAnnouncement(`Step ${currentStep} of ${ONBOARDING_STEPS.length}: ${ONBOARDING_STEPS[currentStep - 1].title}`);
  }, [currentStep]);

  const handleGenerateKeypair = useCallback(() => {
    setError(null);
    try {
      const generated = generateKeypair ? generateKeypair() : Keypair.random();
      setKeypair(generated);
      setAnnouncement(`New keypair generated. Public key ${generated.publicKey()}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not generate a keypair');
    }
  }, [generateKeypair]);

  const handleCreateDID = useCallback(async () => {
    if (!keypair) return;
    setBusy(true);
    setError(null);
    try {
      const created = onCreateDID
        ? await onCreateDID(keypair)
        : keypair.publicKey();
      setDid(created);
      setAnnouncement(`Decentralized identifier created: ${created}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create your DID');
    } finally {
      setBusy(false);
    }
  }, [keypair, onCreateDID]);

  const handleIssueCredential = useCallback(async () => {
    if (!keypair) return;
    setBusy(true);
    setError(null);
    try {
      const issued = onIssueCredential
        ? await onIssueCredential(keypair)
        : `demo-${Date.now()}`;
      setCredentialId(issued);
      setAnnouncement(`First credential issued: ${issued}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not issue your credential');
    } finally {
      setBusy(false);
    }
  }, [keypair, onIssueCredential]);

  if (!isOpen) return null;

  const { Icon } = step;
  const canAdvance =
    step.id === 'wallet' ? Boolean(keypair)
      : step.id === 'did' ? Boolean(did)
        : step.id === 'credential' ? Boolean(credentialId)
          : true;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="onboarding-title"
      aria-describedby="onboarding-description"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
        padding: 'var(--space-4)',
      }}
    >
      <div
        ref={trapRef}
        className="onboarding-wizard"
        style={{
          backgroundColor: 'var(--color-bg)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-xl)',
          padding: 'var(--space-6)',
          width: '100%',
          maxWidth: '36rem',
          maxHeight: '90vh',
          overflowY: 'auto',
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            gap: 'var(--space-4)',
          }}
        >
          <div style={{ minWidth: 0 }}>
            <p
              style={{
                margin: 0,
                fontSize: 'var(--font-size-xs)',
                color: 'var(--color-text-secondary)',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
              }}
            >
              Getting started
            </p>
            <h2
              id="onboarding-title"
              style={{
                margin: '4px 0 0',
                fontSize: 'var(--font-size-lg)',
                fontWeight: 'var(--font-weight-semibold)' as any,
              }}
            >
              {step.title}
            </h2>
          </div>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleSkip}
            aria-label="Skip onboarding"
            title="Skip onboarding"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </Button>
        </div>

        <div style={{ margin: 'var(--space-5) 0' }}>
          <ProgressWithLabel
            value={currentStep + 1}
            max={ONBOARDING_STEPS.length}
            label={`Step ${currentStep + 1} of ${ONBOARDING_STEPS.length}`}
            aria-label="Onboarding progress"
          />
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 'var(--space-3)',
            marginBottom: 'var(--space-5)',
          }}
        >
          <span
            aria-hidden="true"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '40px',
              height: '40px',
              borderRadius: 'var(--radius-md)',
              backgroundColor: 'var(--color-bg-tertiary)',
              flexShrink: 0,
            }}
          >
            <Icon className="h-5 w-5" />
          </span>
          <p
            id="onboarding-description"
            style={{
              margin: 0,
              fontSize: 'var(--font-size-sm)',
              color: 'var(--color-text-secondary)',
              lineHeight: 'var(--line-height-normal)',
            }}
          >
            {step.description}
          </p>
        </div>

        {/* ── Step 1: wallet ── */}
        {step.id === 'wallet' && (
          <div className="onboarding-step" data-step="wallet">
            {keypair ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 'var(--space-3)',
                  padding: 'var(--space-4)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--color-border)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
                  <KeyRound className="h-5 w-5" aria-hidden="true" style={{ flexShrink: 0 }} />
                  <div style={{ minWidth: 0 }}>
                    <p style={{ margin: 0, fontSize: 'var(--font-size-xs)', color: 'var(--color-text-secondary)' }}>
                      Public key
                    </p>
                    <p
                      style={{
                        margin: 0,
                        fontSize: 'var(--font-size-sm)',
                        fontFamily: 'var(--font-family-mono, monospace)',
                        wordBreak: 'break-all',
                      }}
                    >
                      {keypair.publicKey()}
                    </p>
                  </div>
                </div>
                <Button variant="ghost" size="sm" onClick={handleGenerateKeypair}>
                  Regenerate
                </Button>
              </div>
            ) : (
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  padding: 'var(--space-6)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px dashed var(--color-border)',
                }}
              >
                <Wallet className="h-8 w-8" aria-hidden="true" />
                <p
                  style={{
                    margin: 0,
                    fontSize: 'var(--font-size-sm)',
                    color: 'var(--color-text-secondary)',
                    textAlign: 'center',
                  }}
                >
                  No wallet connected. Generate a keypair to continue — this is a demo
                  account and it should not hold real funds.
                </p>
                <Button onClick={handleGenerateKeypair}>
                  <KeyRound className="h-4 w-4 mr-2" aria-hidden="true" />
                  Generate keypair
                </Button>
              </div>
            )}
          </div>
        )}

        {/* ── Step 2: DID ── */}
        {step.id === 'did' && (
          <div className="onboarding-step" data-step="did">
            {did ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  padding: 'var(--space-4)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--color-border)',
                }}
              >
                <CheckCircle2 className="h-5 w-5 text-green-500" aria-hidden="true" style={{ flexShrink: 0 }} />
                <div style={{ minWidth: 0 }}>
                  <p style={{ margin: 0, fontSize: 'var(--font-size-xs)', color: 'var(--color-text-secondary)' }}>
                    Your DID
                  </p>
                  <p
                    style={{
                      margin: 0,
                      fontSize: 'var(--font-size-sm)',
                      fontFamily: 'var(--font-family-mono, monospace)',
                      wordBreak: 'break-all',
                    }}
                  >
                    {did}
                  </p>
                </div>
              </div>
            ) : (
              <>
                <div style={{ marginBottom: 'var(--space-4)' }}>
                  <Label htmlFor="did-method">DID method</Label>
                  <Input
                    id="did-method"
                    value="did:stellar"
                    readOnly
                    aria-describedby="did-method-help"
                  />
                  <p
                    id="did-method-help"
                    style={{
                      margin: 'var(--space-1) 0 0',
                      fontSize: 'var(--font-size-xs)',
                      color: 'var(--color-text-secondary)',
                    }}
                  >
                    Anchors your identity to Stellar. You can add verification methods later.
                  </p>
                </div>
                <Button onClick={handleCreateDID} loading={busy} disabled={!keypair || busy} className="w-full">
                  Create my DID
                </Button>
              </>
            )}
          </div>
        )}

        {/* ── Step 3: first credential ── */}
        {step.id === 'credential' && (
          <div className="onboarding-step" data-step="credential">
            {credentialId ? (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  padding: 'var(--space-4)',
                  borderRadius: 'var(--radius-md)',
                  border: '1px solid var(--color-border)',
                }}
              >
                <BadgeCheck className="h-5 w-5 text-green-500" aria-hidden="true" style={{ flexShrink: 0 }} />
                <div style={{ minWidth: 0 }}>
                  <p style={{ margin: 0, fontSize: 'var(--font-size-xs)', color: 'var(--color-text-secondary)' }}>
                    KYC credential issued
                  </p>
                  <p
                    style={{
                      margin: 0,
                      fontSize: 'var(--font-size-sm)',
                      fontFamily: 'var(--font-family-mono, monospace)',
                      wordBreak: 'break-all',
                    }}
                  >
                    {credentialId}
                  </p>
                </div>
              </div>
            ) : (
              <>
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 'var(--space-3)',
                    padding: 'var(--space-4)',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--color-border)',
                    marginBottom: 'var(--space-4)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
                    <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-secondary)' }}>
                      Document type
                    </span>
                    <Badge variant="outline">Passport</Badge>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
                    <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-secondary)' }}>
                      Verification level
                    </span>
                    <Badge variant="outline">Standard</Badge>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
                    <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-text-secondary)' }}>
                      Validity
                    </span>
                    <Badge variant="outline">1 year</Badge>
                  </div>
                </div>
                <Button
                  onClick={handleIssueCredential}
                  loading={busy}
                  disabled={!keypair || busy}
                  className="w-full"
                >
                  Issue demo KYC credential
                </Button>
                <p
                  style={{
                    margin: 'var(--space-3) 0 0',
                    fontSize: 'var(--font-size-xs)',
                    color: 'var(--color-text-secondary)',
                  }}
                >
                  This issues a real credential to your own address. You can revoke it whenever you like.
                </p>
              </>
            )}
          </div>
        )}

        {/* ── Step 4: explore ── */}
        {step.id === 'explore' && (
          <div className="onboarding-step" data-step="explore">
            {busy ? (
              <SkeletonDetail fields={4} />
            ) : (
              <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 'var(--space-3)' }}>
                {[
                  {
                    title: 'Manage credentials',
                    body: 'Issue, export and revoke credentials from your wallet.',
                  },
                  {
                    title: 'Request proofs',
                    body: 'Ask a verifier for a proof without revealing your personal data.',
                  },
                  {
                    title: 'Track reputation',
                    body: 'Watch how your credentials and on-chain history build your score.',
                  },
                ].map(item => (
                  <li
                    key={item.title}
                    style={{
                      display: 'flex',
                      gap: 'var(--space-3)',
                      padding: 'var(--space-3)',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--color-border)',
                    }}
                  >
                    <CheckCircle2
                      className="h-4 w-4 text-green-500"
                      aria-hidden="true"
                      style={{ flexShrink: 0, marginTop: '2px' }}
                    />
                    <div>
                      <p
                        style={{
                          margin: 0,
                          fontSize: 'var(--font-size-sm)',
                          fontWeight: 'var(--font-weight-medium)' as any,
                        }}
                      >
                        {item.title}
                      </p>
                      <p
                        style={{
                          margin: 0,
                          fontSize: 'var(--font-size-xs)',
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        {item.body}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {error && (
          <div
            role="alert"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 'var(--space-2)',
              marginTop: 'var(--space-4)',
              padding: 'var(--space-3)',
              borderRadius: 'var(--radius-md)',
              border: '1px solid var(--color-danger-500, #ef4444)',
              backgroundColor: 'var(--color-danger-50, #fef2f2)',
              fontSize: 'var(--font-size-sm)',
            }}
          >
            <AlertCircle className="h-4 w-4" aria-hidden="true" style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {/* Step dots double as a non-visual summary of where you are. */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'center',
            gap: 'var(--space-2)',
            margin: 'var(--space-5) 0',
          }}
        >
          {ONBOARDING_STEPS.map((s, index) => (
            <span
              key={s.id}
              aria-hidden="true"
              data-testid="onboarding-step-dot"
              data-active={index === currentStep || undefined}
              data-complete={index < currentStep || undefined}
              style={{
                width: index === currentStep ? '20px' : '8px',
                height: '8px',
                borderRadius: 'var(--radius-full)',
                backgroundColor:
                  index <= currentStep ? 'var(--color-primary-600)' : 'var(--color-border)',
                transition: 'all var(--transition-fast)',
              }}
            />
          ))}
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 'var(--space-3)',
          }}
        >
          <Button
            variant="ghost"
            onClick={currentStep === 0 ? handleSkip : goBack}
          >
            {currentStep === 0 ? 'Skip for now' : (
              <>
                <ChevronLeft className="h-4 w-4 mr-1" aria-hidden="true" />
                Back
              </>
            )}
          </Button>

          <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
            <Button variant="outline" onClick={handleSkip}>
              Skip
            </Button>
            <Button
              onClick={goNext}
              disabled={!canAdvance || busy}
              loading={busy}
            >
              {isLastStep ? 'Finish' : 'Continue'}
              {!isLastStep && <ChevronRight className="h-4 w-4 ml-1" aria-hidden="true" />}
            </Button>
          </div>
        </div>

        <LiveAnnouncer
          message={error ? `Error: ${error}` : announcement}
          politeness={error ? 'assertive' : 'polite'}
        />
      </div>
    </div>
  );
};
OnboardingWizard.displayName = 'OnboardingWizard';
