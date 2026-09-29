import React from 'react';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { axe } from 'jest-axe';
import {
  OnboardingWizard,
  ONBOARDING_STEPS,
  readProgress,
  resolveInitialStep,
  OnboardingProgress,
  StorageLike,
} from '@/components/OnboardingWizard';
import { Keypair } from 'stellar-sdk';

/** In-memory Storage stand-in, so tests never touch a real localStorage. */
function makeStorage(initial: Record<string, string> = {}): StorageLike & { data: Record<string, string> } {
  const data = { ...initial };
  return {
    data,
    getItem: (key: string) => (key in data ? data[key] : null),
    setItem: (key: string, value: string) => {
      data[key] = value;
    },
    removeItem: (key: string) => {
      delete data[key];
    },
  };
}

const keypair = { publicKey: () => 'GDEMO', sign: jest.fn() } as unknown as Keypair;

function renderWizard(props: Partial<React.ComponentProps<typeof OnboardingWizard>> = {}) {
  return render(
    <OnboardingWizard
      show
      generateKeypair={() => keypair}
      onCreateDID={async () => 'did:stellar:GDEMO'}
      onIssueCredential={async () => 'cred-1'}
      {...props}
    />,
  );
}

describe('OnboardingWizard helpers', () => {
  describe('readProgress', () => {
    it('reads a stored progress record', () => {
      const storage = makeStorage({ k: JSON.stringify({ completed: ['wallet'], skipped: false, startedAt: 1 }) });
      expect(readProgress('k', storage)?.completed).toEqual(['wallet']);
    });

    it('returns null without a key', () => {
      expect(readProgress(undefined, makeStorage())).toBeNull();
    });

    it('returns null without storage', () => {
      expect(readProgress('k', undefined)).toBeNull();
    });

    it('returns null for corrupt JSON', () => {
      expect(readProgress('k', makeStorage({ k: '{not json' }))).toBeNull();
    });

    it('returns null when completed is not an array', () => {
      expect(readProgress('k', makeStorage({ k: '{"completed":"wallet"}' }))).toBeNull();
    });
  });

  describe('resolveInitialStep', () => {
    const stepIds = ONBOARDING_STEPS.map(s => s.id);

    it('starts at 0 with no progress', () => {
      expect(resolveInitialStep(null, stepIds)).toBe(0);
    });

    it('starts at 0 when the flow was skipped', () => {
      const progress: OnboardingProgress = { completed: [], skipped: true, startedAt: 1 };
      expect(resolveInitialStep(progress, stepIds)).toBe(0);
    });

    it('resumes at the first incomplete step', () => {
      const progress: OnboardingProgress = {
        completed: ['wallet'],
        skipped: false,
        startedAt: 1,
      };
      expect(resolveInitialStep(progress, stepIds)).toBe(1);
    });

    it('resumes at the first step not in a discontiguous set', () => {
      const progress: OnboardingProgress = {
        completed: ['wallet', 'credential'],
        skipped: false,
        startedAt: 1,
      };
      expect(resolveInitialStep(progress, stepIds)).toBe(1);
    });

    it('clamps to the last step when everything is complete', () => {
      const progress: OnboardingProgress = {
        completed: stepIds as never,
        skipped: false,
        startedAt: 1,
      };
      expect(resolveInitialStep(progress, stepIds)).toBe(stepIds.length - 1);
    });
  });
});

describe('OnboardingWizard', () => {
  it('renders nothing when show is false', () => {
    const { container } = render(
      <OnboardingWizard show={false} generateKeypair={() => keypair} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('exposes the four steps in order', () => {
    expect(ONBOARDING_STEPS.map(s => s.id)).toEqual(['wallet', 'did', 'credential', 'explore']);
  });

  it('has no accessibility violations', async () => {
    const { container } = renderWizard();
    expect(await axe(container)).toHaveNoViolations();
  });

  it('is a labelled modal dialog', () => {
    renderWizard();

    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(dialog).toHaveAccessibleName('Connect your wallet');
  });

  it('starts on the wallet step', () => {
    renderWizard();
    expect(screen.getByRole('heading', { name: 'Connect your wallet' })).toBeInTheDocument();
  });

  it('shows the step in the progress bar', () => {
    renderWizard();
    expect(screen.getByRole('progressbar')).toHaveAttribute('aria-valuetext', '25 percent');
  });

  it('renders one dot per step', () => {
    renderWizard();
    expect(screen.getAllByTestId('onboarding-step-dot')).toHaveLength(ONBOARDING_STEPS.length);
  });

  it('disables Continue until a keypair exists', async () => {
    const user = userEvent.setup();
    renderWizard();

    expect(screen.getByRole('button', { name: /Continue/ })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    expect(screen.getByRole('button', { name: /Continue/ })).toBeEnabled();
  });

  it('walks the whole flow', async () => {
    const user = userEvent.setup();
    const onComplete = jest.fn();
    renderWizard({ onComplete });

    // Step 1: wallet
    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    expect(screen.getByText('GDEMO')).toBeInTheDocument();

    // Step 2: DID
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    expect(screen.getByRole('heading', { name: /Create your decentralized identifier/ })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Create my DID/ }));
    await waitFor(() => expect(screen.getByText('did:stellar:GDEMO')).toBeInTheDocument());

    // Step 3: credential
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    expect(screen.getByRole('heading', { name: /Receive your first credential/ })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Issue demo KYC credential/ }));
    await waitFor(() => expect(screen.getByText('cred-1')).toBeInTheDocument());

    // Step 4: explore
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    expect(screen.getByRole('heading', { name: /Explore your dashboard/ })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Finish/ }));
    expect(onComplete).toHaveBeenCalledTimes(1);
    expect(onComplete.mock.calls[0][0].skipped).toBe(false);
  });

  it('goes back a step', async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    expect(screen.getByRole('heading', { name: /Create your decentralized identifier/ })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Back/ }));
    expect(screen.getByRole('heading', { name: 'Connect your wallet' })).toBeInTheDocument();
  });

  it('labels the first back control as skip', () => {
    renderWizard();
    expect(screen.getByRole('button', { name: 'Skip for now' })).toBeInTheDocument();
  });

  it('skips from the close control and reports it', async () => {
    const user = userEvent.setup();
    const onSkip = jest.fn();
    renderWizard({ onSkip });

    await user.click(screen.getByRole('button', { name: 'Skip onboarding' }));

    expect(onSkip).toHaveBeenCalledTimes(1);
    expect(onSkip.mock.calls[0][0].skipped).toBe(true);
  });

  it('skips from the footer button', async () => {
    const user = userEvent.setup();
    const onSkip = jest.fn();
    const onClose = jest.fn();
    renderWizard({ onSkip, onClose });

    await user.click(screen.getByRole('button', { name: 'Skip' }));

    expect(onSkip).toHaveBeenCalledTimes(1);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('skips on Escape', async () => {
    const user = userEvent.setup();
    const onSkip = jest.fn();
    renderWizard({ onSkip });

    await user.keyboard('{Escape}');

    expect(onSkip).toHaveBeenCalledTimes(1);
  });

  it('persists progress as steps complete', async () => {
    const user = userEvent.setup();
    const storage = makeStorage();
    renderWizard({ storage, storageKey: 'onboarding' });

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));

    await waitFor(() => {
      const stored = JSON.parse(storage.data['onboarding']);
      expect(stored.completed).toContain('wallet');
      expect(stored.skipped).toBe(false);
    });
  });

  it('resumes from persisted progress', () => {
    const storage = makeStorage({
      onboarding: JSON.stringify({
        completed: ['wallet'],
        skipped: false,
        startedAt: 1,
      }),
    });

    renderWizard({ storage, storageKey: 'onboarding' });

    expect(
      screen.getByRole('heading', { name: /Create your decentralized identifier/ }),
    ).toBeInTheDocument();
  });

  it('does not resume a skipped flow', () => {
    const storage = makeStorage({
      onboarding: JSON.stringify({ completed: [], skipped: true, startedAt: 1 }),
    });

    renderWizard({ storage, storageKey: 'onboarding' });

    expect(screen.getByRole('heading', { name: 'Connect your wallet' })).toBeInTheDocument();
  });

  it('shows an error when DID creation fails', async () => {
    const user = userEvent.setup();
    renderWizard({
      onCreateDID: async () => {
        throw new Error('contract reverted');
      },
    });

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    await user.click(screen.getByRole('button', { name: /Create my DID/ }));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('contract reverted'));
  });

  it('shows an error when credential issuance fails', async () => {
    const user = userEvent.setup();
    renderWizard({
      onIssueCredential: async () => {
        throw new Error('network down');
      },
    });

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    await user.click(screen.getByRole('button', { name: /Create my DID/ }));
    await waitFor(() => expect(screen.getByText('did:stellar:GDEMO')).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    await user.click(screen.getByRole('button', { name: /Issue demo KYC credential/ }));

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('network down'));
  });

  it('announces step changes', async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));

    await waitFor(() =>
      expect(screen.getByTestId('live-announcer')).toHaveTextContent('Step 2 of 4'),
    );
  });

  it('traps focus inside the wizard', () => {
    renderWizard();

    const dialog = screen.getByRole('dialog');
    expect(dialog).toContainElement(document.activeElement as HTMLElement);
  });

  it('regenerates the keypair', async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    expect(screen.getByRole('button', { name: 'Regenerate' })).toBeInTheDocument();
  });

  it('shows the KYC summary before issuing', async () => {
    const user = userEvent.setup();
    renderWizard();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    await user.click(screen.getByRole('button', { name: /Create my DID/ }));
    await waitFor(() => expect(screen.getByText('did:stellar:GDEMO')).toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: /Continue/ }));

    expect(screen.getByText('Document type')).toBeInTheDocument();
    expect(screen.getByText('Passport')).toBeInTheDocument();
    expect(screen.getByText('Verification level')).toBeInTheDocument();
  });

  it('survives a storage that throws', async () => {
    const user = userEvent.setup();
    const throwing: StorageLike = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('quota');
      },
      removeItem: () => {},
    };

    expect(() => renderWizard({ storage: throwing, storageKey: 'k' })).not.toThrow();

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('falls back to the public key when no DID handler is supplied', async () => {
    const user = userEvent.setup();
    render(
      <OnboardingWizard show generateKeypair={() => keypair} />,
    );

    await user.click(screen.getByRole('button', { name: /Generate keypair/ }));
    await user.click(screen.getByRole('button', { name: /Continue/ }));
    await user.click(screen.getByRole('button', { name: /Create my DID/ }));

    await waitFor(() => expect(screen.getByText('GDEMO')).toBeInTheDocument());
  });
});
