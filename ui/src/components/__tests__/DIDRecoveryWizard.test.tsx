import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { DIDRecoveryWizard } from '../DIDRecoveryWizard';

// ─── Shared fixtures ──────────────────────────────────────────────────────────

const mockKeypair = { publicKey: () => 'GA1234567890ABCDEF' } as any;

const socialConfig = {
  method: 'social' as const,
  threshold: 3,
  total: 5,
  guardians: [
    { address: 'GA111', approved: true },
    { address: 'GA222', approved: true },
    { address: 'GA333', approved: false },
    { address: 'GA444', approved: false },
    { address: 'GA555', approved: false },
  ],
};

function makeSdk(overrides: Record<string, jest.Mock> = {}) {
  return {
    did: {
      resolveDID: jest.fn().mockResolvedValue({ didDocument: { id: 'did:stellar:GA123' } }),
      getRecoveryConfig: jest.fn().mockResolvedValue(socialConfig),
      submitApproval: jest.fn().mockResolvedValue(undefined),
      submitRecoveryKey: jest.fn().mockResolvedValue(undefined),
      executeRecovery: jest.fn().mockResolvedValue('did:stellar:GA123'),
      ...overrides,
    },
  };
}

// ─── Step 1: Identify DID ─────────────────────────────────────────────────────

describe('Step 1 — Identify DID', () => {
  test('renders DID input field', () => {
    render(<DIDRecoveryWizard sdk={makeSdk()} keypair={mockKeypair} />);
    expect(screen.getByPlaceholderText('did:stellar:G...')).toBeInTheDocument();
  });

  test('pre-fills DID when did prop is provided', () => {
    render(<DIDRecoveryWizard sdk={makeSdk()} keypair={mockKeypair} did="did:stellar:GA999" />);
    expect(screen.getByDisplayValue('did:stellar:GA999')).toBeInTheDocument();
  });

  test('shows error when Next is clicked with empty DID', async () => {
    render(<DIDRecoveryWizard sdk={makeSdk()} keypair={mockKeypair} />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Please enter a DID to recover.')).toBeInTheDocument();
  });

  test('shows error when DID is not found', async () => {
    const sdk = makeSdk({ resolveDID: jest.fn().mockRejectedValue(new Error('DID not found')) });
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:MISSING" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('DID not found')).toBeInTheDocument();
  });

  test('shows error when recovery is not configured', async () => {
    const sdk = makeSdk({ getRecoveryConfig: jest.fn().mockResolvedValue(null) });
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(
      await screen.findByText(/Recovery is not configured for this DID/)
    ).toBeInTheDocument();
  });

  test('calls onCancel when Cancel is clicked', () => {
    const onCancel = jest.fn();
    render(<DIDRecoveryWizard sdk={makeSdk()} keypair={mockKeypair} onCancel={onCancel} />);
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalled();
  });

  test('advances to Step 2 on successful resolution', async () => {
    render(<DIDRecoveryWizard sdk={makeSdk()} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Social Recovery')).toBeInTheDocument();
  });
});

// ─── Step 2: Select Recovery Method ───────────────────────────────────────────

describe('Step 2 — Select Recovery Method', () => {
  async function renderStep2(sdkOverrides: Record<string, jest.Mock> = {}) {
    const sdk = makeSdk(sdkOverrides);
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Social Recovery');
    return sdk;
  }

  test('shows all three recovery method options', async () => {
    await renderStep2();
    expect(screen.getByText('Social Recovery')).toBeInTheDocument();
    expect(screen.getByText('Multi-Sig Recovery')).toBeInTheDocument();
    expect(screen.getByText('Recovery Key')).toBeInTheDocument();
  });

  test('shows threshold info for social recovery', async () => {
    await renderStep2();
    expect(screen.getByText(/3 of 5 guardian approvals/)).toBeInTheDocument();
  });

  test('shows error when Next is clicked without selecting a method', async () => {
    await renderStep2();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Please select a recovery method.')).toBeInTheDocument();
  });

  test('goes back to Step 1 when Back is clicked', async () => {
    await renderStep2();
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(screen.getByPlaceholderText('did:stellar:G...')).toBeInTheDocument();
  });

  test('advances to Step 3 after selecting a method', async () => {
    await renderStep2();
    fireEvent.click(screen.getByText('Social Recovery'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('Submit Approval')).toBeInTheDocument();
  });
});

// ─── Step 3: Gather Approvals ─────────────────────────────────────────────────

describe('Step 3 — Gather Approvals', () => {
  async function renderStep3(sdkOverrides: Record<string, jest.Mock> = {}) {
    const sdk = makeSdk(sdkOverrides);
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    // Step 1 → Step 2
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Social Recovery');
    // Select method → Step 3
    fireEvent.click(screen.getByText('Social Recovery'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Submit Approval');
    return sdk;
  }

  test('shows guardian list with approval statuses', async () => {
    await renderStep3();
    expect(screen.getAllByText('✓ Approved').length).toBe(2);
    expect(screen.getAllByText('Pending').length).toBe(3);
  });

  test('shows approval count progress', async () => {
    await renderStep3();
    expect(screen.getByText(/2 of 3 required approvals/)).toBeInTheDocument();
  });

  test('calls sdk.did.submitApproval when Submit Approval is clicked', async () => {
    const sdk = await renderStep3();
    fireEvent.click(screen.getByRole('button', { name: 'Submit Approval' }));
    await waitFor(() => expect(sdk.did.submitApproval).toHaveBeenCalled());
  });

  test('shows error on approval submission failure', async () => {
    const sdk = await renderStep3({
      submitApproval: jest.fn().mockRejectedValue(new Error('Network error')),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Submit Approval' }));
    expect(await screen.findByText('Network error')).toBeInTheDocument();
  });

  test('renders recovery key input for recovery-key method', async () => {
    const sdk = makeSdk({
      getRecoveryConfig: jest.fn().mockResolvedValue({
        method: 'recovery-key',
        threshold: 1,
        total: 1,
      }),
    });
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Recovery Key');
    fireEvent.click(screen.getByText('Recovery Key'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByPlaceholderText('Enter recovery key')).toBeInTheDocument();
  });

  test('shows error when recovery key field is empty on submit', async () => {
    const sdk = makeSdk({
      getRecoveryConfig: jest.fn().mockResolvedValue({
        method: 'recovery-key',
        threshold: 1,
        total: 1,
      }),
    });
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Recovery Key');
    fireEvent.click(screen.getByText('Recovery Key'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByPlaceholderText('Enter recovery key');
    fireEvent.click(screen.getByRole('button', { name: 'Submit Approval' }));
    expect(await screen.findByText('Please enter the recovery key.')).toBeInTheDocument();
  });
});

// ─── Step 4: Execute Recovery ─────────────────────────────────────────────────

describe('Step 4 — Execute Recovery', () => {
  async function renderStep4(sdkOverrides: Record<string, jest.Mock> = {}) {
    const sdk = makeSdk(sdkOverrides);
    render(<DIDRecoveryWizard sdk={sdk} keypair={mockKeypair} did="did:stellar:GA123" />);
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Social Recovery');
    fireEvent.click(screen.getByText('Social Recovery'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Submit Approval');
    fireEvent.click(screen.getByRole('button', { name: 'Submit Approval' }));
    await screen.findByText('Execute Recovery');
    return sdk;
  }

  test('shows Execute Recovery button', async () => {
    await renderStep4();
    expect(screen.getByRole('button', { name: 'Execute Recovery' })).toBeInTheDocument();
  });

  test('calls sdk.did.executeRecovery on execute', async () => {
    const sdk = await renderStep4();
    fireEvent.click(screen.getByRole('button', { name: 'Execute Recovery' }));
    await waitFor(() => expect(sdk.did.executeRecovery).toHaveBeenCalled());
  });

  test('shows success message after recovery', async () => {
    await renderStep4();
    fireEvent.click(screen.getByRole('button', { name: 'Execute Recovery' }));
    expect(await screen.findByText(/Recovery successful/)).toBeInTheDocument();
  });

  test('calls onSuccess callback with new DID after recovery', async () => {
    const onSuccess = jest.fn();
    const sdk = makeSdk();
    render(
      <DIDRecoveryWizard
        sdk={sdk}
        keypair={mockKeypair}
        did="did:stellar:GA123"
        onSuccess={onSuccess}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Social Recovery');
    fireEvent.click(screen.getByText('Social Recovery'));
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    await screen.findByText('Submit Approval');
    fireEvent.click(screen.getByRole('button', { name: 'Submit Approval' }));
    await screen.findByText('Execute Recovery');
    fireEvent.click(screen.getByRole('button', { name: 'Execute Recovery' }));
    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith('did:stellar:GA123'));
  });

  test('shows error when execution fails', async () => {
    const sdk = await renderStep4({
      executeRecovery: jest.fn().mockRejectedValue(new Error('Insufficient approvals: 2 of 3 required')),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Execute Recovery' }));
    expect(await screen.findByText('Insufficient approvals: 2 of 3 required')).toBeInTheDocument();
  });
});
