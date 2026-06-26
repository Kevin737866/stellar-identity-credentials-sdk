import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';
import { Button } from './ui/button';
import { Input, Label } from './ui/input';
import { Badge } from './ui/badge';
import { Alert, AlertDescription } from './ui/alert';
import { Progress } from './ui/progress';
import { Keypair } from 'stellar-sdk';

// ─── Types ────────────────────────────────────────────────────────────────────

export type RecoveryMethod = 'social' | 'multisig' | 'recovery-key';

export interface Guardian {
  address: string;
  approved: boolean;
}

export interface RecoveryConfig {
  method: RecoveryMethod;
  threshold: number;
  total: number;
  guardians?: Guardian[];
}

export interface DIDRecoveryWizardProps {
  sdk: any;
  keypair: Keypair;
  /** Pre-fill the DID to recover; user can still change it in Step 1. */
  did?: string;
  /** Called when recovery completes successfully. */
  onSuccess?: (newDid: string) => void;
  /** Called when the user cancels. */
  onCancel?: () => void;
}

// ─── Step identifiers ─────────────────────────────────────────────────────────

type Step = 'identify' | 'select-method' | 'gather-approvals' | 'execute';

const STEPS: Step[] = ['identify', 'select-method', 'gather-approvals', 'execute'];

const STEP_LABELS: Record<Step, string> = {
  identify: 'Identify DID',
  'select-method': 'Recovery Method',
  'gather-approvals': 'Gather Approvals',
  execute: 'Execute Recovery',
};

// ─── Component ────────────────────────────────────────────────────────────────

export const DIDRecoveryWizard: React.FC<DIDRecoveryWizardProps> = ({
  sdk,
  keypair,
  did: initialDid = '',
  onSuccess,
  onCancel,
}) => {
  const [step, setStep] = useState<Step>('identify');
  const [did, setDid] = useState(initialDid);
  const [recoveryConfig, setRecoveryConfig] = useState<RecoveryConfig | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<RecoveryMethod | null>(null);
  const [recoveryKey, setRecoveryKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveredDid, setRecoveredDid] = useState<string | null>(null);

  const currentStepIndex = STEPS.indexOf(step);
  const progress = ((currentStepIndex + 1) / STEPS.length) * 100;

  function clearError() {
    setError(null);
  }

  // ── Step 1: resolve DID and load recovery config ─────────────────────────

  async function handleIdentify() {
    if (!did.trim()) {
      setError('Please enter a DID to recover.');
      return;
    }
    clearError();
    setLoading(true);
    try {
      const result = await sdk.did.resolveDID(did.trim());
      if (!result?.didDocument) {
        setError('DID not found. Please check the identifier and try again.');
        return;
      }
      // Load recovery configuration from the DID document or contract
      let config: RecoveryConfig | null = null;
      if (sdk.did.getRecoveryConfig) {
        config = await sdk.did.getRecoveryConfig(did.trim());
      }
      if (!config) {
        setError('Recovery is not configured for this DID. Contact the DID controller to set up recovery.');
        return;
      }
      setRecoveryConfig(config);
      setStep('select-method');
    } catch (err: any) {
      setError(err?.message ?? 'Failed to resolve DID.');
    } finally {
      setLoading(false);
    }
  }

  // ── Step 2: select recovery method ───────────────────────────────────────

  function handleSelectMethod(method: RecoveryMethod) {
    setSelectedMethod(method);
    clearError();
  }

  function handleConfirmMethod() {
    if (!selectedMethod) {
      setError('Please select a recovery method.');
      return;
    }
    clearError();
    setStep('gather-approvals');
  }

  // ── Step 3: submit approval / recovery key ────────────────────────────────

  async function handleApprove() {
    if (!recoveryConfig || !selectedMethod) return;
    clearError();
    setLoading(true);
    try {
      if (selectedMethod === 'recovery-key') {
        if (!recoveryKey.trim()) {
          setError('Please enter the recovery key.');
          return;
        }
        await sdk.did.submitRecoveryKey?.(did, recoveryKey.trim(), keypair);
      } else {
        // For social / multisig: submit the current keypair as an approver
        await sdk.did.submitApproval?.(did, keypair);
      }
      // Re-fetch updated config to reflect new approvals
      if (sdk.did.getRecoveryConfig) {
        const updated = await sdk.did.getRecoveryConfig(did);
        if (updated) setRecoveryConfig(updated);
      }
      setStep('execute');
    } catch (err: any) {
      setError(err?.message ?? 'Failed to submit approval.');
    } finally {
      setLoading(false);
    }
  }

  // ── Step 4: execute recovery ──────────────────────────────────────────────

  async function handleExecute() {
    if (!recoveryConfig || !selectedMethod) return;
    clearError();
    setLoading(true);
    try {
      const approvedCount =
        recoveryConfig.guardians?.filter(g => g.approved).length ?? 0;
      if (selectedMethod !== 'recovery-key' && approvedCount < recoveryConfig.threshold) {
        setError(
          `Insufficient approvals: ${approvedCount} of ${recoveryConfig.threshold} required.`
        );
        return;
      }
      const newDid = await sdk.did.executeRecovery(did, keypair, { method: selectedMethod });
      setRecoveredDid(newDid ?? did);
      onSuccess?.(newDid ?? did);
    } catch (err: any) {
      setError(err?.message ?? 'Recovery execution failed.');
    } finally {
      setLoading(false);
    }
  }

  // ── Render helpers ────────────────────────────────────────────────────────

  const approvedCount = recoveryConfig?.guardians?.filter(g => g.approved).length ?? 0;
  const methodLabel: Record<RecoveryMethod, string> = {
    social: 'Social Recovery',
    multisig: 'Multi-Sig Recovery',
    'recovery-key': 'Recovery Key',
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>DID Recovery Wizard</CardTitle>
        {/* Step progress bar */}
        <div className="mt-2 space-y-1">
          <Progress value={progress} />
          <div className="flex justify-between text-xs text-muted-foreground">
            {STEPS.map((s, i) => (
              <span
                key={s}
                className={i <= currentStepIndex ? 'text-primary font-medium' : ''}
              >
                {STEP_LABELS[s]}
              </span>
            ))}
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* ── Step 1 ── */}
        {step === 'identify' && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Enter the DID you want to recover or select one from your connected wallet.
            </p>
            <div className="space-y-1">
              <Label htmlFor="did-input">DID</Label>
              <Input
                id="did-input"
                placeholder="did:stellar:G..."
                value={did}
                onChange={e => setDid(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={handleIdentify} disabled={loading}>
                {loading ? 'Resolving…' : 'Next'}
              </Button>
              {onCancel && (
                <Button variant="outline" onClick={onCancel} disabled={loading}>
                  Cancel
                </Button>
              )}
            </div>
          </div>
        )}

        {/* ── Step 2 ── */}
        {step === 'select-method' && recoveryConfig && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Choose the recovery method configured for <span className="font-mono text-xs">{did}</span>.
            </p>
            <div className="flex flex-col gap-2">
              {(['social', 'multisig', 'recovery-key'] as RecoveryMethod[]).map(m => (
                <button
                  key={m}
                  type="button"
                  onClick={() => handleSelectMethod(m)}
                  className={`rounded border p-3 text-left text-sm transition-colors ${
                    selectedMethod === m
                      ? 'border-primary bg-primary/10'
                      : 'border-border hover:bg-accent'
                  }`}
                >
                  <span className="font-medium">{methodLabel[m]}</span>
                  {m === 'social' && (
                    <span className="ml-2 text-muted-foreground">
                      — requires {recoveryConfig.threshold} of {recoveryConfig.total} guardian approvals
                    </span>
                  )}
                  {m === 'multisig' && (
                    <span className="ml-2 text-muted-foreground">
                      — requires {recoveryConfig.threshold} of {recoveryConfig.total} signatures
                    </span>
                  )}
                  {m === 'recovery-key' && (
                    <span className="ml-2 text-muted-foreground">— use your pre-configured recovery key</span>
                  )}
                </button>
              ))}
            </div>
            <div className="flex gap-2">
              <Button onClick={handleConfirmMethod} disabled={!selectedMethod}>
                Next
              </Button>
              <Button variant="outline" onClick={() => setStep('identify')}>
                Back
              </Button>
            </div>
          </div>
        )}

        {/* ── Step 3 ── */}
        {step === 'gather-approvals' && recoveryConfig && selectedMethod && (
          <div className="space-y-3">
            {selectedMethod === 'recovery-key' ? (
              <div className="space-y-1">
                <Label htmlFor="recovery-key-input">Recovery Key</Label>
                <Input
                  id="recovery-key-input"
                  type="password"
                  placeholder="Enter recovery key"
                  value={recoveryKey}
                  onChange={e => setRecoveryKey(e.target.value)}
                />
              </div>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  {approvedCount} of {recoveryConfig.threshold} required approvals collected.
                </p>
                <Progress value={(approvedCount / recoveryConfig.threshold) * 100} />
                {recoveryConfig.guardians && (
                  <ul className="space-y-1 text-sm">
                    {recoveryConfig.guardians.map(g => (
                      <li key={g.address} className="flex items-center gap-2">
                        <Badge variant={g.approved ? 'default' : 'secondary'}>
                          {g.approved ? '✓ Approved' : 'Pending'}
                        </Badge>
                        <span className="font-mono text-xs truncate">{g.address}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            )}
            <div className="flex gap-2">
              <Button onClick={handleApprove} disabled={loading}>
                {loading ? 'Submitting…' : 'Submit Approval'}
              </Button>
              <Button variant="outline" onClick={() => setStep('select-method')}>
                Back
              </Button>
            </div>
          </div>
        )}

        {/* ── Step 4 ── */}
        {step === 'execute' && recoveryConfig && (
          <div className="space-y-3">
            {recoveredDid ? (
              <>
                <Alert>
                  <AlertDescription>
                    Recovery successful! New DID document confirmed for{' '}
                    <span className="font-mono text-xs">{recoveredDid}</span>.
                  </AlertDescription>
                </Alert>
                <Button variant="outline" onClick={onCancel}>
                  Close
                </Button>
              </>
            ) : (
              <>
                <p className="text-sm text-muted-foreground">
                  Ready to execute recovery using{' '}
                  <strong>{selectedMethod ? methodLabel[selectedMethod] : ''}</strong>.
                  {selectedMethod !== 'recovery-key' && (
                    <span>
                      {' '}
                      {approvedCount} of {recoveryConfig.threshold} approvals collected.
                    </span>
                  )}
                </p>
                <div className="flex gap-2">
                  <Button onClick={handleExecute} disabled={loading}>
                    {loading ? 'Executing…' : 'Execute Recovery'}
                  </Button>
                  <Button variant="outline" onClick={() => setStep('gather-approvals')}>
                    Back
                  </Button>
                </div>
              </>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
