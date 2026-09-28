import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertCircle,
  Clock,
  User,
  FileText,
  Award,
} from 'lucide-react';

export interface CredentialOffer {
  id: string;
  type: string[];
  issuer: {
    id: string;
    name?: string;
    did?: string;
  };
  offeredAttributes: Record<string, unknown>;
  issuanceDate?: number;
  expirationDate?: number;
  proof?: string;
}

export interface CredentialOfferModalProps {
  offer: CredentialOffer | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAccept: (offer: CredentialOffer) => Promise<void>;
  onReject: (offer: CredentialOffer) => void;
  loading?: boolean;
  error?: string | null;
}

export const CredentialOfferModal: React.FC<CredentialOfferModalProps> = ({
  offer,
  open,
  onOpenChange,
  onAccept,
  onReject,
  loading: externalLoading,
  error: externalError,
}) => {
  const [internalLoading, setInternalLoading] = useState(false);
  const [internalError, setInternalError] = useState<string | null>(null);
  const [accepting, setAccepting] = useState(false);
  const overlayRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);

  const loading = externalLoading ?? internalLoading;
  const error = externalError ?? internalError;

  const isExpired = useCallback((): boolean => {
    if (!offer?.expirationDate) return false;
    return Date.now() > offer.expirationDate;
  }, [offer]);

  useEffect(() => {
    if (!open) {
      setInternalError(null);
      setAccepting(false);
    }
  }, [open]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && open && !loading) {
        onOpenChange(false);
      }
    };
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [open, loading, onOpenChange]);

  useEffect(() => {
    if (open && contentRef.current) {
      const firstFocusable = contentRef.current.querySelector<HTMLElement>(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      firstFocusable?.focus();
    }
  }, [open]);

  const handleOverlayClick = useCallback(
    (e: React.MouseEvent) => {
      if (e.target === overlayRef.current && !loading) {
        onOpenChange(false);
      }
    },
    [loading, onOpenChange]
  );

  const handleAccept = async () => {
    if (!offer) return;
    try {
      setInternalLoading(true);
      setAccepting(true);
      setInternalError(null);
      await onAccept(offer);
      onOpenChange(false);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to accept credential offer';
      setInternalError(message);
    } finally {
      setInternalLoading(false);
      setAccepting(false);
    }
  };

  const handleReject = () => {
    if (!offer || loading) return;
    onReject(offer);
    onOpenChange(false);
  };

  if (!open || !offer) return null;

  const expired = isExpired();
  const credentialType = offer.type[offer.type.length - 1] ?? 'Unknown';
  const issuerName = offer.issuer.name ?? offer.issuer.did ?? offer.issuer.id;
  const issuerShort = issuerName.length > 20
    ? `${issuerName.substring(0, 8)}...${issuerName.substring(issuerName.length - 4)}`
    : issuerName;

  const formatDate = (timestamp?: number): string => {
    if (!timestamp) return 'N/A';
    return new Date(timestamp).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const timeUntilExpiry = (): string => {
    if (!offer.expirationDate) return 'No expiration';
    const diff = offer.expirationDate - Date.now();
    if (diff <= 0) return 'Expired';
    const days = Math.floor(diff / 86400000);
    const hours = Math.floor((diff % 86400000) / 3600000);
    if (days > 0) return `${days}d ${hours}h remaining`;
    return `${hours}h remaining`;
  };

  return (
    <div
      ref={overlayRef}
      onClick={handleOverlayClick}
      role="dialog"
      aria-modal="true"
      aria-label={`Credential offer: ${credentialType}`}
      aria-describedby="credential-offer-description"
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'rgba(0, 0, 0, 0.5)',
      }}
    >
      <div
        ref={contentRef}
        style={{
          backgroundColor: 'var(--color-bg)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-xl)',
          width: '100%',
          maxWidth: '28rem',
          maxHeight: '90vh',
          overflowY: 'auto',
          margin: 'var(--space-4)',
        }}
      >
        <Card>
          <CardHeader>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                <Shield style={{ width: 24, height: 24, color: 'var(--color-primary)' }} />
                <CardTitle style={{ fontSize: 'var(--font-size-lg)', margin: 0 }}>
                  Credential Offer
                </CardTitle>
              </div>
              {expired ? (
                <Badge style={{ backgroundColor: 'var(--color-destructive)', color: 'white' }}>
                  Expired
                </Badge>
              ) : (
                <Badge style={{ backgroundColor: 'var(--color-primary)', color: 'white' }}>
                  Pending
                </Badge>
              )}
            </div>
            <CardDescription id="credential-offer-description">
              You have been offered a verifiable credential
            </CardDescription>
          </CardHeader>

          <CardContent>
            {error && (
              <Alert style={{ marginBottom: 'var(--space-4)' }}>
                <AlertCircle style={{ width: 16, height: 16 }} />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                  <Award style={{ width: 16, height: 16, color: 'var(--color-primary)' }} />
                  <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, color: 'var(--color-muted-foreground)' }}>
                    Credential Type
                  </span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
                  {offer.type.map((t, i) => (
                    <Badge key={i} variant="outline" style={{ fontSize: 'var(--font-size-xs)' }}>
                      {t}
                    </Badge>
                  ))}
                </div>
              </div>

              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                  <User style={{ width: 16, height: 16, color: 'var(--color-primary)' }} />
                  <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, color: 'var(--color-muted-foreground)' }}>
                    Issuer
                  </span>
                </div>
                <span style={{ fontSize: 'var(--font-size-sm)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {issuerShort}
                </span>
              </div>

              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)', marginBottom: 'var(--space-1)' }}>
                  <FileText style={{ width: 16, height: 16, color: 'var(--color-primary)' }} />
                  <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 600, color: 'var(--color-muted-foreground)' }}>
                    Offered Attributes
                  </span>
                </div>
                <div style={{ backgroundColor: 'var(--color-muted)', borderRadius: 'var(--radius)', padding: 'var(--space-3)' }}>
                  {Object.entries(offer.offeredAttributes).length === 0 ? (
                    <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-muted-foreground)' }}>
                      No attributes disclosed
                    </span>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                      {Object.entries(offer.offeredAttributes).map(([key, value]) => (
                        <div key={key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span style={{ fontSize: 'var(--font-size-sm)', fontWeight: 500 }}>{key}</span>
                          <span style={{ fontSize: 'var(--font-size-sm)', color: 'var(--color-muted-foreground)' }}>
                            {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-2)' }}>
                <div>
                  <span style={{ fontSize: 'var(--font-size-xs)', fontWeight: 600, color: 'var(--color-muted-foreground)' }}>
                    Issued
                  </span>
                  <p style={{ fontSize: 'var(--font-size-xs)', margin: 0, marginTop: 2 }}>
                    {formatDate(offer.issuanceDate)}
                  </p>
                </div>
                <div>
                  <span style={{ fontSize: 'var(--font-size-xs)', fontWeight: 600, color: 'var(--color-muted-foreground)' }}>
                    Expiration
                  </span>
                  <p style={{ fontSize: 'var(--font-size-xs)', margin: 0, marginTop: 2 }}>
                    {offer.expirationDate ? formatDate(offer.expirationDate) : 'Never'}
                  </p>
                </div>
              </div>

              {offer.expirationDate && !expired && (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', marginBottom: 'var(--space-1)' }}>
                    <Clock style={{ width: 12, height: 12, color: 'var(--color-muted-foreground)' }} />
                    <span style={{ fontSize: 'var(--font-size-xs)', color: 'var(--color-muted-foreground)' }}>
                      {timeUntilExpiry()}
                    </span>
                  </div>
                  <Progress value={((Date.now() - (offer.issuanceDate ?? Date.now())) / (offer.expirationDate - (offer.issuanceDate ?? Date.now()))) * 100} />
                </div>
              )}

              {loading && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-2)', padding: 'var(--space-2)' }}>
                  <div style={{
                    width: 16, height: 16,
                    border: '2px solid var(--color-border)',
                    borderTopColor: 'var(--color-primary)',
                    borderRadius: '50%',
                    animation: 'spin 0.6s linear infinite',
                  }} />
                  <span style={{ fontSize: 'var(--font-size-sm)' }}>
                    {accepting ? 'Accepting credential...' : 'Processing...'}
                  </span>
                </div>
              )}
            </div>
          </CardContent>

          <CardFooter style={{ display: 'flex', justifyContent: 'flex-end', gap: 'var(--space-2)' }}>
            <Button
              variant="outline"
              onClick={handleReject}
              disabled={loading}
              aria-label="Reject credential offer"
            >
              <XCircle style={{ width: 16, height: 16, marginRight: 'var(--space-1)' }} />
              Reject
            </Button>
            <Button
              onClick={handleAccept}
              disabled={loading || expired}
              aria-label="Accept credential offer"
            >
              {accepting ? (
                <>
                  <div style={{
                    width: 16, height: 16,
                    border: '2px solid rgba(255,255,255,0.3)',
                    borderTopColor: 'white',
                    borderRadius: '50%',
                    animation: 'spin 0.6s linear infinite',
                    marginRight: 'var(--space-1)',
                  }} />
                  Accepting...
                </>
              ) : (
                <>
                  <CheckCircle style={{ width: 16, height: 16, marginRight: 'var(--space-1)' }} />
                  Accept
                </>
              )}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
};
