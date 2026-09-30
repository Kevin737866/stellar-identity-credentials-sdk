import React, { useCallback, useMemo, useRef, useState } from 'react';
import {
  VerifiableCredential,
  CredentialVerificationResult,
} from '@stellar-identity/sdk';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SkeletonDetail } from '@/components/ui/skeleton';
import { LiveAnnouncer } from '@/components/ui/live-region';
import {
  Download,
  FileText,
  FileDown,
  Share2,
  CheckCircle,
  XCircle,
  Clock,
  AlertCircle,
  Copy,
} from 'lucide-react';

/** One entry in a credential's verification history. */
export interface CredentialHistoryEntry {
  /** Epoch ms the event occurred. */
  timestamp: number;
  /** What happened, e.g. `Issued` or `Revoked`. */
  action: string;
  /** Who performed it, usually the issuer address. */
  actor?: string;
  /** Free-text detail shown under the action. */
  detail?: string;
  /** Tones the timeline marker. */
  status?: 'success' | 'danger' | 'warning' | 'neutral';
}

export interface CredentialDetailProps {
  credential: VerifiableCredential;
  /** Current verification result, when the caller already has one. */
  verification?: CredentialVerificationResult;
  /**
   * Verification history. When omitted, a history is derived from the
   * credential's own fields (issuance and expiration), which is all that is
   * knowable without a ledger query.
   */
  history?: CredentialHistoryEntry[];
  /** Show the share/QR panel. Default true. */
  allowSharing?: boolean;
  /** Show the export buttons. Default true. */
  allowExport?: boolean;
  /** Rendered while a caller-supplied history is loading. */
  loading?: boolean;
}

const TABS = [
  { value: 'overview', label: 'Overview' },
  { value: 'attributes', label: 'Attributes' },
  { value: 'proof', label: 'Proof' },
  { value: 'history', label: 'History' },
] as const;

type TabValue = (typeof TABS)[number]['value'];

/** Human-readable name, falling back to the id. */
function credentialLabel(credential: VerifiableCredential): string {
  return credential.type?.find(t => t !== 'VerifiableCredential') ?? credential.id;
}

function formatDate(value: number | undefined): string {
  if (!value) return 'Never';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

/**
 * Derive a minimal history from the credential itself.
 *
 * Issuance and expiry are facts on the credential; revocation only shows up
 * when the caller passes a verification result, so it is added here rather
 * than being invented.
 */
function deriveHistory(
  credential: VerifiableCredential,
  verification?: CredentialVerificationResult,
): CredentialHistoryEntry[] {
  const entries: CredentialHistoryEntry[] = [];

  entries.push({
    timestamp: credential.issuanceDate,
    action: 'Issued',
    actor: credential.issuer,
    detail: `Credential ${credential.id} was issued.`,
    status: 'success',
  });

  if (verification?.revoked) {
    entries.push({
      timestamp: Date.now(),
      action: 'Revoked',
      actor: credential.issuer,
      detail: 'The issuer revoked this credential.',
      status: 'danger',
    });
  }

  if (credential.expirationDate) {
    const expired = verification?.expired ?? Date.now() > credential.expirationDate;
    entries.push({
      timestamp: credential.expirationDate,
      action: expired ? 'Expired' : 'Expires',
      actor: credential.issuer,
      detail: expired
        ? 'This credential is past its expiration date.'
        : 'This credential will stop being valid at this time.',
      status: expired ? 'warning' : 'neutral',
    });
  }

  return entries.sort((a, b) => a.timestamp - b.timestamp);
}

/** Flatten a nested attribute object into `path -> primitive` pairs. */
export function flattenAttributes(
  input: unknown,
  prefix = '',
): Array<{ path: string; value: string }> {
  if (input === null || input === undefined) return [];

  if (typeof input !== 'object') {
    return [{ path: prefix || 'value', value: String(input) }];
  }

  if (Array.isArray(input)) {
    if (input.length === 0) return [{ path: prefix, value: '[]' }];
    return input.flatMap((item, index) =>
      flattenAttributes(item, prefix ? `${prefix}[${index}]` : `[${index}]`),
    );
  }

  return Object.entries(input as Record<string, unknown>).flatMap(([key, value]) =>
    flattenAttributes(value, prefix ? `${prefix}.${key}` : key),
  );
}

/** Serialise a credential for export, with a wrapper for provenance. */
export function buildExportPayload(
  credential: VerifiableCredential,
  verification?: CredentialVerificationResult,
): string {
  return JSON.stringify(
    {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      exportedAt: new Date().toISOString(),
      verification: verification ?? null,
      credential,
    },
    null,
    2,
  );
}

/**
 * Trigger a browser download for `content`.
 *
 * Uses a data URL rather than a Blob so it works in jsdom and in browsers
 * without a `URL.createObjectURL` implementation, at the cost of size limits
 * on very large payloads.
 */
function downloadFile(content: string, filename: string, mimeType: string): void {
  const uri = `data:${mimeType};charset=utf-8,${encodeURIComponent(content)}`;
  const link = document.createElement('a');
  link.setAttribute('href', uri);
  link.setAttribute('download', filename);
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

/**
 * Render a credential as a minimal scannable QR-style matrix.
 *
 * This is intentionally *not* a real QR encoder. Encoding a real QR code needs
 * a Reed-Solomon implementation and a mask selection pass, and shipping a
 * hand-rolled approximation would produce codes that ordinary scanners decode
 * to the wrong value — worse than no code at all. What this provides is a
 * deterministic visual fingerprint of the credential, useful for confirming
 * at a glance that two parties hold the same credential.
 *
 * The full credential is always available in the adjacent text field, so
 * sharing does not depend on scanning the image.
 */
function CredentialFingerprint({ value, size = 148 }: { value: string; size?: number }) {
  const modules = 21;
  const cells = useMemo(() => {
    // FNV-1a, expanded into a deterministic bit matrix. Cheap, stable, and
    // sufficient for a visual fingerprint.
    let hash = 0x811c9dc5;
    const bits: boolean[] = [];
    for (let i = 0; i < value.length; i++) {
      hash ^= value.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
      for (let b = 0; b < 24; b++) {
        hash ^= hash << 13;
        hash >>>= 0;
        hash ^= hash >> 17;
        hash ^= hash << 5;
        hash >>>= 0;
        bits.push((hash >>> (b % 32)) & 1 ? true : false);
      }
    }
    // Ensure we have enough bits for a full matrix.
    while (bits.length < modules * modules) {
      bits.push(bits[bits.length % Math.max(1, value.length)] ?? false);
    }
    return bits.slice(0, modules * modules);
  }, [value]);

  const cellSize = size / modules;
  // Standard finder patterns in three corners, so it reads as a code at a glance.
  const isFinder = (row: number, col: number): boolean => {
    const inBox = (r0: number, c0: number) => {
      const dr = row - r0;
      const dc = col - c0;
      if (dr < 0 || dc < 0 || dr > 6 || dc > 6) return false;
      const ring = Math.max(Math.abs(dr - 3), Math.abs(dc - 3));
      return ring !== 2;
    };
    return inBox(0, 0) || inBox(0, modules - 7) || inBox(modules - 7, 0);
  };

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      role="img"
      aria-label="Credential fingerprint image"
      data-testid="credential-fingerprint"
      style={{
        borderRadius: 'var(--radius-md)',
        backgroundColor: '#ffffff',
        padding: '8px',
        boxSizing: 'content-box',
        border: '1px solid var(--color-border)',
      }}
    >
      <rect width={size} height={size} fill="#ffffff" />
      {Array.from({ length: modules * modules }, (_, index) => {
        const row = Math.floor(index / modules);
        const col = index % modules;
        const filled = isFinder(row, col) || cells[index];
        if (!filled) return null;
        return (
          <rect
            key={index}
            x={col * cellSize}
            y={row * cellSize}
            width={cellSize}
            height={cellSize}
            fill="#000000"
          />
        );
      })}
    </svg>
  );
}

/** A labelled read-only field. */
const Field: React.FC<{ label: string; children: React.ReactNode; mono?: boolean }> = ({
  label,
  children,
  mono,
}) => (
  <div style={{ minWidth: 0 }}>
    <dt
      style={{
        fontSize: 'var(--font-size-xs)',
        color: 'var(--color-text-secondary)',
        marginBottom: 'var(--space-1)',
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {label}
    </dt>
    <dd
      style={{
        margin: 0,
        fontSize: 'var(--font-size-sm)',
        color: 'var(--color-text)',
        wordBreak: 'break-all',
        fontFamily: mono ? 'var(--font-family-mono, monospace)' : undefined,
      }}
    >
      {children}
    </dd>
  </div>
);

/**
 * Detailed view of a single credential, with tabs for Overview, Attributes,
 * Proof and History.
 *
 * @example
 * ```tsx
 * <CredentialDetail credential={credential} verification={verification} />
 * ```
 */
export const CredentialDetail: React.FC<CredentialDetailProps> = ({
  credential,
  verification,
  history,
  allowSharing = true,
  allowExport = true,
  loading = false,
}) => {
  const [activeTab, setActiveTab] = useState<TabValue>('overview');
  const [announcement, setAnnouncement] = useState('');
  const [copied, setCopied] = useState(false);
  const shareRef = useRef<HTMLDivElement>(null);

  const label = credentialLabel(credential);
  const entries = useMemo(
    () => history ?? deriveHistory(credential, verification),
    [history, credential, verification],
  );
  const attributes = useMemo(
    () => flattenAttributes(credential.credentialData),
    [credential.credentialData],
  );

  const status = verification?.revoked
    ? { label: 'Revoked', variant: 'destructive' as const, Icon: XCircle, color: 'text-red-500' }
    : verification?.expired
      ? { label: 'Expired', variant: 'secondary' as const, Icon: Clock, color: 'text-yellow-500' }
      : verification?.valid
        ? { label: 'Valid', variant: 'default' as const, Icon: CheckCircle, color: 'text-green-500' }
        : { label: 'Unverified', variant: 'outline' as const, Icon: AlertCircle, color: 'text-gray-500' };

  const shareUrl = useMemo(() => {
    const payload = buildExportPayload(credential, verification);
    const base =
      typeof window !== 'undefined' && window.location
        ? window.location.origin
        : 'https://app.stellar-identity.example';
    return `${base}/share/${encodeURIComponent(btoa(payload))}`;
  }, [credential, verification]);

  const handleExportJSON = useCallback(() => {
    downloadFile(
      buildExportPayload(credential, verification),
      `credential-${credential.id}.json`,
      'application/json',
    );
    setAnnouncement('Credential exported as JSON');
  }, [credential, verification]);

  /**
   * Export as PDF.
   *
   * A real PDF needs a font subset and a page tree, so this writes a
   * print-ready HTML document that the browser's own print-to-PDF produces.
   * The output is a valid PDF when saved from the print dialog, and the
   * approach adds no runtime dependency to the bundle.
   */
  const handleExportPDF = useCallback(() => {
    const rows = attributes
      .map(a => `<tr><th style="text-align:left;padding:4px 12px 4px 0">${a.path}</th><td style="padding:4px 0">${a.value}</td></tr>`)
      .join('');

    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${credential.id}</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#111}
h1{font-size:1.25rem}h2{font-size:1rem;margin-top:1.5rem}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #ddd;font-size:0.85rem;font-weight:400;text-align:left}
th{width:30%;color:#555}</style></head><body>
<h1>Verifiable Credential</h1>
<p><strong>ID:</strong> ${credential.id}<br>
<strong>Issuer:</strong> ${credential.issuer}<br>
<strong>Subject:</strong> ${credential.subject}<br>
<strong>Issued:</strong> ${formatDate(credential.issuanceDate)}<br>
<strong>Expires:</strong> ${formatDate(credential.expirationDate)}<br>
<strong>Status:</strong> ${status.label}</p>
<h2>Types</h2><p>${(credential.type ?? []).join(', ')}</p>
<h2>Attributes</h2><table>${rows}</table>
${credential.proof ? `<h2>Proof</h2><pre style="word-break:break-all;font-size:0.75rem">${credential.proof}</pre>` : ''}
<h2>Verification History</h2><ul>${entries
      .map(e => `<li>${formatDate(e.timestamp)} — ${e.action}</li>`)
      .join('')}</ul>
</body></html>`;

    const printWindow = window.open('', '_blank', 'noopener,noreferrer,width=800,height=900');
    if (!printWindow) {
      setAnnouncement('Pop-up blocked. Allow pop-ups to export a PDF.');
      return;
    }
    printWindow.document.write(html);
    printWindow.document.close();
    printWindow.focus();
    setAnnouncement('Print dialog opened. Choose "Save as PDF" to export.');
  }, [attributes, credential, entries, status.label]);

  const handleCopyShareLink = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopied(true);
      setAnnouncement('Share link copied to clipboard');
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setAnnouncement('Could not copy. Select the link and copy manually.');
    }
  }, [shareUrl]);

  if (loading) {
    return <SkeletonDetail fields={8} />;
  }

  const { Icon } = status;

  return (
    <div className="credential-detail">
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'space-between',
          gap: 'var(--space-4)',
          marginBottom: 'var(--space-5)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
          <FileText className="h-6 w-6" aria-hidden="true" style={{ flexShrink: 0 }} />
          <div style={{ minWidth: 0 }}>
            <h3 style={{ margin: 0, fontSize: 'var(--font-size-lg)', fontWeight: 'var(--font-weight-semibold)' }}>
              {label}
            </h3>
            <p style={{ margin: 0, fontSize: 'var(--font-size-xs)', color: 'var(--color-text-secondary)' }}>
              {credential.id}
            </p>
          </div>
        </div>
        <Badge variant={status.variant}>
          <Icon className={`h-3 w-3 mr-1 ${status.color}`} aria-hidden="true" />
          {status.label}
        </Badge>
      </div>

      <Tabs value={activeTab} onValueChange={value => setActiveTab(value as TabValue)}>
        <TabsList>
          {TABS.map(tab => (
            <TabsTrigger key={tab.value} value={tab.value}>
              {tab.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {/* ── Overview ── */}
        <TabsContent value="overview">
          <dl
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(12rem, 1fr))',
              gap: 'var(--space-4)',
            }}
          >
            <Field label="Credential ID" mono>
              {credential.id}
            </Field>
            <Field label="Issuer" mono>
              {credential.issuer}
            </Field>
            <Field label="Subject" mono>
              {credential.subject}
            </Field>
            <Field label="Issued">{formatDate(credential.issuanceDate)}</Field>
            <Field label="Expires">{formatDate(credential.expirationDate)}</Field>
            <Field label="Types">
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: 'var(--space-1)' }}>
                {(credential.type ?? []).map(type => (
                  <Badge key={type} variant="outline" className="text-xs">
                    {type}
                  </Badge>
                ))}
              </span>
            </Field>
          </dl>

          {(allowExport || allowSharing) && (
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 'var(--space-2)',
                marginTop: 'var(--space-5)',
                paddingTop: 'var(--space-4)',
                borderTop: '1px solid var(--color-border)',
              }}
            >
              {allowExport && (
                <>
                  <Button variant="outline" size="sm" onClick={handleExportJSON}>
                    <Download className="h-4 w-4 mr-2" aria-hidden="true" />
                    Export JSON
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleExportPDF}>
                    <FileDown className="h-4 w-4 mr-2" aria-hidden="true" />
                    Export PDF
                  </Button>
                </>
              )}
              {allowSharing && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setActiveTab('overview');
                    shareRef.current?.scrollIntoView({ block: 'nearest' });
                    setAnnouncement('Share options shown below');
                  }}
                >
                  <Share2 className="h-4 w-4 mr-2" aria-hidden="true" />
                  Share
                </Button>
              )}
            </div>
          )}
        </TabsContent>

        {/* ── Attributes ── */}
        <TabsContent value="attributes">
          {attributes.length === 0 ? (
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              This credential has no attributes.
            </p>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <caption className="sr-only">
                Attributes contained in {label}
              </caption>
              <thead>
                <tr>
                  <th
                    scope="col"
                    style={{
                      textAlign: 'left',
                      fontSize: 'var(--font-size-xs)',
                      color: 'var(--color-text-secondary)',
                      padding: '0 12px 8px 0',
                      borderBottom: '1px solid var(--color-border)',
                    }}
                  >
                    Attribute
                  </th>
                  <th
                    scope="col"
                    style={{
                      textAlign: 'left',
                      fontSize: 'var(--font-size-xs)',
                      color: 'var(--color-text-secondary)',
                      padding: '0 0 8px',
                      borderBottom: '1px solid var(--color-border)',
                    }}
                  >
                    Value
                  </th>
                </tr>
              </thead>
              <tbody>
                {attributes.map(attribute => (
                  <tr key={attribute.path}>
                    <th
                      scope="row"
                      style={{
                        textAlign: 'left',
                        fontWeight: 'var(--font-weight-medium)' as any,
                        fontSize: 'var(--font-size-sm)',
                        padding: '8px 12px 8px 0',
                        borderBottom: '1px solid var(--color-border)',
                        verticalAlign: 'top',
                        wordBreak: 'break-all',
                      }}
                    >
                      {attribute.path}
                    </th>
                    <td
                      style={{
                        fontSize: 'var(--font-size-sm)',
                        padding: '8px 0',
                        borderBottom: '1px solid var(--color-border)',
                        wordBreak: 'break-word',
                      }}
                    >
                      {attribute.value}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </TabsContent>

        {/* ── Proof ── */}
        <TabsContent value="proof">
          {credential.proof ? (
            <div>
              <Field label="Signature" mono>
                <pre
                  style={{
                    margin: 0,
                    padding: 'var(--space-3)',
                    backgroundColor: 'var(--color-bg-secondary)',
                    borderRadius: 'var(--radius-md)',
                    overflowX: 'auto',
                    fontSize: 'var(--font-size-xs)',
                  }}
                >
                  {credential.proof}
                </pre>
              </Field>
              <div style={{ marginTop: 'var(--space-4)' }}>
                <Field label="Verification status">
                  {verification
                    ? `${status.label} — checked against the issuer's status list.`
                    : 'Not verified. Run a verification to check this proof against the issuer.'}
                </Field>
              </div>
            </div>
          ) : (
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              This credential has no proof attached.
            </p>
          )}
        </TabsContent>

        {/* ── History ── */}
        <TabsContent value="history">
          {entries.length === 0 ? (
            <p style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--font-size-sm)' }}>
              No verification history available.
            </p>
          ) : (
            <ol
              style={{ listStyle: 'none', margin: 0, padding: 0 }}
              aria-label="Verification history"
            >
              {entries.map((entry, index) => {
                const tone =
                  entry.status === 'danger'
                    ? 'var(--color-danger-600, #dc2626)'
                    : entry.status === 'success'
                      ? 'var(--color-success-600, #16a34a)'
                      : entry.status === 'warning'
                        ? 'var(--color-warning-600, #d97706)'
                        : 'var(--color-border)';
                const isLast = index === entries.length - 1;

                return (
                  <li
                    key={`${entry.action}-${entry.timestamp}`}
                    style={{ display: 'flex', gap: 'var(--space-3)' }}
                  >
                    <div
                      style={{
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        flexShrink: 0,
                      }}
                    >
                      <span
                        aria-hidden="true"
                        style={{
                          width: '10px',
                          height: '10px',
                          borderRadius: '50%',
                          backgroundColor: tone,
                          marginTop: '6px',
                          flexShrink: 0,
                        }}
                      />
                      {!isLast && (
                        <span
                          aria-hidden="true"
                          style={{
                            width: '2px',
                            flex: 1,
                            minHeight: '24px',
                            backgroundColor: 'var(--color-border)',
                            margin: '2px 0',
                          }}
                        />
                      )}
                    </div>
                    <div style={{ paddingBottom: isLast ? 0 : 'var(--space-4)', minWidth: 0 }}>
                      <p
                        style={{
                          margin: 0,
                          fontSize: 'var(--font-size-sm)',
                          fontWeight: 'var(--font-weight-medium)' as any,
                        }}
                      >
                        {entry.action}
                      </p>
                      <p
                        style={{
                          margin: 0,
                          fontSize: 'var(--font-size-xs)',
                          color: 'var(--color-text-secondary)',
                        }}
                      >
                        {formatDate(entry.timestamp)}
                        {entry.actor ? ` · ${entry.actor}` : ''}
                      </p>
                      {entry.detail && (
                        <p
                          style={{
                            margin: '4px 0 0',
                            fontSize: 'var(--font-size-xs)',
                            color: 'var(--color-text-secondary)',
                          }}
                        >
                          {entry.detail}
                        </p>
                      )}
                    </div>
                  </li>
                );
              })}
            </ol>
          )}
        </TabsContent>
      </Tabs>

      {/* ── Sharing ── */}
      {allowSharing && (
        <div
          ref={shareRef}
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 'var(--space-4)',
            alignItems: 'center',
            marginTop: 'var(--space-5)',
            paddingTop: 'var(--space-4)',
            borderTop: '1px solid var(--color-border)',
          }}
        >
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: 'var(--space-2)',
              alignItems: 'center',
            }}
          >
            <CredentialFingerprint value={credential.id} />
            <p
              style={{
                margin: 0,
                fontSize: 'var(--font-size-xs)',
                color: 'var(--color-text-secondary)',
                maxWidth: '148px',
                textAlign: 'center',
              }}
            >
              Fingerprint of this credential. Share the link below to transfer it.
            </p>
          </div>

          <div style={{ flex: 1, minWidth: '12rem' }}>
            <Field label="Share link" mono>
              <input
                type="text"
                readOnly
                value={shareUrl}
                aria-label="Credential share link"
                onFocus={event => event.currentTarget.select()}
                style={{
                  width: '100%',
                  fontSize: 'var(--font-size-xs)',
                  padding: 'var(--space-2)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--color-border)',
                  backgroundColor: 'var(--color-bg-secondary)',
                  color: 'var(--color-text)',
                  fontFamily: 'var(--font-family-mono, monospace)',
                }}
              />
            </Field>
            <Button variant="secondary" size="sm" onClick={handleCopyShareLink}>
              <Copy className="h-4 w-4 mr-2" aria-hidden="true" />
              {copied ? 'Copied' : 'Copy link'}
            </Button>
          </div>
        </div>
      )}

      <LiveAnnouncer message={announcement} />
    </div>
  );
};
CredentialDetail.displayName = 'CredentialDetail';
