import React, { useState, useEffect, useCallback } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { Input, Label } from '@/components/ui/input';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ScreeningStatus = 'blocked' | 'suspicious' | 'clear' | 'pending';

export interface ScreeningResult {
  address: string;
  status: ScreeningStatus;
  riskScore: number;
  sanctionsLists: string[];
  checkedAt: number;
  details?: string;
}

export interface AuditEntry {
  id: string;
  eventType: string;
  address: string;
  description: string;
  timestamp: number;
  severity: 'info' | 'warning' | 'critical';
}

export interface ComplianceRule {
  id: string;
  name: string;
  description: string;
  jurisdiction: string;
  enabled: boolean;
  createdAt: number;
}

export interface ComplianceDashboardProps {
  sdk: any;
  address: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const PAGE_SIZE = 10;

const JURISDICTIONS = ['All', 'US', 'EU', 'UK', 'FATF', 'APAC', 'Global'];

const AUDIT_EVENT_TYPES = [
  'All',
  'screening',
  'credential_issued',
  'credential_revoked',
  'did_created',
  'rule_triggered',
  'access_denied',
];

function statusColor(status: ScreeningStatus): string {
  switch (status) {
    case 'blocked':
      return '#dc2626';
    case 'suspicious':
      return '#d97706';
    case 'clear':
      return '#16a34a';
    default:
      return '#6b7280';
  }
}

function riskLabel(score: number): string {
  if (score >= 80) return 'High';
  if (score >= 50) return 'Medium';
  return 'Low';
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleString();
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface PaginationProps {
  page: number;
  total: number;
  pageSize: number;
  onPage: (p: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({ page, total, pageSize, onPage }) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div
      style={{ display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'flex-end', marginTop: 12 }}
      aria-label="pagination"
    >
      <Button
        variant="outline"
        onClick={() => onPage(page - 1)}
        disabled={page === 0}
        aria-label="previous page"
        style={{ padding: '4px 10px' }}
      >
        ‹
      </Button>
      <span style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>
        {page + 1} / {totalPages}
      </span>
      <Button
        variant="outline"
        onClick={() => onPage(page + 1)}
        disabled={page >= totalPages - 1}
        aria-label="next page"
        style={{ padding: '4px 10px' }}
      >
        ›
      </Button>
    </div>
  );
};

// ─── RiskGauge ────────────────────────────────────────────────────────────────

interface RiskGaugeProps {
  score: number;
}

const RiskGauge: React.FC<RiskGaugeProps> = ({ score }) => {
  const clampedScore = Math.min(100, Math.max(0, score));
  const color =
    clampedScore >= 80
      ? '#dc2626'
      : clampedScore >= 50
      ? '#d97706'
      : '#16a34a';

  return (
    <div aria-label={`risk score gauge: ${clampedScore}`} style={{ textAlign: 'center', padding: 8 }}>
      <div style={{ fontSize: 32, fontWeight: 700, color }}>{clampedScore}</div>
      <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 6 }}>Risk Score</div>
      <Progress value={clampedScore} style={{ height: 10 }} />
      <Badge
        style={{
          marginTop: 6,
          backgroundColor: color,
          color: '#fff',
          fontSize: 11,
        }}
      >
        {riskLabel(clampedScore)} Risk
      </Badge>
    </div>
  );
};

// ─── Screening Tab ────────────────────────────────────────────────────────────

interface ScreeningTabProps {
  sdk: any;
  defaultAddress: string;
}

const ScreeningTab: React.FC<ScreeningTabProps> = ({ sdk, defaultAddress }) => {
  const [query, setQuery] = useState(defaultAddress);
  const [result, setResult] = useState<ScreeningResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runScreening = useCallback(async (addr: string) => {
    if (!addr.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const data = await sdk.compliance?.screenAddress?.(addr) ?? {
        address: addr,
        status: 'clear' as ScreeningStatus,
        riskScore: 0,
        sanctionsLists: [],
        checkedAt: Date.now(),
      };
      setResult(data);
    } catch (err: any) {
      setError(err?.message ?? 'Screening failed');
    } finally {
      setLoading(false);
    }
  }, [sdk]);

  const handleSearch = () => runScreening(query);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Address search */}
      <Card>
        <CardContent style={{ paddingTop: 16 }}>
          <Label htmlFor="screening-address">Stellar Address</Label>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <Input
              id="screening-address"
              placeholder="Enter Stellar address (G…)"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              style={{ flex: 1 }}
            />
            <Button onClick={handleSearch} disabled={loading}>
              {loading ? 'Screening…' : 'Screen'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <Card>
            <CardHeader>
              <CardTitle>Screening Result</CardTitle>
            </CardHeader>
            <CardContent>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>Status</span>
                <Badge style={{ backgroundColor: statusColor(result.status), color: '#fff' }}>
                  {result.status.toUpperCase()}
                </Badge>
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', marginBottom: 4 }}>
                Checked: {formatDate(result.checkedAt)}
              </div>
              {result.sanctionsLists.length > 0 && (
                <div style={{ marginTop: 8 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>Sanctions Lists</div>
                  {result.sanctionsLists.map((list) => (
                    <Badge key={list} variant="destructive" style={{ marginRight: 4 }}>
                      {list}
                    </Badge>
                  ))}
                </div>
              )}
              {result.details && (
                <div style={{ marginTop: 8, fontSize: 13, color: 'var(--color-text-secondary)' }}>
                  {result.details}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Risk Assessment</CardTitle>
            </CardHeader>
            <CardContent>
              <RiskGauge score={result.riskScore} />
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
};

// ─── Audit Tab ────────────────────────────────────────────────────────────────

interface AuditTabProps {
  sdk: any;
  address: string;
}

const AuditTab: React.FC<AuditTabProps> = ({ sdk, address }) => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [eventType, setEventType] = useState('All');

  const load = useCallback(async (p: number) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await sdk.compliance?.getAuditTrail?.({
        address,
        page: p,
        pageSize: PAGE_SIZE,
        dateFrom: dateFrom || undefined,
        dateTo: dateTo || undefined,
        eventType: eventType === 'All' ? undefined : eventType,
      }) ?? { entries: [], total: 0 };
      setEntries(resp.entries ?? []);
      setTotal(resp.total ?? 0);
      setPage(p);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to load audit trail');
    } finally {
      setLoading(false);
    }
  }, [sdk, address, dateFrom, dateTo, eventType]);

  useEffect(() => {
    load(0);
  }, [load]);

  const severityColor = (s: AuditEntry['severity']) =>
    s === 'critical' ? '#dc2626' : s === 'warning' ? '#d97706' : '#3b82f6';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Filters */}
      <Card>
        <CardContent style={{ paddingTop: 16 }}>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div>
              <Label htmlFor="audit-from">From</Label>
              <Input
                id="audit-from"
                type="date"
                value={dateFrom}
                onChange={(e) => setDateFrom(e.target.value)}
                style={{ marginTop: 4 }}
              />
            </div>
            <div>
              <Label htmlFor="audit-to">To</Label>
              <Input
                id="audit-to"
                type="date"
                value={dateTo}
                onChange={(e) => setDateTo(e.target.value)}
                style={{ marginTop: 4 }}
              />
            </div>
            <div>
              <Label htmlFor="audit-type">Event Type</Label>
              <select
                id="audit-type"
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                aria-label="Event type filter"
                style={{
                  display: 'block',
                  marginTop: 4,
                  padding: '6px 10px',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: 14,
                  background: 'var(--color-bg)',
                }}
              >
                {AUDIT_EVENT_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <Button onClick={() => load(0)} disabled={loading}>
              {loading ? 'Loading…' : 'Apply'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Entries */}
      <Card>
        <CardHeader>
          <CardTitle>Audit Trail ({total} entries)</CardTitle>
        </CardHeader>
        <CardContent>
          {entries.length === 0 && !loading && (
            <div style={{ color: 'var(--color-text-secondary)', fontSize: 14, padding: 16, textAlign: 'center' }}>
              No audit entries found.
            </div>
          )}
          {entries.map((entry) => (
            <div
              key={entry.id}
              style={{
                padding: '10px 0',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                gap: 12,
              }}
            >
              <div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 2 }}>
                  <Badge style={{ backgroundColor: severityColor(entry.severity), color: '#fff', fontSize: 10 }}>
                    {entry.severity}
                  </Badge>
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{entry.eventType}</span>
                </div>
                <div style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>{entry.description}</div>
              </div>
              <div style={{ fontSize: 12, color: 'var(--color-text-secondary)', whiteSpace: 'nowrap' }}>
                {formatDate(entry.timestamp)}
              </div>
            </div>
          ))}
          <Pagination page={page} total={total} pageSize={PAGE_SIZE} onPage={load} />
        </CardContent>
      </Card>
    </div>
  );
};

// ─── Rules Tab ────────────────────────────────────────────────────────────────

interface RulesTabProps {
  sdk: any;
}

const RulesTab: React.FC<RulesTabProps> = ({ sdk }) => {
  const [rules, setRules] = useState<ComplianceRule[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [jurisdiction, setJurisdiction] = useState('All');

  const load = useCallback(async (p: number) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await sdk.compliance?.getComplianceRules?.({
        page: p,
        pageSize: PAGE_SIZE,
        jurisdiction: jurisdiction === 'All' ? undefined : jurisdiction,
      }) ?? { rules: [], total: 0 };
      setRules(resp.rules ?? []);
      setTotal(resp.total ?? 0);
      setPage(p);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to load compliance rules');
    } finally {
      setLoading(false);
    }
  }, [sdk, jurisdiction]);

  useEffect(() => {
    load(0);
  }, [load]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Jurisdiction filter */}
      <Card>
        <CardContent style={{ paddingTop: 16 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-end' }}>
            <div>
              <Label htmlFor="jurisdiction-filter">Jurisdiction</Label>
              <select
                id="jurisdiction-filter"
                value={jurisdiction}
                onChange={(e) => setJurisdiction(e.target.value)}
                aria-label="Jurisdiction filter"
                style={{
                  display: 'block',
                  marginTop: 4,
                  padding: '6px 10px',
                  border: '1px solid var(--color-border)',
                  borderRadius: 'var(--radius-md)',
                  fontSize: 14,
                  background: 'var(--color-bg)',
                }}
              >
                {JURISDICTIONS.map((j) => (
                  <option key={j} value={j}>{j}</option>
                ))}
              </select>
            </div>
            <Button onClick={() => load(0)} disabled={loading}>
              {loading ? 'Loading…' : 'Filter'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Rules list */}
      <Card>
        <CardHeader>
          <CardTitle>Active Compliance Rules ({total})</CardTitle>
        </CardHeader>
        <CardContent>
          {rules.length === 0 && !loading && (
            <div style={{ color: 'var(--color-text-secondary)', fontSize: 14, padding: 16, textAlign: 'center' }}>
              No compliance rules found.
            </div>
          )}
          {rules.map((rule) => (
            <div
              key={rule.id}
              style={{
                padding: '12px 0',
                borderBottom: '1px solid var(--color-border)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>{rule.name}</div>
                <div style={{ fontSize: 13, color: 'var(--color-text-secondary)', marginBottom: 4 }}>
                  {rule.description}
                </div>
                <Badge variant="outline" style={{ fontSize: 11 }}>
                  {rule.jurisdiction}
                </Badge>
              </div>
              <Badge
                style={{
                  backgroundColor: rule.enabled ? '#16a34a' : '#6b7280',
                  color: '#fff',
                  fontSize: 11,
                  whiteSpace: 'nowrap',
                }}
              >
                {rule.enabled ? 'Active' : 'Disabled'}
              </Badge>
            </div>
          ))}
          <Pagination page={page} total={total} pageSize={PAGE_SIZE} onPage={load} />
        </CardContent>
      </Card>
    </div>
  );
};

// ─── Main Component ───────────────────────────────────────────────────────────

export const ComplianceDashboard: React.FC<ComplianceDashboardProps> = ({ sdk, address }) => {
  const [activeTab, setActiveTab] = useState('screening');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <Card>
        <CardHeader>
          <CardTitle>Compliance Dashboard</CardTitle>
        </CardHeader>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="screening">Screening</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
        </TabsList>

        <TabsContent value="screening">
          <ScreeningTab sdk={sdk} defaultAddress={address} />
        </TabsContent>

        <TabsContent value="audit">
          <AuditTab sdk={sdk} address={address} />
        </TabsContent>

        <TabsContent value="rules">
          <RulesTab sdk={sdk} />
        </TabsContent>
      </Tabs>
    </div>
  );
};
