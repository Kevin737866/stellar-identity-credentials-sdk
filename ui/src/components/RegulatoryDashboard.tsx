import React, { useState, useEffect, useCallback } from 'react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
  CardDescription,
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Input, Label } from '@/components/ui/input';
import { Progress } from '@/components/ui/progress';
import {
  RegulatoryReportingClient,
  ReportTemplate,
  RegulatoryReport,
  SARReport,
  ReportSchedule,
  TransactionReport,
  ExportFormat,
  PaginatedReports,
  PaginatedSARs,
  DEFAULT_TEMPLATES,
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import {
  FileText,
  AlertTriangle,
  Calendar,
  Download,
  Clock,
  Activity,
  Shield,
  FileSpreadsheet,
  FileJson,
  FileType,
  Plus,
  RefreshCw,
  Search,
  CheckCircle,
  XCircle,
  AlertCircle,
  BarChart3,
  TrendingUp,
  Settings,
  Trash2,
  Eye,
  ChevronDown,
  Upload,
  ClipboardList,
  Flag,
  Database,
} from 'lucide-react';

interface RegulatoryDashboardProps {
  sdk: any; // StellarIdentitySDK instance
  address: string;
  keypair: Keypair;
}

type ReportTab = 'overview' | 'templates' | 'reports' | 'sar' | 'schedules' | 'export';

export const RegulatoryDashboard: React.FC<RegulatoryDashboardProps> = ({ sdk, address, keypair }) => {
  const [activeTab, setActiveTab] = useState<ReportTab>('overview');
  const [reportingClient, setReportingClient] = useState<RegulatoryReportingClient | null>(null);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [reports, setReports] = useState<PaginatedReports>({ data: [], page: 0, total: 0, hasMore: false });
  const [sars, setSARs] = useState<PaginatedSARs>({ data: [], page: 0, total: 0, hasMore: false });
  const [schedules, setSchedules] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportFormat, setExportFormat] = useState<ExportFormat>('json');

  // SAR form state
  const [sarForm, setSarForm] = useState({
    subject: '',
    activityType: 'structuring',
    description: '',
    estimatedValue: '',
    currency: 'USD',
    notifyRegulators: 'FINCEN',
  });

  // Schedule form state
  const [scheduleForm, setScheduleForm] = useState({
    scheduleId: '',
    templateId: 'FATF_TRAVEL_RULE',
    intervalHours: 24,
    exportFormats: ['json'] as ExportFormat[],
  });

  // Transaction report form state
  const [txReportForm, setTxReportForm] = useState({
    transactionCount: 0,
    totalVolume: 0,
    periodStart: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10),
    periodEnd: new Date().toISOString().slice(0, 10),
    asset: 'USDC',
    suspiciousCount: 0,
  });

  useEffect(() => {
    if (sdk?.config) {
      const client = new RegulatoryReportingClient(sdk.config);
      setReportingClient(client);
    }
  }, [sdk]);

  useEffect(() => {
    if (reportingClient) {
      loadData();
    }
  }, [reportingClient, activeTab]);

  const loadData = async () => {
    if (!reportingClient) return;
    setLoading(true);
    setError(null);
    try {
      const [loadedTemplates, loadedReports, loadedSARs] = await Promise.all([
        reportingClient.getAllTemplates(),
        reportingClient.getReports(address, 0, 20),
        reportingClient.getSARs(0, 20),
      ]);
      setTemplates(loadedTemplates);
      setReports(loadedReports);
      setSARs(loadedSARs);
    } catch (err: any) {
      setError(err.message || 'Failed to load reporting data');
    } finally {
      setLoading(false);
    }
  };

  // ── Overview stats ──────────────────────────────────────────────────────────

  const stats = {
    totalTemplates: templates.length,
    totalReports: reports.total,
    totalSARs: sars.total,
    activeSchedules: schedules.length,
    highRiskReports: reports.data.filter(r => r.riskScore >= 70).length,
  };

  // ── SAR filing ──────────────────────────────────────────────────────────────

  const fileSAR = async () => {
    if (!reportingClient || !keypair) return;
    setLoading(true);
    setError(null);
    try {
      await reportingClient.fileSAR(keypair, {
        subject: sarForm.subject || address,
        activityType: sarForm.activityType,
        description: sarForm.description,
        relatedTransactions: [],
        estimatedValue: sarForm.estimatedValue,
        currency: sarForm.currency,
        notifyRegulators: sarForm.notifyRegulators.split(',').map(s => s.trim()).filter(Boolean),
        evidenceHashes: [],
        activityTimestamp: Math.floor(Date.now() / 1000),
      });
      setSarForm({ ...sarForm, description: '', estimatedValue: '' });
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to file SAR');
    } finally {
      setLoading(false);
    }
  };

  // ── Schedule management ─────────────────────────────────────────────────────

  const createSchedule = async () => {
    if (!reportingClient || !keypair) return;
    setLoading(true);
    setError(null);
    try {
      await reportingClient.scheduleReport(
        keypair,
        scheduleForm.scheduleId || `SCHED_${Date.now()}`,
        scheduleForm.templateId,
        address,
        scheduleForm.intervalHours * 3600,
        scheduleForm.exportFormats,
      );
      const loadedSchedules = await reportingClient.getSchedules();
      setSchedules(loadedSchedules);
    } catch (err: any) {
      setError(err.message || 'Failed to create schedule');
    } finally {
      setLoading(false);
    }
  };

  // ── Transaction report filing ───────────────────────────────────────────────

  const fileTransactionReport = async () => {
    if (!reportingClient || !keypair) return;
    setLoading(true);
    setError(null);
    try {
      await reportingClient.fileTransactionReport(
        keypair,
        address,
        txReportForm.transactionCount,
        txReportForm.totalVolume,
        Math.floor(new Date(txReportForm.periodStart).getTime() / 1000),
        Math.floor(new Date(txReportForm.periodEnd).getTime() / 1000),
        txReportForm.asset,
        txReportForm.transactionCount > 0 ? Math.floor(txReportForm.totalVolume / txReportForm.transactionCount) : 0,
        txReportForm.totalVolume,
        txReportForm.suspiciousCount,
      );
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to file transaction report');
    } finally {
      setLoading(false);
    }
  };

  // ── Export ──────────────────────────────────────────────────────────────────

  const exportAuditTrail = async () => {
    if (!reportingClient || !keypair) return;
    setLoading(true);
    setError(null);
    try {
      const auditEntries = reports.data.flatMap(r =>
        r.sections.flatMap(s =>
          s.fields.map(f => ({
            action: `${r.templateId}:${s.title}`,
            timestamp: r.generatedAt / 1000,
            detail: `${f.name}=${f.value}`,
            ledgerSequence: r.ledgerSequence,
          }))
        )
      );
      const content = await reportingClient.exportAuditTrail(address, auditEntries, exportFormat);
      downloadFile(content, `audit-trail-${address.slice(0, 8)}-${Date.now()}.${exportFormat}`);
    } catch (err: any) {
      setError(err.message || 'Failed to export audit trail');
    } finally {
      setLoading(false);
    }
  };

  const exportReport = async (report: RegulatoryReport) => {
    if (!reportingClient || !keypair) return;
    try {
      const { content } = await reportingClient.exportReport(keypair, address, report, exportFormat);
      downloadFile(content, `report-${report.id.slice(0, 16)}-${Date.now()}.${exportFormat}`);
    } catch (err: any) {
      setError(err.message || 'Failed to export report');
    }
  };

  const downloadFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  // ── Helpers ─────────────────────────────────────────────────────────────────

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'generated': return <Badge className="bg-blue-100 text-blue-800">Generated</Badge>;
      case 'filed': return <Badge className="bg-green-100 text-green-800">Filed</Badge>;
      case 'acknowledged': return <Badge className="bg-purple-100 text-purple-800">Acknowledged</Badge>;
      case 'closed': return <Badge className="bg-gray-100 text-gray-800">Closed</Badge>;
      case 'draft': return <Badge className="bg-yellow-100 text-yellow-800">Draft</Badge>;
      default: return <Badge variant="outline">{status}</Badge>;
    }
  };

  const getRiskBadge = (score: number) => {
    if (score >= 80) return <Badge className="bg-red-100 text-red-800">High Risk ({score})</Badge>;
    if (score >= 50) return <Badge className="bg-yellow-100 text-yellow-800">Medium Risk ({score})</Badge>;
    return <Badge className="bg-green-100 text-green-800">Low Risk ({score})</Badge>;
  };

  const formatDate = (ts: number) => new Date(ts * 1000).toLocaleDateString();

  if (loading && templates.length === 0) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <RefreshCw className="animate-spin h-5 w-5 mr-2" />
            <span>Loading regulatory reporting data...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardContent className="p-4 text-center">
            <FileText className="h-5 w-5 mx-auto mb-1 text-blue-600" />
            <div className="text-2xl font-bold">{stats.totalTemplates}</div>
            <div className="text-xs text-gray-500">Templates</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <ClipboardList className="h-5 w-5 mx-auto mb-1 text-green-600" />
            <div className="text-2xl font-bold">{stats.totalReports}</div>
            <div className="text-xs text-gray-500">Reports</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Flag className="h-5 w-5 mx-auto mb-1 text-red-600" />
            <div className="text-2xl font-bold">{stats.totalSARs}</div>
            <div className="text-xs text-gray-500">SARs</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <AlertTriangle className="h-5 w-5 mx-auto mb-1 text-yellow-600" />
            <div className="text-2xl font-bold">{stats.highRiskReports}</div>
            <div className="text-xs text-gray-500">High Risk</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 text-center">
            <Clock className="h-5 w-5 mx-auto mb-1 text-purple-600" />
            <div className="text-2xl font-bold">{stats.activeSchedules}</div>
            <div className="text-xs text-gray-500">Schedules</div>
          </CardContent>
        </Card>
      </div>

      {/* Main Tabs */}
      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle className="flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              Regulatory Reporting Dashboard
            </CardTitle>
            <div className="flex space-x-2">
              <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
                <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as ReportTab)}>
            <TabsList className="mb-4 flex-wrap">
              <TabsTrigger value="overview">
                <Activity className="h-4 w-4 mr-2" />
                Overview
              </TabsTrigger>
              <TabsTrigger value="templates">
                <FileText className="h-4 w-4 mr-2" />
                Templates
              </TabsTrigger>
              <TabsTrigger value="reports">
                <ClipboardList className="h-4 w-4 mr-2" />
                Reports
              </TabsTrigger>
              <TabsTrigger value="sar">
                <Flag className="h-4 w-4 mr-2" />
                SAR Filing
              </TabsTrigger>
              <TabsTrigger value="schedules">
                <Clock className="h-4 w-4 mr-2" />
                Schedules
              </TabsTrigger>
              <TabsTrigger value="export">
                <Download className="h-4 w-4 mr-2" />
                Export
              </TabsTrigger>
            </TabsList>

            {/* Overview Tab */}
            <TabsContent value="overview">
              <div className="space-y-4">
                <h3 className="font-medium text-lg">Regulatory Coverage</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {templates.slice(0, 6).map(tpl => (
                    <Card key={tpl.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-2">
                        <div className="flex justify-between items-start">
                          <div>
                            <CardTitle className="text-base">{tpl.name}</CardTitle>
                            <CardDescription>{tpl.jurisdiction} — v{tpl.version}</CardDescription>
                          </div>
                          <Badge variant={tpl.active ? 'default' : 'outline'}>
                            {tpl.active ? 'Active' : 'Inactive'}
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <div className="text-sm text-gray-600">
                          <div>{tpl.sections.length} sections</div>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {tpl.tags.map((tag, i) => (
                              <Badge key={i} variant="outline" className="text-xs">{tag}</Badge>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>

                {/* Recent Reports */}
                {reports.data.length > 0 && (
                  <div className="mt-6">
                    <h3 className="font-medium text-lg mb-3">Recent Reports</h3>
                    <div className="space-y-2">
                      {reports.data.slice(0, 5).map(report => (
                        <div key={report.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center space-x-3">
                            <ClipboardList className="h-4 w-4 text-blue-500" />
                            <div>
                              <div className="text-sm font-medium">{report.templateId}</div>
                              <div className="text-xs text-gray-500">{formatDate(report.generatedAt)}</div>
                            </div>
                          </div>
                          <div className="flex items-center space-x-3">
                            {getRiskBadge(report.riskScore)}
                            {getStatusBadge(report.status)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recent SARs */}
                {sars.data.length > 0 && (
                  <div className="mt-6">
                    <h3 className="font-medium text-lg mb-3">Recent SAR Filings</h3>
                    <div className="space-y-2">
                      {sars.data.slice(0, 3).map(sar => (
                        <div key={sar.id} className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                          <div className="flex items-center space-x-3">
                            <AlertTriangle className="h-4 w-4 text-red-500" />
                            <div>
                              <div className="text-sm font-medium">{sar.activityType}</div>
                              <div className="text-xs text-gray-500">
                                {sar.estimatedValue} {sar.currency} — {formatDate(sar.filedAt)}
                              </div>
                            </div>
                          </div>
                          {getStatusBadge(sar.status)}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </TabsContent>

            {/* Templates Tab */}
            <TabsContent value="templates">
              <div className="space-y-4">
                <div className="text-sm text-gray-500">
                  Pre-defined regulatory report templates for key jurisdictions. Templates define the structure and required fields for generated reports.
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {templates.map(tpl => (
                    <Card key={tpl.id} className="hover:shadow-md transition-shadow">
                      <CardHeader className="pb-2">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <CardTitle className="text-sm font-mono">{tpl.id}</CardTitle>
                            <CardDescription className="text-base font-semibold">{tpl.name}</CardDescription>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className="text-xs space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-500">Jurisdiction:</span>
                          <Badge variant="outline">{tpl.jurisdiction}</Badge>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Version:</span>
                          <span>{tpl.version}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-500">Sections:</span>
                          <span>{tpl.sections.length}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Sections:</span>
                          <div className="mt-1 space-y-1">
                            {tpl.sections.map((sec, i) => (
                              <div key={i} className="flex items-center text-xs">
                                <span className="w-2 h-2 rounded-full bg-blue-400 mr-1" />
                                {sec.title}
                                <span className="text-gray-400 ml-1">
                                  ({sec.fields.length} fields{sec.required ? ', required' : ''})
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              </div>
            </TabsContent>

            {/* Reports Tab */}
            <TabsContent value="reports">
              <div className="space-y-4">
                {/* Transaction Report Form */}
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <BarChart3 className="h-4 w-4 mr-2" />
                      File Transaction Report
                    </CardTitle>
                    <CardDescription>Generate a transaction activity report for financial regulators.</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div>
                        <Label>Transaction Count</Label>
                        <Input
                          type="number"
                          value={txReportForm.transactionCount}
                          onChange={e => setTxReportForm({ ...txReportForm, transactionCount: Number(e.target.value) })}
                          placeholder="e.g. 150"
                        />
                      </div>
                      <div>
                        <Label>Total Volume (stroops)</Label>
                        <Input
                          type="number"
                          value={txReportForm.totalVolume}
                          onChange={e => setTxReportForm({ ...txReportForm, totalVolume: Number(e.target.value) })}
                          placeholder="e.g. 5000000"
                        />
                      </div>
                      <div>
                        <Label>Asset</Label>
                        <Select value={txReportForm.asset} onValueChange={v => setTxReportForm({ ...txReportForm, asset: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="USDC">USDC</SelectItem>
                            <SelectItem value="XLM">XLM (native)</SelectItem>
                            <SelectItem value="EURMTL">EURMTL</SelectItem>
                            <SelectItem value="BTC">BTC</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div>
                        <Label>Period Start</Label>
                        <Input
                          type="date"
                          value={txReportForm.periodStart}
                          onChange={e => setTxReportForm({ ...txReportForm, periodStart: e.target.value })}
                        />
                      </div>
                      <div>
                        <Label>Period End</Label>
                        <Input
                          type="date"
                          value={txReportForm.periodEnd}
                          onChange={e => setTxReportForm({ ...txReportForm, periodEnd: e.target.value })}
                        />
                      </div>
                      <div>
                        <Label>Suspicious Count</Label>
                        <Input
                          type="number"
                          value={txReportForm.suspiciousCount}
                          onChange={e => setTxReportForm({ ...txReportForm, suspiciousCount: Number(e.target.value) })}
                          placeholder="e.g. 2"
                        />
                      </div>
                    </div>
                    <Button className="mt-4" onClick={fileTransactionReport} disabled={loading}>
                      <Upload className="h-4 w-4 mr-2" />
                      File Transaction Report
                    </Button>
                  </CardContent>
                </Card>

                {/* Existing Reports List */}
                <h3 className="font-medium">Generated Reports ({reports.total})</h3>
                {reports.data.length === 0 ? (
                  <div className="text-center py-8 text-gray-500">
                    <ClipboardList className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                    <p>No reports generated yet.</p>
                    <p className="text-sm">File a transaction report above or generate a templated report.</p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    {reports.data.map(report => (
                      <Card key={report.id}>
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                              <ClipboardList className="h-5 w-5 text-blue-500" />
                              <div>
                                <div className="text-sm font-medium">{report.templateId}</div>
                                <div className="text-xs text-gray-500">
                                  {formatDate(report.generatedAt)} · {report.sections.length} sections
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center space-x-2">
                              {getRiskBadge(report.riskScore)}
                              {getStatusBadge(report.status)}
                              <Button variant="ghost" size="sm" onClick={() => exportReport(report)}>
                                <Download className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                          {report.sections.length > 0 && (
                            <details className="mt-3">
                              <summary className="text-xs text-blue-600 cursor-pointer hover:underline">
                                View sections ({report.sections.length})
                              </summary>
                              <div className="mt-2 space-y-2">
                                {report.sections.map((sec, i) => (
                                  <div key={i} className="bg-gray-50 p-2 rounded text-xs">
                                    <div className="font-medium">{sec.title}</div>
                                    <div className="grid grid-cols-2 gap-1 mt-1">
                                      {sec.fields.map((f, j) => (
                                        <div key={j}>
                                          <span className="text-gray-500">{f.name}:</span>{' '}
                                          <span className="font-mono">{f.value}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </details>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </div>
            </TabsContent>

            {/* SAR Tab */}
            <TabsContent value="sar">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Flag className="h-5 w-5 mr-2 text-red-500" />
                      File Suspicious Activity Report
                    </CardTitle>
                    <CardDescription>
                      Submit a SAR to be filed with the relevant financial intelligence unit (FIU).
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <Label>Subject Address</Label>
                      <Input
                        value={sarForm.subject}
                        onChange={e => setSarForm({ ...sarForm, subject: e.target.value })}
                        placeholder={address}
                      />
                    </div>
                    <div>
                      <Label>Activity Type</Label>
                      <Select value={sarForm.activityType} onValueChange={v => setSarForm({ ...sarForm, activityType: v })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="structuring">Structuring / Smurfing</SelectItem>
                          <SelectItem value="money_laundering">Money Laundering</SelectItem>
                          <SelectItem value="fraud">Fraud</SelectItem>
                          <SelectItem value="terrorist_financing">Terrorist Financing</SelectItem>
                          <SelectItem value="sanctions_evasion">Sanctions Evasion</SelectItem>
                          <SelectItem value="cybercrime">Cybercrime / Ransomware</SelectItem>
                          <SelectItem value="insider_trading">Insider Trading</SelectItem>
                          <SelectItem value="market_manipulation">Market Manipulation</SelectItem>
                          <SelectItem value="other">Other</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Description</Label>
                      <textarea
                        className="w-full min-h-[100px] px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                        value={sarForm.description}
                        onChange={e => setSarForm({ ...sarForm, description: e.target.value })}
                        placeholder="Describe the suspicious activity in detail..."
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label>Estimated Value</Label>
                        <Input
                          value={sarForm.estimatedValue}
                          onChange={e => setSarForm({ ...sarForm, estimatedValue: e.target.value })}
                          placeholder="e.g. 50000"
                        />
                      </div>
                      <div>
                        <Label>Currency</Label>
                        <Select value={sarForm.currency} onValueChange={v => setSarForm({ ...sarForm, currency: v })}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="USD">USD</SelectItem>
                            <SelectItem value="EUR">EUR</SelectItem>
                            <SelectItem value="GBP">GBP</SelectItem>
                            <SelectItem value="XLM">XLM</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <div>
                      <Label>Notify Regulators</Label>
                      <Input
                        value={sarForm.notifyRegulators}
                        onChange={e => setSarForm({ ...sarForm, notifyRegulators: e.target.value })}
                        placeholder="FINCEN, OFAC (comma-separated)"
                      />
                    </div>
                    <Button
                      className="w-full"
                      onClick={fileSAR}
                      disabled={loading || !sarForm.description}
                    >
                      <AlertTriangle className="h-4 w-4 mr-2" />
                      File SAR
                    </Button>
                  </CardContent>
                </Card>

                {/* Filed SARs */}
                <div>
                  <h3 className="font-medium mb-3">Filed SARs ({sars.total})</h3>
                  {sars.data.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      <AlertTriangle className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                      <p>No SARs filed yet.</p>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-[600px] overflow-y-auto">
                      {sars.data.map(sar => (
                        <Card key={sar.id} className="border-l-4 border-l-red-500">
                          <CardContent className="p-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center space-x-2">
                                  <Badge className="bg-red-100 text-red-800 text-xs">
                                    {sar.activityType}
                                  </Badge>
                                  {getStatusBadge(sar.status)}
                                </div>
                                <p className="text-sm mt-2">{sar.description}</p>
                                <div className="text-xs text-gray-500 mt-2 flex space-x-4">
                                  <span>{sar.estimatedValue} {sar.currency}</span>
                                  <span>Filed: {formatDate(sar.filedAt)}</span>
                                </div>
                                {sar.notifyRegulators.length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-2">
                                    {sar.notifyRegulators.map((reg, i) => (
                                      <Badge key={i} variant="outline" className="text-xs">{reg}</Badge>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* Schedules Tab */}
            <TabsContent value="schedules">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Clock className="h-5 w-5 mr-2" />
                      Create Report Schedule
                    </CardTitle>
                    <CardDescription>
                      Automate report generation on a recurring schedule.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <Label>Schedule ID</Label>
                      <Input
                        value={scheduleForm.scheduleId}
                        onChange={e => setScheduleForm({ ...scheduleForm, scheduleId: e.target.value })}
                        placeholder="e.g. DAILY_FATF"
                      />
                    </div>
                    <div>
                      <Label>Template</Label>
                      <Select value={scheduleForm.templateId} onValueChange={v => setScheduleForm({ ...scheduleForm, templateId: v })}>
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          {templates.map(tpl => (
                            <SelectItem key={tpl.id} value={tpl.id}>{tpl.name} ({tpl.jurisdiction})</SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Interval (hours)</Label>
                      <Select
                        value={String(scheduleForm.intervalHours)}
                        onValueChange={v => setScheduleForm({ ...scheduleForm, intervalHours: Number(v) })}
                      >
                        <SelectTrigger><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="1">Every hour</SelectItem>
                          <SelectItem value="6">Every 6 hours</SelectItem>
                          <SelectItem value="12">Every 12 hours</SelectItem>
                          <SelectItem value="24">Daily</SelectItem>
                          <SelectItem value="168">Weekly</SelectItem>
                          <SelectItem value="720">Monthly (30 days)</SelectItem>
                          <SelectItem value="2160">Quarterly (90 days)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label>Export Formats</Label>
                      <div className="flex space-x-2 mt-2">
                        {(['json', 'csv'] as ExportFormat[]).map(fmt => (
                          <label key={fmt} className="flex items-center space-x-1 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={scheduleForm.exportFormats.includes(fmt)}
                              onChange={e => {
                                if (e.target.checked) {
                                  setScheduleForm({ ...scheduleForm, exportFormats: [...scheduleForm.exportFormats, fmt] });
                                } else {
                                  setScheduleForm({ ...scheduleForm, exportFormats: scheduleForm.exportFormats.filter(f => f !== fmt) });
                                }
                              }}
                              className="rounded"
                            />
                            <span className="text-sm uppercase">{fmt}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                    <Button className="w-full" onClick={createSchedule} disabled={loading}>
                      <Calendar className="h-4 w-4 mr-2" />
                      Create Schedule
                    </Button>
                  </CardContent>
                </Card>

                {/* Schedule List */}
                <div>
                  <h3 className="font-medium mb-3">Active Schedules</h3>
                  {schedules.length === 0 ? (
                    <div className="text-center py-8 text-gray-500">
                      <Clock className="h-12 w-12 mx-auto mb-3 text-gray-300" />
                      <p>No schedules configured yet.</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {schedules.map(schedId => (
                        <Card key={schedId}>
                          <CardContent className="p-4">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-3">
                                <Clock className="h-5 w-5 text-purple-500" />
                                <div>
                                  <div className="text-sm font-medium font-mono">{schedId}</div>
                                  <div className="text-xs text-gray-500">Active</div>
                                </div>
                              </div>
                              <Badge className="bg-green-100 text-green-800">Active</Badge>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>

            {/* Export Tab */}
            <TabsContent value="export">
              <div className="space-y-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center">
                      <Download className="h-5 w-5 mr-2" />
                      Export Audit Trail
                    </CardTitle>
                    <CardDescription>
                      Export the complete audit trail for this address in the selected format.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="flex items-center space-x-4">
                      <div className="flex-1">
                        <Label>Export Format</Label>
                        <Select value={exportFormat} onValueChange={v => setExportFormat(v as ExportFormat)}>
                          <SelectTrigger><SelectValue /></SelectTrigger>
                          <SelectContent>
                            <SelectItem value="json">
                              <div className="flex items-center">
                                <FileJson className="h-4 w-4 mr-2" /> JSON
                              </div>
                            </SelectItem>
                            <SelectItem value="csv">
                              <div className="flex items-center">
                                <FileSpreadsheet className="h-4 w-4 mr-2" /> CSV
                              </div>
                            </SelectItem>
                            <SelectItem value="pdf">
                              <div className="flex items-center">
                                <FileType className="h-4 w-4 mr-2" /> PDF (JSON wrapper)
                              </div>
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <Button onClick={exportAuditTrail} disabled={loading} className="mt-6">
                        <Download className="h-4 w-4 mr-2" />
                        Export Audit Trail
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Export Settings</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                      <div className="p-3 bg-blue-50 rounded-lg">
                        <div className="flex items-center space-x-2 mb-1">
                          <FileJson className="h-4 w-4 text-blue-600" />
                          <span className="font-medium">JSON Export</span>
                        </div>
                        <p className="text-gray-600">Machine-readable format suitable for API integration and automated processing.</p>
                      </div>
                      <div className="p-3 bg-green-50 rounded-lg">
                        <div className="flex items-center space-x-2 mb-1">
                          <FileSpreadsheet className="h-4 w-4 text-green-600" />
                          <span className="font-medium">CSV Export</span>
                        </div>
                        <p className="text-gray-600">Spreadsheet-compatible format for manual review and analysis.</p>
                      </div>
                      <div className="p-3 bg-purple-50 rounded-lg">
                        <div className="flex items-center space-x-2 mb-1">
                          <Database className="h-4 w-4 text-purple-600" />
                          <span className="font-medium">Integrity Verification</span>
                        </div>
                        <p className="text-gray-600">All exports are SHA-256 hashed and recorded on-chain for integrity verification.</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default RegulatoryDashboard;
