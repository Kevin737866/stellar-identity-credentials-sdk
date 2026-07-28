/**
 * Tests for RegulatoryDashboard component
 *
 * Covers:
 *   - Rendering of all tabs
 *   - Template display
 *   - SAR filing form
 *   - Schedule form
 *   - Export controls
 *   - Empty states
 *   - Error display
 */

import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { RegulatoryDashboard } from '../RegulatoryDashboard';
import { Keypair } from 'stellar-sdk';

// Mock lucide-react icons
jest.mock('lucide-react', () => ({
  FileText: () => React.createElement('span', { 'data-testid': 'icon-file-text' }),
  AlertTriangle: () => React.createElement('span', { 'data-testid': 'icon-alert-triangle' }),
  Calendar: () => React.createElement('span', { 'data-testid': 'icon-calendar' }),
  Download: () => React.createElement('span', { 'data-testid': 'icon-download' }),
  Clock: () => React.createElement('span', { 'data-testid': 'icon-clock' }),
  Activity: () => React.createElement('span', { 'data-testid': 'icon-activity' }),
  Shield: () => React.createElement('span', { 'data-testid': 'icon-shield' }),
  FileSpreadsheet: () => React.createElement('span', { 'data-testid': 'icon-file-spreadsheet' }),
  FileJson: () => React.createElement('span', { 'data-testid': 'icon-file-json' }),
  FileType: () => React.createElement('span', { 'data-testid': 'icon-file-type' }),
  Plus: () => React.createElement('span', { 'data-testid': 'icon-plus' }),
  RefreshCw: () => React.createElement('span', { 'data-testid': 'icon-refresh-cw' }),
  Search: () => React.createElement('span', { 'data-testid': 'icon-search' }),
  CheckCircle: () => React.createElement('span', { 'data-testid': 'icon-check-circle' }),
  XCircle: () => React.createElement('span', { 'data-testid': 'icon-x-circle' }),
  AlertCircle: () => React.createElement('span', { 'data-testid': 'icon-alert-circle' }),
  BarChart3: () => React.createElement('span', { 'data-testid': 'icon-bar-chart' }),
  TrendingUp: () => React.createElement('span', { 'data-testid': 'icon-trending-up' }),
  Settings: () => React.createElement('span', { 'data-testid': 'icon-settings' }),
  Trash2: () => React.createElement('span', { 'data-testid': 'icon-trash' }),
  Eye: () => React.createElement('span', { 'data-testid': 'icon-eye' }),
  ChevronDown: () => React.createElement('span', { 'data-testid': 'icon-chevron-down' }),
  Upload: () => React.createElement('span', { 'data-testid': 'icon-upload' }),
  ClipboardList: () => React.createElement('span', { 'data-testid': 'icon-clipboard-list' }),
  Flag: () => React.createElement('span', { 'data-testid': 'icon-flag' }),
  Database: () => React.createElement('span', { 'data-testid': 'icon-database' }),
}));

// Mock RegulatoryReportingClient
const mockGetAllTemplates = jest.fn();
const mockGetReports = jest.fn();
const mockGetSARs = jest.fn();
const mockGetSchedules = jest.fn();
const mockFileSAR = jest.fn();
const mockFileTransactionReport = jest.fn();
const mockScheduleReport = jest.fn();
const mockExportAuditTrail = jest.fn();
const mockExportReport = jest.fn();
const mockGetStatistics = jest.fn();

jest.mock('@stellar-identity/sdk', () => ({
  RegulatoryReportingClient: jest.fn().mockImplementation(() => ({
    getAllTemplates: mockGetAllTemplates,
    getReports: mockGetReports,
    getSARs: mockGetSARs,
    getSchedules: mockGetSchedules,
    fileSAR: mockFileSAR,
    fileTransactionReport: mockFileTransactionReport,
    scheduleReport: mockScheduleReport,
    exportAuditTrail: mockExportAuditTrail,
    exportReport: mockExportReport,
    getStatistics: mockGetStatistics,
  })),
  DEFAULT_TEMPLATES: [
    {
      id: 'FATF_TRAVEL_RULE',
      name: 'FATF Travel Rule Report',
      jurisdiction: 'FATF',
      version: 1,
      sections: [
        { title: 'Transfer Details', description: 'Transfer info', fields: ['amount', 'asset'], required: true, order: 0 },
        { title: 'Originator Information', description: 'Originator info', fields: ['originatorName'], required: true, order: 1 },
      ],
      tags: ['travel-rule'],
      active: true,
      created: 1700000000,
      updated: 1700000000,
    },
    {
      id: 'FINCEN_SAR',
      name: 'FINCEN SAR',
      jurisdiction: 'FINCEN',
      version: 1,
      sections: [
        { title: 'Subject Information', description: 'Subject', fields: ['subjectName'], required: true, order: 0 },
      ],
      tags: ['suspicious-activity'],
      active: true,
      created: 1700000000,
      updated: 1700000000,
    },
  ],
}));

const createMockSDK = () => ({
  config: {
    network: 'testnet' as const,
    contracts: {
      complianceFilter: '0xmock',
      didRegistry: '0xmock',
      credentialIssuer: '0xmock',
      reputationScore: '0xmock',
      zkAttestation: '0xmock',
    },
    rpcUrl: 'https://soroban-testnet.stellar.org',
  },
});

describe('RegulatoryDashboard', () => {
  let mockKeypair: Keypair;
  const testAddress = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ12345678901234';

  beforeEach(() => {
    jest.clearAllMocks();
    mockKeypair = Keypair.random();

    // Default successful responses
    mockGetAllTemplates.mockResolvedValue([
      {
        id: 'FATF_TRAVEL_RULE',
        name: 'FATF Travel Rule Report',
        jurisdiction: 'FATF',
        version: 1,
        sections: [],
        tags: ['travel-rule'],
        active: true,
        created: 1700000000,
        updated: 1700000000,
      },
    ]);
    mockGetReports.mockResolvedValue({ data: [], page: 0, total: 0, hasMore: false });
    mockGetSARs.mockResolvedValue({ data: [], page: 0, total: 0, hasMore: false });
    mockGetSchedules.mockResolvedValue([]);
    mockGetStatistics.mockResolvedValue({ templates: 5, reports: 0, sars: 0 });
  });

  const renderComponent = () =>
    render(
      <RegulatoryDashboard
        sdk={createMockSDK() as any}
        address={testAddress}
        keypair={mockKeypair}
      />
    );

  // ── Initial rendering ────────────────────────────────────────────────────

  it('should render without crashing', () => {
    renderComponent();
    expect(screen.getByText('Regulatory Reporting Dashboard')).toBeInTheDocument();
  });

  it('should display all tab triggers', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Overview')).toBeInTheDocument();
      expect(screen.getByText('Templates')).toBeInTheDocument();
      expect(screen.getByText('Reports')).toBeInTheDocument();
      expect(screen.getByText('SAR Filing')).toBeInTheDocument();
      expect(screen.getByText('Schedules')).toBeInTheDocument();
      expect(screen.getByText('Export')).toBeInTheDocument();
    });
  });

  it('should display stat cards', async () => {
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Templates')).toBeInTheDocument();
      expect(screen.getByText('Reports')).toBeInTheDocument();
      expect(screen.getByText('SARs')).toBeInTheDocument();
      expect(screen.getByText('High Risk')).toBeInTheDocument();
      expect(screen.getByText('Schedules')).toBeInTheDocument();
    });
  });

  // ── Template display ─────────────────────────────────────────────────────

  it('should show template info in Overview tab', async () => {
    mockGetAllTemplates.mockResolvedValue([
      {
        id: 'FATF_TRAVEL_RULE',
        name: 'FATF Travel Rule Report',
        jurisdiction: 'FATF',
        version: 1,
        sections: [],
        tags: ['travel-rule'],
        active: true,
        created: 1700000000,
        updated: 1700000000,
      },
    ]);
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('FATF Travel Rule Report')).toBeInTheDocument();
    });
  });

  it('should show template details in Templates tab', async () => {
    renderComponent();
    // Switch to templates tab
    fireEvent.click(screen.getByText('Templates'));
    await waitFor(() => {
      expect(screen.getByText('FATF Travel Rule Report')).toBeInTheDocument();
    });
  });

  // ── SAR Filing form ──────────────────────────────────────────────────────

  it('should render SAR filing form', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('SAR Filing'));
    await waitFor(() => {
      expect(screen.getByText('File Suspicious Activity Report')).toBeInTheDocument();
      expect(screen.getByText('File SAR')).toBeInTheDocument();
    });
  });

  it('should have activity type selector', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('SAR Filing'));
    await waitFor(() => {
      expect(screen.getByText('Activity Type')).toBeInTheDocument();
    });
  });

  it('should have description textarea', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('SAR Filing'));
    await waitFor(() => {
      expect(screen.getByPlaceholderText('Describe the suspicious activity in detail...')).toBeInTheDocument();
    });
  });

  // ── Reports tab ──────────────────────────────────────────────────────────

  it('should render transaction report form in Reports tab', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Reports'));
    await waitFor(() => {
      expect(screen.getByText('File Transaction Report')).toBeInTheDocument();
      expect(screen.getByText('File Transaction Report')).toBeInTheDocument();
    });
  });

  it('should show empty state for reports', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Reports'));
    await waitFor(() => {
      expect(screen.getByText('No reports generated yet.')).toBeInTheDocument();
    });
  });

  // ── Schedules tab ────────────────────────────────────────────────────────

  it('should render schedule creation form', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Schedules'));
    await waitFor(() => {
      expect(screen.getByText('Create Report Schedule')).toBeInTheDocument();
      expect(screen.getByText('Create Schedule')).toBeInTheDocument();
    });
  });

  it('should show empty state for schedules', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Schedules'));
    await waitFor(() => {
      expect(screen.getByText('No schedules configured yet.')).toBeInTheDocument();
    });
  });

  // ── Export tab ───────────────────────────────────────────────────────────

  it('should render export controls', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Export'));
    await waitFor(() => {
      expect(screen.getByText('Export Audit Trail')).toBeInTheDocument();
      expect(screen.getByText('Export Settings')).toBeInTheDocument();
    });
  });

  it('should show export format descriptions', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('Export'));
    await waitFor(() => {
      expect(screen.getByText('JSON Export')).toBeInTheDocument();
      expect(screen.getByText('CSV Export')).toBeInTheDocument();
      expect(screen.getByText('Integrity Verification')).toBeInTheDocument();
    });
  });

  // ── Empty SAR state ─────────────────────────────────────────────────────

  it('should show empty state for SARs', async () => {
    renderComponent();
    fireEvent.click(screen.getByText('SAR Filing'));
    await waitFor(() => {
      expect(screen.getByText('No SARs filed yet.')).toBeInTheDocument();
    });
  });

  // ── Reports with data ────────────────────────────────────────────────────

  it('should display report data when available', async () => {
    mockGetReports.mockResolvedValue({
      data: [
        {
          id: 'RPT:FATF:subject:12345',
          templateId: 'FATF_TRAVEL_RULE',
          subject: testAddress,
          reporter: testAddress,
          sections: [
            {
              title: 'Transfer Details',
              fields: [
                { name: 'amount', value: '5000' },
                { name: 'asset', value: 'USDC' },
              ],
            },
          ],
          riskScore: 30,
          status: 'generated',
          generatedAt: 1700000000,
          ledgerSequence: 1000,
          tags: [],
        },
      ],
      page: 0,
      total: 1,
      hasMore: false,
    });
    renderComponent();
    fireEvent.click(screen.getByText('Reports'));
    await waitFor(() => {
      expect(screen.getByText('FATF_TRAVEL_RULE')).toBeInTheDocument();
      expect(screen.getByText('Low Risk (30)')).toBeInTheDocument();
    });
  });

  // ── High risk display ────────────────────────────────────────────────────

  it('should display High Risk badge for high risk reports', async () => {
    mockGetReports.mockResolvedValue({
      data: [
        {
          id: 'RPT:HIGH:subject:12345',
          templateId: 'FINCEN_SAR',
          subject: testAddress,
          reporter: testAddress,
          sections: [],
          riskScore: 85,
          status: 'generated',
          generatedAt: 1700000000,
          ledgerSequence: 1000,
          tags: [],
        },
      ],
      page: 0,
      total: 1,
      hasMore: false,
    });
    renderComponent();
    fireEvent.click(screen.getByText('Reports'));
    await waitFor(() => {
      expect(screen.getByText('High Risk (85)')).toBeInTheDocument();
    });
  });

  // ── Error display ────────────────────────────────────────────────────────

  it('should display error alert when data loading fails', async () => {
    mockGetAllTemplates.mockRejectedValue(new Error('Network error'));
    renderComponent();
    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  // ── Refresh button ───────────────────────────────────────────────────────

  it('should have a refresh button', () => {
    renderComponent();
    expect(screen.getByText('Refresh')).toBeInTheDocument();
  });
});
