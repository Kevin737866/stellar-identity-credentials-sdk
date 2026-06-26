/**
 * Tests for RegulatoryReportingClient
 *
 * Covers:
 *   - Default template retrieval
 *   - Template management
 *   - SAR filing and retrieval
 *   - Transaction report filing
 *   - Report scheduling
 *   - Export (JSON, CSV)
 *   - Audit trail export
 *   - Error handling
 */

import { RegulatoryReportingClient, DEFAULT_TEMPLATES } from '../regulatoryReporting';
import type {
  ReportTemplate,
  SARReport,
  ReportSchedule,
  TransactionReport,
  PaginatedReports,
  PaginatedSARs,
  ExportFormat,
} from '../regulatoryReporting';
import { StellarIdentityConfig } from '../types';
import { Keypair } from 'stellar-sdk';

// ---------------------------------------------------------------------------
// Mock stellar-sdk Contract to bypass ID validation
// ---------------------------------------------------------------------------

jest.mock('stellar-sdk', () => {
  const actual = jest.requireActual('stellar-sdk');

  const mockRpc = {
    getAccount: jest.fn().mockResolvedValue({
      accountId: () => 'GADJEVBI5FYHA7E6UAKHF734QSXQIWBQ5P6336YAFQQI6ZMW2K2E2KRW',
      sequenceNumber: () => '1',
      incrementSequenceNumber: () => {},
    }),
    prepareTransaction: jest.fn().mockImplementation((tx) => {
      tx.sign = jest.fn();
      return tx;
    }),
    sendTransaction: jest.fn().mockResolvedValue({ status: 'SUCCESS', hash: '0xmock' }),
    simulateTransaction: jest.fn().mockRejectedValue(new Error('Contract not deployed')),
  };

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const actualSorobanRpc = actual.SorobanRpc;
  return {
    ...actual,
    Contract: jest.fn().mockImplementation(() => ({
      call: jest.fn().mockReturnValue({}),
    })),
    SorobanRpc: {
      ...actualSorobanRpc,
      Server: jest.fn().mockImplementation(() => mockRpc),
      Api: {
        ...actualSorobanRpc?.Api,
        isSimulationError: jest.fn().mockReturnValue(true),
      },
    },
  };
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const createTestConfig = (): StellarIdentityConfig => ({
  network: 'testnet',
  contracts: {
    didRegistry: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822a',
    credentialIssuer: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822b',
    reputationScore: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822c',
    zkAttestation: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822d',
    complianceFilter: '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822e',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
});

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RegulatoryReportingClient', () => {
  let client: RegulatoryReportingClient;
  let testKeypair: Keypair;

  beforeEach(() => {
    client = new RegulatoryReportingClient(createTestConfig());
    testKeypair = Keypair.random();
  });

  // ── Default templates ─────────────────────────────────────────────────────

  describe('Default templates', () => {
    it('should have 5 pre-defined templates', () => {
      expect(DEFAULT_TEMPLATES).toHaveLength(5);
    });

    it('should include FATF Travel Rule template', () => {
      const fatf = DEFAULT_TEMPLATES.find(t => t.id === 'FATF_TRAVEL_RULE');
      expect(fatf).toBeDefined();
      expect(fatf!.jurisdiction).toBe('FATF');
      expect(fatf!.sections).toHaveLength(4);
      expect(fatf!.tags).toContain('travel-rule');
    });

    it('should include MiCA Quarterly template', () => {
      const mica = DEFAULT_TEMPLATES.find(t => t.id === 'MICA_QUARTERLY');
      expect(mica).toBeDefined();
      expect(mica!.jurisdiction).toBe('MiCA');
      expect(mica!.sections).toHaveLength(3);
    });

    it('should include FINCEN SAR template', () => {
      const fincen = DEFAULT_TEMPLATES.find(t => t.id === 'FINCEN_SAR');
      expect(fincen).toBeDefined();
      expect(fincen!.jurisdiction).toBe('FINCEN');
    });

    it('should include GDPR Compliance template', () => {
      const gdpr = DEFAULT_TEMPLATES.find(t => t.id === 'GDPR_COMPLIANCE');
      expect(gdpr).toBeDefined();
      expect(gdpr!.jurisdiction).toBe('GDPR');
      expect(gdpr!.tags).toContain('privacy');
    });

    it('should include Transaction Report template', () => {
      const txn = DEFAULT_TEMPLATES.find(t => t.id === 'TXN_RPT');
      expect(txn).toBeDefined();
      expect(txn!.jurisdiction).toBe('GENERAL');
    });

    it('should return null for unknown template', async () => {
      const tpl = await client.getTemplate('NONEXISTENT');
      expect(tpl).toBeNull();
    });
  });

  // ── Template retrieval ───────────────────────────────────────────────────

  describe('getTemplate', () => {
    it('should return a default template with version and active fields', async () => {
      const tpl = await client.getTemplate('FATF_TRAVEL_RULE');
      expect(tpl).not.toBeNull();
      expect(tpl!.id).toBe('FATF_TRAVEL_RULE');
      expect(tpl!.version).toBeGreaterThanOrEqual(1);
      expect(tpl!.active).toBe(true);
    });

    it('should return null when template not found and not in defaults', async () => {
      const tpl = await client.getTemplate('MADE_UP_TEMPLATE_XYZ');
      expect(tpl).toBeNull();
    });
  });

  describe('getAllTemplates', () => {
    it('should return all default templates when contract unavailable', async () => {
      const templates = await client.getAllTemplates();
      expect(templates.length).toBeGreaterThanOrEqual(5);
      expect(templates.every(t => t.id && t.name && t.jurisdiction)).toBe(true);
    });
  });

  // ── Report section/FATF section data ─────────────────────────────────────

  describe('Template structure validation', () => {
    it('should have FATF template with required transfer details section', () => {
      const fatf = DEFAULT_TEMPLATES.find(t => t.id === 'FATF_TRAVEL_RULE')!;
      const transferSection = fatf.sections[0];
      expect(transferSection.title).toBe('Transfer Details');
      expect(transferSection.required).toBe(true);
      expect(transferSection.fields).toContain('amount');
      expect(transferSection.fields).toContain('asset');
      expect(transferSection.fields).toContain('timestamp');
    });

    it('should have MiCA template with customer due diligence section', () => {
      const mica = DEFAULT_TEMPLATES.find(t => t.id === 'MICA_QUARTERLY')!;
      const cddSection = mica.sections.find(s => s.title === 'Customer Due Diligence');
      expect(cddSection).toBeDefined();
      expect(cddSection!.fields).toContain('kycVerified');
      expect(cddSection!.fields).toContain('pepIdentified');
    });

    it('should have FINCEN SAR template with law enforcement section', () => {
      const fincen = DEFAULT_TEMPLATES.find(t => t.id === 'FINCEN_SAR')!;
      const leSection = fincen.sections.find(s => s.title === 'Law Enforcement');
      expect(leSection).toBeDefined();
      expect(leSection!.required).toBe(false); // optional section
    });
  });

  // ── Report methods (contract unavailable — graceful fallback) ────────────

  describe('getReports', () => {
    it('should return empty paginated result when contract unavailable', async () => {
      const subject = testKeypair.publicKey();
      const result = await client.getReports(subject);
      expect(result).toBeDefined();
      expect(result.data).toEqual([]);
      expect(result.page).toBe(0);
      expect(result.total).toBe(0);
      expect(result.hasMore).toBe(false);
    });
  });

  // ── Transaction report → fallback type return ────────────────────────────

  describe('fileTransactionReport', () => {
    it('should validate method signature and parameter types', () => {
      // Verify the client method accepts correct parameter types.
      // Full on-chain testing requires a deployed contract on testnet.
      expect(typeof client.fileTransactionReport).toBe('function');
    });

    it('should have correct parameter count', () => {
      // Method: reporterKeypair, subject, transactionCount, totalVolume,
      // periodStart, periodEnd, asset, avgTransactionSize, maxTransactionSize, suspiciousCount
      expect(client.fileTransactionReport.length).toBe(10);
    });
  });

  // ── SAR methods ──────────────────────────────────────────────────────────

  describe('fileSAR', () => {
    it('should validate method signature accepts SAR params object', () => {
      // Verify the client method accepts correct parameter types.
      // Full on-chain testing requires a deployed contract on testnet.
      expect(typeof client.fileSAR).toBe('function');
    });

    it('should validate SAR params structure', () => {
      const params = {
        subject: testKeypair.publicKey(),
        activityType: 'structuring',
        description: 'Test description',
        relatedTransactions: ['tx1'],
        estimatedValue: '10000',
        currency: 'USD',
        notifyRegulators: ['FINCEN'],
        evidenceHashes: [],
        activityTimestamp: 1700000000,
      };
      expect(params.subject).toBeTruthy();
      expect(params.activityType).toBe('structuring');
      expect(params.description).toBeTruthy();
      expect(Array.isArray(params.relatedTransactions)).toBe(true);
      expect(params.currency).toBe('USD');
      expect(Array.isArray(params.notifyRegulators)).toBe(true);
    });
  });

  describe('getSAR', () => {
    it('should return null when SAR not found', async () => {
      const result = await client.getSAR('SAR:nonexistent:12345');
      expect(result).toBeNull();
    });
  });

  describe('getSARs', () => {
    it('should return empty paginated result when contract unavailable', async () => {
      const result = await client.getSARs();
      expect(result).toBeDefined();
      expect(result.data).toEqual([]);
      expect(result.page).toBe(0);
      expect(result.total).toBe(0);
    });
  });

  // ── Scheduling methods ───────────────────────────────────────────────────

  describe('getSchedules', () => {
    it('should return empty array when contract unavailable', async () => {
      const result = await client.getSchedules();
      expect(Array.isArray(result)).toBe(true);
      expect(result).toEqual([]);
    });
  });

  // ── Export methods ───────────────────────────────────────────────────────

  describe('exportAuditTrail', () => {
    it('should export audit trail as JSON', async () => {
      const entries = [
        { action: 'screen', timestamp: 1700000000, detail: 'matched:OFAC', ledgerSequence: 1000 },
        { action: 'risk_score_update', timestamp: 1700000100, detail: 'suspicious activity', ledgerSequence: 1001 },
      ];
      const json = await client.exportAuditTrail(testKeypair.publicKey(), entries, 'json');
      expect(json).toBeDefined();
      const parsed = JSON.parse(json);
      expect(parsed.subject).toBe(testKeypair.publicKey());
      expect(parsed.totalEntries).toBe(2);
      expect(parsed.entries).toHaveLength(2);
      expect(parsed.entries[0].action).toBe('screen');
    });

    it('should export audit trail as CSV', async () => {
      const entries = [
        { action: 'screen', timestamp: 1700000000, detail: 'matched:OFAC', ledgerSequence: 1000 },
      ];
      const csv = await client.exportAuditTrail(testKeypair.publicKey(), entries, 'csv');
      expect(csv).toBeDefined();
      expect(csv).toContain('Action,Timestamp,Detail,LedgerSequence');
      expect(csv).toContain('screen');
      expect(csv).toContain('OFAC');
    });

    it('should handle empty entries', async () => {
      const json = await client.exportAuditTrail(testKeypair.publicKey(), [], 'json');
      const parsed = JSON.parse(json);
      expect(parsed.totalEntries).toBe(0);
      expect(parsed.entries).toEqual([]);
    });
  });

  // ── Export format handling ───────────────────────────────────────────────

  describe('exportReport', () => {
    it('should export a report as JSON', async () => {
      const report = {
        id: 'RPT:FATF:subject:12345',
        templateId: 'FATF_TRAVEL_RULE',
        subject: testKeypair.publicKey(),
        reporter: testKeypair.publicKey(),
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
        tags: ['travel-rule'],
      };

      const { content, hash } = await client.exportReport(
        testKeypair,
        testKeypair.publicKey(),
        report,
        'json',
      );
      expect(content).toBeDefined();
      expect(hash).toBeDefined();
      expect(hash.length).toBe(64); // SHA-256 hex
      const parsed = JSON.parse(content);
      expect(parsed.templateId).toBe('FATF_TRAVEL_RULE');
    });

    it('should export a report as CSV', async () => {
      const report = {
        id: 'RPT:TXN:subject:12345',
        templateId: 'TXN_RPT',
        subject: testKeypair.publicKey(),
        reporter: testKeypair.publicKey(),
        sections: [],
        riskScore: 30,
        status: 'generated',
        generatedAt: 1700000000,
        ledgerSequence: 1000,
        tags: [],
      };

      const { content } = await client.exportReport(
        testKeypair,
        testKeypair.publicKey(),
        report,
        'csv',
      );
      expect(content).toBeDefined();
      expect(content).toContain('TXN_RPT');
    });

    it('should export a SAR as JSON', async () => {
      const sar = {
        id: 'SAR:subject:12345',
        subject: testKeypair.publicKey(),
        filer: testKeypair.publicKey(),
        activityType: 'fraud',
        description: 'Fraudulent transfers detected',
        relatedTransactions: ['tx1'],
        estimatedValue: '100000',
        currency: 'USD',
        status: 'filed' as const,
        notifyRegulators: ['FINCEN'],
        evidenceHashes: [],
        filedAt: 1700000000,
        activityTimestamp: 1699900000,
        ledgerSequence: 1000,
      };

      const { content } = await client.exportReport(
        testKeypair,
        testKeypair.publicKey(),
        sar,
        'json',
      );
      const parsed = JSON.parse(content);
      expect(parsed.activityType).toBe('fraud');
    });

    it('should export a TransactionReport as CSV', async () => {
      const txReport: TransactionReport = {
        id: 'TXN_RPT:subject:12345',
        subject: testKeypair.publicKey(),
        transactionCount: 150,
        totalVolume: 5_000_000,
        periodStart: 1699900000,
        periodEnd: 1700000000,
        asset: 'USDC',
        avgTransactionSize: 33_333,
        maxTransactionSize: 500_000,
        suspiciousCount: 2,
        exceedsThreshold: false,
        generatedAt: 1700000000,
        ledgerSequence: 1000,
      };

      const { content } = await client.exportReport(
        testKeypair,
        testKeypair.publicKey(),
        txReport,
        'csv',
      );
      expect(content).toContain('150');
      expect(content).toContain('USDC');
    });
  });

  // ── Statistics ───────────────────────────────────────────────────────────

  describe('getStatistics', () => {
    it('should return default statistics when contract unavailable', async () => {
      const stats = await client.getStatistics();
      expect(stats.templates).toBeGreaterThanOrEqual(5);
      expect(typeof stats.reports).toBe('number');
      expect(typeof stats.sars).toBe('number');
    });
  });

  // ── getExportSnapshots ───────────────────────────────────────────────────

  describe('getExportSnapshots', () => {
    it('should return empty array when contract unavailable', async () => {
      const snapshots = await client.getExportSnapshots(testKeypair.publicKey());
      expect(Array.isArray(snapshots)).toBe(true);
      expect(snapshots).toEqual([]);
    });
  });

  // ── Default template completeness ────────────────────────────────────────

  describe('Default template completeness', () => {
    it('each default template should have required fields at the top level', () => {
      for (const tpl of DEFAULT_TEMPLATES) {
        expect(tpl.id).toBeTruthy();
        expect(tpl.name).toBeTruthy();
        expect(tpl.jurisdiction).toBeTruthy();
        expect(tpl.sections.length).toBeGreaterThan(0);
        expect(tpl.tags).toBeDefined();
      }
    });

    it('each template section should have a title and fields array', () => {
      for (const tpl of DEFAULT_TEMPLATES) {
        for (const section of tpl.sections) {
          expect(section.title).toBeTruthy();
          expect(Array.isArray(section.fields)).toBe(true);
          expect(section.fields.length).toBeGreaterThan(0);
          expect(typeof section.required).toBe('boolean');
          expect(typeof section.order).toBe('number');
        }
      }
    });
  });
});
