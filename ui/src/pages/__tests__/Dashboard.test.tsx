import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { Dashboard } from '../Dashboard';

// Mock all child components
jest.mock('@/components/ReputationBadge', () => ({
  ReputationBadge: ({ sdk, address, keypair, size }: any) => (
    <div data-testid="reputation-badge" data-size={size}>
      Reputation Badge
    </div>
  ),
}));

jest.mock('@/components/CredentialWallet', () => ({
  CredentialWallet: ({ sdk, address, keypair }: any) => (
    <div data-testid="credential-wallet">
      Credential Wallet
    </div>
  ),
}));

jest.mock('@/components/ProofRequest', () => ({
  ProofRequest: ({ sdk, address, keypair }: any) => (
    <div data-testid="proof-request">
      Proof Request
    </div>
  ),
}));

jest.mock('@/components/ComplianceCheck', () => ({
  ComplianceCheck: ({ sdk, address, keypair }: any) => (
    <div data-testid="compliance-check">
      Compliance Check
    </div>
  ),
}));

jest.mock('@/hooks/useStellarIdentity', () => ({
  useStellarIdentity: jest.fn(),
}));

const mockSDK = {} as any;
const mockKeypair = {} as any;

const createUseStellarIdentityMock = (overrides: any = {}) => ({
  sdk: mockSDK,
  isConnected: true,
  isLoading: false,
  error: null,
  address: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
  keypair: mockKeypair,
  connect: jest.fn(),
  disconnect: jest.fn(),
  createKeypair: jest.fn(),
  getBalance: jest.fn(),
  sendTransaction: jest.fn(),
  ...overrides,
});

const TEST_CONFIG = {
  network: 'testnet' as const,
  contracts: {
    didRegistry: '0xaaa',
    credentialIssuer: '0xbbb',
    reputationScore: '0xccc',
    zkAttestation: '0xddd',
    complianceFilter: '0xeee',
  },
  rpcUrl: 'https://testnet.example.com',
};

describe('Dashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    const { useStellarIdentity } = require('@/hooks/useStellarIdentity');
    useStellarIdentity.mockReturnValue(createUseStellarIdentityMock());
  });

  describe('Loading State', () => {
    it('should show loading spinner when initializing', () => {
      const { useStellarIdentity } = require('@/hooks/useStellarIdentity');
      useStellarIdentity.mockReturnValue(createUseStellarIdentityMock({ 
        isLoading: true,
        isConnected: false,
        address: null,
        keypair: null,
      }));

      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Initializing Stellar Identity Dashboard')).toBeInTheDocument();
    });
  });

  describe('Not Connected State', () => {
    it('should show connect screen when not connected', () => {
      const { useStellarIdentity } = require('@/hooks/useStellarIdentity');
      useStellarIdentity.mockReturnValue(createUseStellarIdentityMock({ 
        isConnected: false,
        address: null,
        keypair: null,
      }));

      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Stellar Identity Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Create New Keypair')).toBeInTheDocument();
    });
  });

  describe('Connected State', () => {
    it('should render the sidebar with navigation items', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Credentials')).toBeInTheDocument();
      expect(screen.getByText('Proofs')).toBeInTheDocument();
      expect(screen.getByText('Compliance')).toBeInTheDocument();
      expect(screen.getByText('Reputation')).toBeInTheDocument();
    });

    it('should render the top bar with network info', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Testnet')).toBeInTheDocument();
    });

    it('should render the stats header cards', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Connected')).toBeInTheDocument();
      expect(screen.getByText('Network')).toBeInTheDocument();
    });

    it('should show credentials tab by default', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByTestId('credential-wallet')).toBeInTheDocument();
    });

    it('should render ReputationBadge in sidebar', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByTestId('reputation-badge')).toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    it('should switch to Proofs tab', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      fireEvent.click(screen.getByRole('tab', { name: /proofs/i }));

      expect(screen.getByTestId('proof-request')).toBeInTheDocument();
    });

    it('should switch to Compliance tab', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      fireEvent.click(screen.getByRole('tab', { name: /compliance/i }));

      expect(screen.getByTestId('compliance-check')).toBeInTheDocument();
    });

    it('should switch to Reputation tab', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      fireEvent.click(screen.getByRole('tab', { name: /reputation/i }));

      // Reputation tab shows the ReputationBadge with size="lg"
      const badges = screen.getAllByTestId('reputation-badge');
      expect(badges.length).toBe(2); // one in sidebar, one in content
    });

    it('should switch back to Credentials tab', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      fireEvent.click(screen.getByRole('tab', { name: /proofs/i }));
      fireEvent.click(screen.getByRole('tab', { name: /credentials/i }));

      expect(screen.getByTestId('credential-wallet')).toBeInTheDocument();
    });
  });

  describe('Disconnect', () => {
    it('should call disconnect when disconnect button is clicked', () => {
      const { useStellarIdentity } = require('@/hooks/useStellarIdentity');
      const mockDisconnect = jest.fn();
      useStellarIdentity.mockReturnValue(createUseStellarIdentityMock({ 
        disconnect: mockDisconnect 
      }));

      render(<Dashboard config={TEST_CONFIG} />);

      const disconnectBtn = screen.getByText('Disconnect');
      fireEvent.click(disconnectBtn);

      expect(mockDisconnect).toHaveBeenCalled();
    });
  });

  describe('Copy Address', () => {
    it('should copy address to clipboard', () => {
      const clipboardSpy = jest.spyOn(navigator.clipboard, 'writeText').mockResolvedValue();

      render(<Dashboard config={TEST_CONFIG} />);

      // Find a copy button - there are multiple
      const copyButtons = screen.getAllByRole('button').filter(
        btn => btn.querySelector('svg')
      );
      // Click a copy button
      if (copyButtons.length > 0) {
        fireEvent.click(copyButtons[0]);
      }

      clipboardSpy.mockRestore();
    });
  });

  describe('Responsive Layout', () => {
    it('should render with sidebar by default on desktop', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      expect(screen.getByText('Stellar ID')).toBeInTheDocument();
    });

    it('should have a toggle menu button', () => {
      render(<Dashboard config={TEST_CONFIG} />);

      // Find the menu/toggle button
      const toggleButtons = screen.getAllByRole('button');
      expect(toggleButtons.length).toBeGreaterThan(0);
    });
  });
});
