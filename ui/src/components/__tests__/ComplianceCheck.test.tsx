import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ComplianceCheck } from '../ComplianceCheck';

const mockSdk = {
  performComplianceCheck: jest.fn(),
  did: {
    validateDIDFormat: jest.fn(),
  },
};

const mockKeypair = {
  publicKey: () => 'GA1234567890ABCDEF',
};

const mockComplianceResult = {
  status: 'cleared',
  riskScore: 25,
  complianceScore: 90,
  totalCredentials: 5,
  validCredentials: 5,
  sanctionsLists: [],
  lastChecked: Date.now(),
  recommendations: ['Maintain current compliance status'],
};

describe('ComplianceCheck', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSdk.did.validateDIDFormat.mockReturnValue(true);
  });

  test('renders address input field', () => {
    render(
      <ComplianceCheck sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(screen.getByPlaceholderText('Enter Stellar address (G...)')).toBeInTheDocument();
  });

  test('performs compliance check on button click', async () => {
    mockSdk.performComplianceCheck.mockResolvedValue(mockComplianceResult);
    render(
      <ComplianceCheck sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    const input = screen.getByPlaceholderText('Enter Stellar address (G...)');
    const checkButton = screen.getByRole('button', { name: /check/i });
    fireEvent.change(input, { target: { value: 'GBBB' } });
    fireEvent.click(checkButton);
    await waitFor(() => {
      expect(mockSdk.performComplianceCheck).toHaveBeenCalledWith('GBBB');
    });
  });

  test('displays screening results', async () => {
    mockSdk.performComplianceCheck.mockResolvedValue(mockComplianceResult);
    render(
      <ComplianceCheck sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    await waitFor(() => {
      expect(screen.getByText('Compliance Status')).toBeInTheDocument();
    });
  });

  test('handles error states', async () => {
    mockSdk.performComplianceCheck.mockRejectedValue(new Error('Network error'));
    render(
      <ComplianceCheck sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    await waitFor(() => {
      expect(screen.getByText('Network error')).toBeInTheDocument();
    });
  });

  test('shows loading state', async () => {
    mockSdk.performComplianceCheck.mockImplementation(
      () => new Promise(() => {})
    );
    render(
      <ComplianceCheck sdk={mockSdk} address="GA123" keypair={mockKeypair as any} />
    );
    expect(screen.getByText('Performing compliance check...')).toBeInTheDocument();
  });
});
