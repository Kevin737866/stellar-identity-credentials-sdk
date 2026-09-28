import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CredentialOfferModal, CredentialOffer } from '../CredentialOfferModal';

const mockOffer: CredentialOffer = {
  id: 'cred-offer-123',
  type: ['VerifiableCredential', 'KYCCredential'],
  issuer: {
    id: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
    name: 'Test Issuer',
    did: 'did:stellar:GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
  },
  offeredAttributes: {
    name: 'John Doe',
    nationality: 'US',
    dateOfBirth: '1990-01-15',
    documentType: 'Passport',
  },
  issuanceDate: Date.now() - 86400000,
  expirationDate: Date.now() + 86400000 * 30,
};

const expiredOffer: CredentialOffer = {
  ...mockOffer,
  id: 'cred-offer-expired',
  expirationDate: Date.now() - 86400000,
};

describe('CredentialOfferModal', () => {
  const mockOnAccept = jest.fn();
  const mockOnReject = jest.fn();
  const mockOnOpenChange = jest.fn();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  test('should not render when open is false', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={false}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  test('should not render when offer is null', () => {
    render(
      <CredentialOfferModal
        offer={null}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  test('should render credential offer details', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('Credential Offer')).toBeInTheDocument();
    expect(screen.getByText('KYCCredential')).toBeInTheDocument();
    expect(screen.getByText(/Test Issuer/)).toBeInTheDocument();
    expect(screen.getByText('name')).toBeInTheDocument();
    expect(screen.getByText('John Doe')).toBeInTheDocument();
    expect(screen.getByText('nationality')).toBeInTheDocument();
    expect(screen.getByText('US')).toBeInTheDocument();
  });

  test('should call onAccept when Accept button is clicked', async () => {
    mockOnAccept.mockResolvedValue(undefined);
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    fireEvent.click(screen.getByText('Accept'));
    await waitFor(() => {
      expect(mockOnAccept).toHaveBeenCalledWith(mockOffer);
    });
  });

  test('should call onReject when Reject button is clicked', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    fireEvent.click(screen.getByText('Reject'));
    expect(mockOnReject).toHaveBeenCalledWith(mockOffer);
    expect(mockOnOpenChange).toHaveBeenCalledWith(false);
  });

  test('should show error state when accept fails', async () => {
    mockOnAccept.mockRejectedValue(new Error('Transaction failed'));
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    fireEvent.click(screen.getByText('Accept'));
    await waitFor(() => {
      expect(screen.getByText('Transaction failed')).toBeInTheDocument();
    });
  });

  test('should show loading state during accept', () => {
    mockOnAccept.mockImplementation(() => new Promise(() => {}));
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        loading={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('Processing...')).toBeInTheDocument();
  });

  test('should show expired badge and disable Accept for expired offers', () => {
    render(
      <CredentialOfferModal
        offer={expiredOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('Expired')).toBeInTheDocument();
    expect(screen.getByText('Accept')).toBeDisabled();
  });

  test('should display loading from external prop', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        loading={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('Processing...')).toBeInTheDocument();
  });

  test('should display error from external prop', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        error="Network error"
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('Network error')).toBeInTheDocument();
  });

  test('should show credential type badges', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('VerifiableCredential')).toBeInTheDocument();
    expect(screen.getByText('KYCCredential')).toBeInTheDocument();
  });

  test('should close on Escape key', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(mockOnOpenChange).toHaveBeenCalledWith(false);
  });

  test('should close on overlay click', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    const overlay = screen.getByRole('dialog');
    fireEvent.click(overlay);
    expect(mockOnOpenChange).toHaveBeenCalledWith(false);
  });

  test('should handle empty offered attributes', () => {
    const emptyAttributesOffer = {
      ...mockOffer,
      offeredAttributes: {},
    };
    render(
      <CredentialOfferModal
        offer={emptyAttributesOffer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('No attributes disclosed')).toBeInTheDocument();
  });

  test('should handle missing issuer name', () => {
    const noNameIssuer = {
      ...mockOffer,
      issuer: { id: 'GA1234567890' },
    };
    render(
      <CredentialOfferModal
        offer={noNameIssuer}
        open={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    expect(screen.getByText('GA1234567890')).toBeInTheDocument();
  });

  test('should not close on overlay click while loading', () => {
    render(
      <CredentialOfferModal
        offer={mockOffer}
        open={true}
        loading={true}
        onOpenChange={mockOnOpenChange}
        onAccept={mockOnAccept}
        onReject={mockOnReject}
      />
    );
    const overlay = screen.getByRole('dialog');
    fireEvent.click(overlay);
    expect(mockOnOpenChange).not.toHaveBeenCalled();
  });
});
