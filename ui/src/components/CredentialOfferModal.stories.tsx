import type { Meta, StoryObj } from '@storybook/react';
import { CredentialOfferModal, CredentialOffer } from './CredentialOfferModal';

const mockOffer: CredentialOffer = {
  id: 'cred-offer-123',
  type: ['VerifiableCredential', 'KYCCredential'],
  issuer: {
    id: 'GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
    name: 'Verified Identity Inc.',
    did: 'did:stellar:GD5DJQDKEJXGYQTELBQJXG2QFQHZXJN5T2YGF4Y4A3K5Z2Q2B4F5',
  },
  offeredAttributes: {
    name: 'John Doe',
    nationality: 'US',
    dateOfBirth: '1990-01-15',
    documentType: 'Passport',
    documentNumber: '****1234',
  },
  issuanceDate: Date.now() - 86400000,
  expirationDate: Date.now() + 86400000 * 30,
};

const expiredOffer: CredentialOffer = {
  ...mockOffer,
  id: 'cred-offer-expired',
  expirationDate: Date.now() - 86400000,
};

const meta: Meta<typeof CredentialOfferModal> = {
  title: 'Components/CredentialOfferModal',
  component: CredentialOfferModal,
  tags: ['autodocs'],
  argTypes: {
    open: { control: 'boolean' },
    loading: { control: 'boolean' },
    error: { control: 'text' },
  },
};

export default meta;
type Story = StoryObj<typeof CredentialOfferModal>;

export const Default: Story = {
  args: {
    offer: mockOffer,
    open: true,
    onOpenChange: () => {},
    onAccept: async () => {},
    onReject: () => {},
  },
};

export const Loading: Story = {
  args: {
    offer: mockOffer,
    open: true,
    loading: true,
    onOpenChange: () => {},
    onAccept: async () => {},
    onReject: () => {},
  },
};

export const Error: Story = {
  args: {
    offer: mockOffer,
    open: true,
    error: 'Transaction failed: Insufficient funds',
    onOpenChange: () => {},
    onAccept: async () => {},
    onReject: () => {},
  },
};

export const Expired: Story = {
  args: {
    offer: expiredOffer,
    open: true,
    onOpenChange: () => {},
    onAccept: async () => {},
    onReject: () => {},
  },
};

export const NoAttributes: Story = {
  args: {
    offer: { ...mockOffer, offeredAttributes: {} },
    open: true,
    onOpenChange: () => {},
    onAccept: async () => {},
    onReject: () => {},
  },
};
