import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardContent 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import {
  Skeleton,
  SkeletonCard,
  SkeletonDetail,
  SkeletonList,
  SkeletonTable,
} from '@/components/ui/skeleton';
import { LiveAnnouncer } from '@/components/ui/live-region';
import { CredentialDetail } from '@/components/CredentialDetail';
import { 
  CredentialClient, 
  VerifiableCredential, 
  CredentialVerificationResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { useTranslation } from '@/i18n';
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Eye, 
  Download, 
  Share,
  Plus,
  AlertCircle,
  FileText
} from 'lucide-react';

interface CredentialWalletProps {
  sdk: any; // StellarIdentitySDK instance
  address: string;
  keypair: Keypair;
}

/**
 * Human-readable name for a credential, used in button labels and headings.
 * Falls back to the id so a credential with no recognisable type is still
 * nameable.
 */
function credentialLabel(credential: VerifiableCredential): string {
  const named = credential.type?.find(type => type !== 'VerifiableCredential');
  return named ?? credential.id;
}

export const CredentialWallet: React.FC<CredentialWalletProps> = ({ sdk, address, keypair }) => {
  const [credentials, setCredentials] = useState<VerifiableCredential[]>([]);
  const [selectedCredential, setSelectedCredential] = useState<VerifiableCredential | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showIssueDialog, setShowIssueDialog] = useState(false);
  const [verificationResults, setVerificationResults] = useState<Record<string, CredentialVerificationResult>>({});

  // Form states
  const [newCredential, setNewCredential] = useState({
    subject: '',
    credentialType: [] as string[],
    credentialData: '',
    expirationDate: ''
  });

  const { t, format } = useTranslation();

  useEffect(() => {
    loadCredentials();
  }, [address]);

  const loadCredentials = async () => {
    try {
      setLoading(true);
      const credentialIds = await sdk.credentials.getSubjectCredentials(address);
      const credentialPromises = credentialIds.map(id => sdk.credentials.getCredential(id));
      const loadedCredentials = await Promise.all(credentialPromises);
      setCredentials(loadedCredentials);
      
      // Verify all credentials
      const verificationPromises = credentialIds.map(id => 
        sdk.credentials.verifyCredential(id)
      );
      const results = await Promise.all(verificationPromises);
      const verificationMap: Record<string, CredentialVerificationResult> = {};
      credentialIds.forEach((id, index) => {
        verificationMap[id] = results[index];
      });
      setVerificationResults(verificationMap);
    } catch (error: any) {
      setError(error.message || t('credential.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const issueCredential = async () => {
    try {
      setLoading(true);
      setError(null);
      
      if (!newCredential.subject || newCredential.credentialType.length === 0 || !newCredential.credentialData) {
        setError(t('credential.requiredFields'));
        return;
      }

      const credentialData = JSON.parse(newCredential.credentialData);
      const expirationDate = newCredential.expirationDate ? 
        new Date(newCredential.expirationDate).getTime() : undefined;

      const credentialId = await sdk.credentials.issueCredential(keypair, {
        subject: newCredential.subject,
        credentialType: newCredential.credentialType,
        credentialData,
        expirationDate,
        proof: await generateProof(credentialData)
      });

      setSuccess(t('credential.issueSucceeded', { id: credentialId }));
      setShowIssueDialog(false);
      setNewCredential({
        subject: '',
        credentialType: [],
        credentialData: '',
        expirationDate: ''
      });
      await loadCredentials();
    } catch (error: any) {
      setError(error.message || t('credential.issueFailed'));
    } finally {
      setLoading(false);
    }
  };

  const revokeCredential = async (credentialId: string) => {
    if (!confirm(t('credential.revokeConfirm'))) {
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      // The reason is persisted on chain and shown to third-party verifiers,
      // so it stays a stable English identifier rather than being localised.
      // Translating it would make the recorded reason depend on the issuer's
      // UI language, which is not what the field means.
      await sdk.credentials.revokeCredential(keypair, credentialId, 'User requested revocation');
      setSuccess(t('credential.revokeSucceeded'));
      await loadCredentials();
    } catch (error: any) {
      setError(error.message || t('credential.revokeFailed'));
    } finally {
      setLoading(false);
    }
  };

  const generateProof = async (credentialData: any): Promise<string> => {
    // Simplified proof generation - in practice, this would use proper cryptographic signing
    const message = JSON.stringify(credentialData);
    return keypair.sign(Buffer.from(message)).toString('hex');
  };

  const downloadCredential = (credential: VerifiableCredential) => {
    const dataStr = JSON.stringify(credential, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
    
    const exportFileDefaultName = `credential-${credential.id}.json`;
    
    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  const shareCredential = async (credential: VerifiableCredential) => {
    try {
      const presentation = await sdk.credentials.createPresentation([credential], keypair);
      const shareUrl = `${window.location.origin}/share/${btoa(JSON.stringify(presentation))}`;
      
      if (navigator.share) {
        await navigator.share({
          title: t('credential.shareSheetTitle'),
          text: t('credential.shareSheetText'),
          url: shareUrl
        });
      } else {
        await navigator.clipboard.writeText(shareUrl);
        setSuccess(t('credential.shareSucceeded'));
      }
    } catch (error: any) {
      setError(error.message || t('credential.shareFailed'));
    }
  };

  const getStatusIcon = (verification: CredentialVerificationResult) => {
    // The badge beside it already names the state, so the icon is decorative
    // and must be hidden from assistive tech to avoid a duplicate reading.
    if (verification.revoked) {
      return <XCircle className="h-4 w-4 text-red-500" aria-hidden="true" />;
    }
    if (verification.expired) {
      return <Clock className="h-4 w-4 text-yellow-500" aria-hidden="true" />;
    }
    if (verification.valid) {
      return <CheckCircle className="h-4 w-4 text-green-500" aria-hidden="true" />;
    }
    return <AlertCircle className="h-4 w-4 text-gray-500" aria-hidden="true" />;
  };

  const getStatusBadge = (verification: CredentialVerificationResult) => {
    if (verification.revoked) {
      return <Badge variant="destructive">{t('credential.status.revoked')}</Badge>;
    }
    if (verification.expired) {
      return <Badge variant="secondary">{t('credential.status.expired')}</Badge>;
    }
    if (verification.valid) {
      return <Badge variant="default">{t('credential.status.valid')}</Badge>;
    }
    return <Badge variant="outline">{t('credential.status.unknown')}</Badge>;
  };

  if (loading) {
    // Skeletons mirror the credential cards below so the list does not jump
    // when the credentials arrive.
    return (
      <Card>
        <CardContent className="p-6">
          <div
            role="status"
            aria-live="polite"
            aria-busy="true"
            aria-label={t('common.loadingAria')}
          >
            <div className="flex items-center gap-3 mb-6">
              <Skeleton shape="circle" height={40} width={40} />
              <div style={{ flex: 1 }}>
                <Skeleton height={18} shape="text" width={5} />
                <div style={{ height: 'var(--space-2)' }} />
                <Skeleton height={11} shape="text" width={7} />
              </div>
            </div>
            <div className="grid gap-4">
              <SkeletonCard />
              <SkeletonCard />
              <SkeletonCard />
            </div>
            <span className="sr-only">{t('common.loading')}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      
      {success && (
        <Alert variant="default" className="bg-green-50 border-green-200">
          <CheckCircle className="h-4 w-4 text-green-600" />
          <AlertDescription className="text-green-800">{success}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle className="flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              {t('credential.wallet')}
            </CardTitle>
            <div className="space-x-2">
              <Dialog open={showIssueDialog} onOpenChange={setShowIssueDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    {t('credential.issue')}
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>{t('credential.issueNew')}</DialogTitle>
                  </DialogHeader>
                  <IssueCredentialForm
                    credential={newCredential}
                    onChange={setNewCredential}
                    onSubmit={issueCredential}
                    loading={loading}
                  />
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {credentials.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <FileText className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p>{t('credential.empty')}</p>
              <p className="text-sm">{t('credential.emptyHint')}</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {credentials.map((credential) => {
                const verification = verificationResults[credential.id];
                return (
                  <Card key={credential.id} className="hover:shadow-md transition-shadow">
                    <CardContent className="p-4">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center space-x-2 mb-2">
                            {getStatusIcon(verification)}
                            {getStatusBadge(verification)}
                            <span className="text-sm text-gray-500">
                              {format.formatDate(credential.issuanceDate)}
                            </span>
                          </div>
                          
                          <h3 className="font-medium mb-1">
                            {credential.type[credential.type.length - 1]}
                          </h3>
                          
                          <p className="text-sm text-gray-600 mb-2">
                            {t('credential.issuedBy', { issuer: `${credential.issuer.substring(0, 8)}...` })}
                          </p>
                          
                          <div className="flex flex-wrap gap-1 mb-2">
                            {credential.type.map((type, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {type}
                              </Badge>
                            ))}
                          </div>
                          
                          {credential.expirationDate && (
                            <p className="text-xs text-gray-500">
                              {t('credential.expirationDate')}: {format.formatDate(credential.expirationDate)}
                            </p>
                          )}
                        </div>
                        
                        <div className="flex space-x-2">
                          {/* Icon-only actions: each needs a name, since the
                              icon alone conveys nothing to a screen reader. */}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setSelectedCredential(credential)}
                            aria-label={t('credential.viewDetailsFor', { label: credentialLabel(credential) })}
                            title={t('credential.viewDetails')}
                          >
                            <Eye className="h-4 w-4" aria-hidden="true" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => downloadCredential(credential)}
                            aria-label={t('credential.exportJsonFor', { label: credentialLabel(credential) })}
                            title={t('credential.exportJson')}
                          >
                            <Download className="h-4 w-4" aria-hidden="true" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => shareCredential(credential)}
                            disabled={!verification?.valid}
                            aria-label={t('credential.shareFor', { label: credentialLabel(credential) })}
                            title={t('credential.shareAction')}
                          >
                            <Share className="h-4 w-4" aria-hidden="true" />
                          </Button>
                          {verification?.valid && (
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => revokeCredential(credential.id)}
                              aria-label={t('credential.revokeFor', { label: credentialLabel(credential) })}
                              title={t('credential.revokeAction')}
                            >
                              <XCircle className="h-4 w-4" aria-hidden="true" />
                            </Button>
                          )}
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {selectedCredential && (
        <Dialog open={!!selectedCredential} onOpenChange={() => setSelectedCredential(null)}>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{t('credential.details')}</DialogTitle>
            </DialogHeader>
            <CredentialDetail
              credential={selectedCredential}
              verification={verificationResults[selectedCredential.id]}
            />
          </DialogContent>
        </Dialog>
      )}

      {/* Errors and confirmations are announced, not just rendered. */}
      <LiveAnnouncer
        message={error ?? (success ? `Success: ${success}` : '')}
        politeness={error ? 'assertive' : 'polite'}
      />
    </div>
  );
};

interface IssueCredentialFormProps {
  credential: any;
  onChange: (credential: any) => void;
  onSubmit: () => void;
  loading: boolean;
}

const IssueCredentialForm: React.FC<IssueCredentialFormProps> = ({
  credential,
  onChange,
  onSubmit,
  loading
}) => {
  const { t } = useTranslation();

  // Credential type identifiers are written into the credential on chain and
  // compared by verifiers, so they are data rather than copy and must not be
  // translated. Only the surrounding labels are localised.
  const credentialTypes = [
    'KYCVerification',
    'EducationCredential',
    'ProfessionalLicense',
    'AgeVerification',
    'IncomeVerification',
    'IdentityVerification'
  ];

  return (
    <div className="space-y-4">
      <div>
        <Label htmlFor="subject">{t('credential.subjectAddress')}</Label>
        <Input
          id="subject"
          value={credential.subject}
          onChange={(e) => onChange({ ...credential, subject: e.target.value })}
          placeholder="G..."
        />
      </div>

      <div>
        <Label>{t('credential.typesLabel')}</Label>
        <Select
          value={credential.credentialType[0] || ''}
          onValueChange={(value) => onChange({ 
            ...credential, 
            credentialType: [value, 'VerifiableCredential'] 
          })}
        >
          <SelectTrigger>
            <SelectValue placeholder={t('credential.typesLabel')} />
          </SelectTrigger>
          <SelectContent>
            {credentialTypes.map((type) => (
              <SelectItem key={type} value={type}>
                {type}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div>
        <Label htmlFor="credentialData">{t('credential.dataLabel')}</Label>
        <Textarea
          id="credentialData"
          value={credential.credentialData}
          onChange={(e) => onChange({ ...credential, credentialData: e.target.value })}
          placeholder='{"name": "John Doe", "age": 30, "verified": true}'
          rows={6}
        />
      </div>

      <div>
        <Label htmlFor="expirationDate">{t('credential.expirationOptional')}</Label>
        <Input
          id="expirationDate"
          type="date"
          value={credential.expirationDate}
          onChange={(e) => onChange({ ...credential, expirationDate: e.target.value })}
        />
      </div>

      <Button onClick={onSubmit} disabled={loading} className="w-full">
        {loading ? t('credential.issuing') : t('credential.issue')}
      </Button>
    </div>
  );
};
