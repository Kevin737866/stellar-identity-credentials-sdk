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
  CredentialClient, 
  VerifiableCredential, 
  CredentialVerificationResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
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
      setError(error.message || 'Failed to load credentials');
    } finally {
      setLoading(false);
    }
  };

  const issueCredential = async () => {
    try {
      setLoading(true);
      setError(null);
      
      if (!newCredential.subject || newCredential.credentialType.length === 0 || !newCredential.credentialData) {
        setError('Please fill in all required fields');
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

      setSuccess(`Credential issued successfully: ${credentialId}`);
      setShowIssueDialog(false);
      setNewCredential({
        subject: '',
        credentialType: [],
        credentialData: '',
        expirationDate: ''
      });
      await loadCredentials();
    } catch (error: any) {
      setError(error.message || 'Failed to issue credential');
    } finally {
      setLoading(false);
    }
  };

  const revokeCredential = async (credentialId: string) => {
    if (!confirm('Are you sure you want to revoke this credential?')) {
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      await sdk.credentials.revokeCredential(keypair, credentialId, 'User requested revocation');
      setSuccess('Credential revoked successfully');
      await loadCredentials();
    } catch (error: any) {
      setError(error.message || 'Failed to revoke credential');
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
          title: 'Verifiable Credential',
          text: 'Share your verifiable credential',
          url: shareUrl
        });
      } else {
        await navigator.clipboard.writeText(shareUrl);
        setSuccess('Share link copied to clipboard!');
      }
    } catch (error: any) {
      setError(error.message || 'Failed to share credential');
    }
  };

  const getStatusIcon = (verification: CredentialVerificationResult) => {
    if (verification.revoked) {
      return <XCircle className="h-4 w-4 text-red-500" />;
    }
    if (verification.expired) {
      return <Clock className="h-4 w-4 text-yellow-500" />;
    }
    if (verification.valid) {
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    }
    return <AlertCircle className="h-4 w-4 text-gray-500" />;
  };

  const getStatusBadge = (verification: CredentialVerificationResult) => {
    if (verification.revoked) {
      return <Badge variant="destructive">Revoked</Badge>;
    }
    if (verification.expired) {
      return <Badge variant="secondary">Expired</Badge>;
    }
    if (verification.valid) {
      return <Badge variant="default">Valid</Badge>;
    }
    return <Badge variant="outline">Unknown</Badge>;
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Loading credentials...</span>
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
              Credential Wallet
            </CardTitle>
            <div className="space-x-2">
              <Dialog open={showIssueDialog} onOpenChange={setShowIssueDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Issue Credential
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Issue New Credential</DialogTitle>
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
              <p>No credentials found</p>
              <p className="text-sm">Issue your first credential to get started</p>
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
                              {new Date(credential.issuanceDate).toLocaleDateString()}
                            </span>
                          </div>
                          
                          <h3 className="font-medium mb-1">
                            {credential.type[credential.type.length - 1]}
                          </h3>
                          
                          <p className="text-sm text-gray-600 mb-2">
                            Issued by: {credential.issuer.substring(0, 8)}...
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
                              Expires: {new Date(credential.expirationDate).toLocaleDateString()}
                            </p>
                          )}
                        </div>
                        
                        <div className="flex space-x-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setSelectedCredential(credential)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => downloadCredential(credential)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => shareCredential(credential)}
                            disabled={!verification?.valid}
                          >
                            <Share className="h-4 w-4" />
                          </Button>
                          {verification?.valid && (
                            <Button
                              variant="destructive"
                              size="sm"
                              onClick={() => revokeCredential(credential.id)}
                            >
                              <XCircle className="h-4 w-4" />
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
              <DialogTitle>Credential Details</DialogTitle>
            </DialogHeader>
            <CredentialDetailView credential={selectedCredential} />
          </DialogContent>
        </Dialog>
      )}
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
        <Label htmlFor="subject">Subject Address</Label>
        <Input
          id="subject"
          value={credential.subject}
          onChange={(e) => onChange({ ...credential, subject: e.target.value })}
          placeholder="G..."
        />
      </div>

      <div>
        <Label>Credential Types</Label>
        <Select
          value={credential.credentialType[0] || ''}
          onValueChange={(value) => onChange({ 
            ...credential, 
            credentialType: [value, 'VerifiableCredential'] 
          })}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select credential type" />
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
        <Label htmlFor="credentialData">Credential Data (JSON)</Label>
        <Textarea
          id="credentialData"
          value={credential.credentialData}
          onChange={(e) => onChange({ ...credential, credentialData: e.target.value })}
          placeholder='{"name": "John Doe", "age": 30, "verified": true}'
          rows={6}
        />
      </div>

      <div>
        <Label htmlFor="expirationDate">Expiration Date (Optional)</Label>
        <Input
          id="expirationDate"
          type="date"
          value={credential.expirationDate}
          onChange={(e) => onChange({ ...credential, expirationDate: e.target.value })}
        />
      </div>

      <Button onClick={onSubmit} disabled={loading} className="w-full">
        {loading ? 'Issuing...' : 'Issue Credential'}
      </Button>
    </div>
  );
};

interface CredentialDetailViewProps {
  credential: VerifiableCredential;
}

const CredentialDetailView: React.FC<CredentialDetailViewProps> = ({ credential }) => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">Credential ID</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1 break-all">
            {credential.id}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">Type</Label>
          <div className="flex flex-wrap gap-1 mt-1">
            {credential.type.map((type, index) => (
              <Badge key={index} variant="outline">
                {type}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">Issuer</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {credential.issuer}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">Subject</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {credential.subject}
          </code>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">Issuance Date</Label>
          <p className="text-sm mt-1">
            {new Date(credential.issuanceDate).toLocaleString()}
          </p>
        </div>
        {credential.expirationDate && (
          <div>
            <Label className="text-sm font-medium">Expiration Date</Label>
            <p className="text-sm mt-1">
              {new Date(credential.expirationDate).toLocaleString()}
            </p>
          </div>
        )}
      </div>

      <div>
        <Label className="text-sm font-medium">Credential Data</Label>
        <pre className="bg-gray-100 p-4 rounded text-sm mt-1 overflow-x-auto">
          {JSON.stringify(credential.credentialData, null, 2)}
        </pre>
      </div>

      {credential.proof && (
        <div>
          <Label className="text-sm font-medium">Proof</Label>
          <pre className="bg-gray-100 p-4 rounded text-sm mt-1 overflow-x-auto">
            {credential.proof}
          </pre>
        </div>
      )}
    </div>
  );
};
