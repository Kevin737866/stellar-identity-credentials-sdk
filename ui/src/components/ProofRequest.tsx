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
import { Checkbox } from '@/components/ui/checkbox';
import { Skeleton, SkeletonList } from '@/components/ui/skeleton';
import { useTranslation } from '../i18n';
import { 
  ZKProofsClient, 
  ZKProof, 
  ZKVerificationResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  Eye, 
  EyeOff, 
  Lock,
  Unlock,
  Plus,
  AlertCircle,
  Zap,
  UserCheck,
  Calendar,
  DollarSign
} from 'lucide-react';

interface ProofRequestProps {
  sdk: any; // StellarIdentitySDK instance
  address: string;
  keypair: Keypair;
}

export const ProofRequest: React.FC<ProofRequestProps> = ({ sdk, address, keypair }) => {
  const { t, format } = useTranslation();
  const [proofs, setProofs] = useState<ZKProof[]>([]);
  const [circuits, setCircuits] = useState<any[]>([]);
  const [selectedProof, setSelectedProof] = useState<ZKProof | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [verificationResults, setVerificationResults] = useState<Record<string, ZKVerificationResult>>({});

  // Form states
  const [newProof, setNewProof] = useState({
    circuitId: '',
    publicInputs: [] as string[],
    proofBytes: '',
    expiresAt: '',
    metadata: {} as Record<string, string>
  });

  useEffect(() => {
    loadProofs();
    loadCircuits();
  }, [address]);

  const loadProofs = async () => {
    try {
      setLoading(true);
      // Load proofs for this address - this would need to be implemented in the SDK
      const proofIds = await sdk.zkProofs.getCircuitProofs('age_verification'); // Example
      const proofPromises = proofIds.map(id => sdk.zkProofs.getProof(id));
      const loadedProofs = await Promise.all(proofPromises);
      setProofs(loadedProofs);
      
      // Verify all proofs
      const verificationPromises = proofIds.map(id => 
        sdk.zkProofs.verifyProof(id)
      );
      const results = await Promise.all(verificationPromises);
      const verificationMap: Record<string, ZKVerificationResult> = {};
      proofIds.forEach((id, index) => {
        verificationMap[id] = results[index];
      });
      setVerificationResults(verificationMap);
    } catch (error: any) {
      setError(error.message || t('proof.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const loadCircuits = async () => {
    try {
      const circuitIds = await sdk.zkProofs.getActiveCircuits();
      const circuitPromises = circuitIds.map(id => sdk.zkProofs.getCircuit(id));
      const loadedCircuits = await Promise.all(circuitPromises);
      setCircuits(loadedCircuits);
    } catch (error: any) {
      console.error(t('proof.circuitsLoadFailed'), error);
    }
  };

  const createProof = async () => {
    try {
      setLoading(true);
      setError(null);
      
      if (!newProof.circuitId || !newProof.proofBytes) {
        setError(t('proof.requiredFields'));
        return;
      }

      const expirationDate = newProof.expiresAt ? 
        new Date(newProof.expiresAt).getTime() : undefined;

      const proofId = await sdk.zkProofs.submitProof({
        circuitId: newProof.circuitId,
        publicInputs: newProof.publicInputs,
        proofBytes: newProof.proofBytes,
        expiresAt: expirationDate,
        metadata: newProof.metadata
      });

      setSuccess(t('proof.createSucceeded', { id: proofId }));
      setShowCreateDialog(false);
      setNewProof({
        circuitId: '',
        publicInputs: [],
        proofBytes: '',
        expiresAt: '',
        metadata: {}
      });
      await loadProofs();
    } catch (error: any) {
      setError(error.message || t('proof.createFailed'));
    } finally {
      setLoading(false);
    }
  };

  const createAgeProof = async (minAge: number) => {
    try {
      setLoading(true);
      setError(null);
      
      const commitment = sdk.zkProofs.generateCommitment('user_age_data');
      // In a real implementation, this would be generated using a ZK circuit
      const proofBytes = 'mock_age_proof_bytes';
      
      const proofId = await sdk.zkProofs.createAgeProof(
        'age_verification',
        commitment,
        minAge,
        proofBytes
      );

      setSuccess(t('proof.ageSucceeded', { id: proofId }));
      await loadProofs();
    } catch (error: any) {
      setError(error.message || t('proof.ageFailed'));
    } finally {
      setLoading(false);
    }
  };

  const createIncomeProof = async (minIncome: number) => {
    try {
      setLoading(true);
      setError(null);
      
      const commitment = sdk.zkProofs.generateCommitment('user_income_data');
      const proofBytes = 'mock_income_proof_bytes';
      
      const proofId = await sdk.zkProofs.createIncomeProof(
        'income_verification',
        commitment,
        minIncome,
        proofBytes
      );

      setSuccess(t('proof.incomeSucceeded', { id: proofId }));
      await loadProofs();
    } catch (error: any) {
      setError(error.message || t('proof.incomeFailed'));
    } finally {
      setLoading(false);
    }
  };

  const verifyProof = async (proofId: string) => {
    try {
      setLoading(true);
      const result = await sdk.zkProofs.verifyProof(proofId);
      setVerificationResults(prev => ({
        ...prev,
        [proofId]: result
      }));
    } catch (error: any) {
      setError(error.message || t('proof.verifyFailed'));
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (verification: ZKVerificationResult) => {
    if (verification.valid) {
      return <CheckCircle className="h-4 w-4 text-green-500" />;
    }
    return <XCircle className="h-4 w-4 text-red-500" />;
  };

  const getStatusBadge = (verification: ZKVerificationResult) => {
    if (verification.valid) {
      return <Badge variant="default">{t('proof.status.valid')}</Badge>;
    }
    return <Badge variant="destructive">{t('proof.status.invalid')}</Badge>;
  };

  const getCircuitIcon = (circuitId: string) => {
    switch (circuitId) {
      case 'age_verification':
        return <Calendar className="h-4 w-4" />;
      case 'income_verification':
        return <DollarSign className="h-4 w-4" />;
      case 'identity_verification':
        return <UserCheck className="h-4 w-4" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div
            role="status"
            aria-live="polite"
            aria-busy="true"
            aria-label={t('proof.loading')}
          >
            <div className="flex items-center gap-3 mb-6">
              <Skeleton shape="circle" height={40} width={40} />
              <div style={{ flex: 1 }}>
                <Skeleton height={16} shape="text" width={6} />
                <div style={{ height: 'var(--space-2)' }} />
                <Skeleton height={11} shape="text" width={9} />
              </div>
            </div>
            <SkeletonList rows={3} />
            <span className="sr-only">{t('proof.loading')}</span>
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
              <Zap className="h-5 w-5 mr-2" />
              {t('proof.title')}
            </CardTitle>
            <div className="space-x-2">
              <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    {t('proof.create')}
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>{t('proof.createNew')}</DialogTitle>
                  </DialogHeader>
                  <CreateProofForm
                    proof={newProof}
                    circuits={circuits}
                    onChange={setNewProof}
                    onSubmit={createProof}
                    loading={loading}
                  />
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="quick-actions" className="w-full">
            <TabsList>
              <TabsTrigger value="quick-actions">{t('proof.quickActions')}</TabsTrigger>
              <TabsTrigger value="my-proofs">{t('proof.myProofs')}</TabsTrigger>
              <TabsTrigger value="circuits">{t('proof.availableCircuits')}</TabsTrigger>
            </TabsList>
            
            <TabsContent value="quick-actions" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium flex items-center">
                          <Calendar className="h-4 w-4 mr-2" />
                          {t('proof.age')}
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          {t('proof.ageDescription')}
                        </p>
                      </div>
                      <Button
                        onClick={() => createAgeProof(18)}
                        disabled={loading}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        {t('proof.create')}
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium flex items-center">
                          <DollarSign className="h-4 w-4 mr-2" />
                          {t('proof.income')}
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          {t('proof.incomeDescription')}
                        </p>
                      </div>
                      <Button
                        onClick={() => createIncomeProof(50000)}
                        disabled={loading}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        {t('proof.create')}
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium flex items-center">
                          <UserCheck className="h-4 w-4 mr-2" />
                          {t('proof.identity')}
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          {t('proof.identityDescription')}
                        </p>
                      </div>
                      <Button
                        onClick={() => {
                          setNewProof({
                            circuitId: 'identity_verification',
                            publicInputs: ['credential_hash'],
                            proofBytes: '',
                            expiresAt: '',
                            metadata: { type: 'credential_ownership' }
                          });
                          setShowCreateDialog(true);
                        }}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        {t('proof.create')}
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium flex items-center">
                          <Shield className="h-4 w-4 mr-2" />
                          {t('proof.customTitle')}
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          {t('proof.customDescription')}
                        </p>
                      </div>
                      <Button
                        onClick={() => setShowCreateDialog(true)}
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        {t('proof.custom')}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="my-proofs" className="space-y-4">
              {proofs.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p>{t('proof.empty')}</p>
                  <p className="text-sm">{t('proof.emptyHint')}</p>
                </div>
              ) : (
                <div className="grid gap-4">
                  {proofs.map((proof) => {
                    const verification = verificationResults[proof.proofId];
                    return (
                      <Card key={proof.proofId} className="hover:shadow-md transition-shadow">
                        <CardContent className="p-4">
                          <div className="flex justify-between items-start">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                {getCircuitIcon(proof.circuitId)}
                                {verification && getStatusIcon(verification)}
                                {verification && getStatusBadge(verification)}
                                <span className="text-sm text-gray-500">
                                  {format.formatDate(new Date(proof.createdAt))}
                                </span>
                              </div>

                              {/* Circuit ids are on-chain identifiers, not UI copy: they are
                                  never translated, only shortened to fit the card. */}
                              <h3 className="font-medium mb-1">
                                {format.truncateMiddle(proof.circuitId, 24)}
                              </h3>

                              <p className="text-sm text-gray-600 mb-2">
                                {t('proof.circuitLabel')}: {proof.circuitId}
                              </p>
                              
                              <div className="flex flex-wrap gap-1 mb-2">
                                {Object.entries(proof.metadata).map(([key, value]) => (
                                  <Badge key={key} variant="outline" className="text-xs">
                                    {key}: {value}
                                  </Badge>
                                ))}
                              </div>
                              
                              {proof.expiresAt && (
                                <p className="text-xs text-gray-500">
                                  {t('proof.expires')}: {format.formatDate(new Date(proof.expiresAt))}
                                </p>
                              )}
                            </div>
                            
                            <div className="flex space-x-2">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setSelectedProof(proof)}
                              >
                                <Eye className="h-4 w-4" />
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => verifyProof(proof.proofId)}
                                disabled={loading}
                              >
                                <CheckCircle className="h-4 w-4" />
                              </Button>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })}
                </div>
              )}
            </TabsContent>
            
            <TabsContent value="circuits" className="space-y-4">
              <div className="grid gap-4">
                {circuits.map((circuit) => (
                  <Card key={circuit.circuitId} className="hover:shadow-md transition-shadow">
                    <CardContent className="p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="flex items-center space-x-2 mb-2">
                            {getCircuitIcon(circuit.circuitId)}
                            <h3 className="font-medium">{circuit.name}</h3>
                            <Badge variant={circuit.active ? 'default' : 'secondary'}>
                              {circuit.active ? t('proof.active') : t('proof.inactive')}
                            </Badge>
                          </div>
                          {/* Name and description come from the server in English; they are
                              data, not localisable copy. */}
                          <p className="text-sm text-gray-600 mb-2">{circuit.description}</p>
                          <div className="text-xs text-gray-500">
                            <p>{t('proof.publicInputsCount', { count: format.formatNumber(circuit.publicInputCount) })}</p>
                            <p>{t('proof.privateInputsCount', { count: format.formatNumber(circuit.privateInputCount) })}</p>
                          </div>
                        </div>
                        <Button
                          variant="outline"
                          onClick={() => {
                            setNewProof({
                              circuitId: circuit.circuitId,
                              publicInputs: new Array(circuit.publicInputCount).fill(''),
                              proofBytes: '',
                              expiresAt: '',
                              metadata: {}
                            });
                            setShowCreateDialog(true);
                          }}
                        >
                          {t('proof.useCircuit')}
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>

      {selectedProof && (
        <Dialog open={!!selectedProof} onOpenChange={() => setSelectedProof(null)}>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>{t('proof.details')}</DialogTitle>
            </DialogHeader>
            <ProofDetailView proof={selectedProof} />
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
};

interface CreateProofFormProps {
  proof: any;
  circuits: any[];
  onChange: (proof: any) => void;
  onSubmit: () => void;
  loading: boolean;
}

const CreateProofForm: React.FC<CreateProofFormProps> = ({
  proof,
  circuits,
  onChange,
  onSubmit,
  loading
}) => {
  const { t } = useTranslation();
  const selectedCircuit = circuits.find(c => c.circuitId === proof.circuitId);

  const addPublicInput = () => {
    onChange({
      ...proof,
      publicInputs: [...proof.publicInputs, '']
    });
  };

  const updatePublicInput = (index: number, value: string) => {
    const newInputs = [...proof.publicInputs];
    newInputs[index] = value;
    onChange({
      ...proof,
      publicInputs: newInputs
    });
  };

  const removePublicInput = (index: number) => {
    onChange({
      ...proof,
      publicInputs: proof.publicInputs.filter((_, i) => i !== index)
    });
  };

  return (
    <div className="space-y-4">
      <div>
        <Label>{t('proof.circuitLabel')}</Label>
        <Select
          value={proof.circuitId}
          onValueChange={(value) => onChange({ 
            ...proof, 
            circuitId: value,
            publicInputs: new Array(circuits.find(c => c.circuitId === value)?.publicInputCount || 0).fill('')
          })}
        >
          <SelectTrigger>
            <SelectValue placeholder={t('proof.selectCircuit')} />
          </SelectTrigger>
          <SelectContent>
            {circuits.map((circuit) => (
              <SelectItem key={circuit.circuitId} value={circuit.circuitId}>
                {circuit.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {selectedCircuit && (
        <div>
          <Label>{t('proof.publicInputs')}</Label>
          <div className="space-y-2 mt-2">
            {proof.publicInputs.map((input: string, index: number) => (
              <div key={index} className="flex space-x-2">
                <Input
                  value={input}
                  onChange={(e) => updatePublicInput(index, e.target.value)}
                  placeholder={t('proof.inputPlaceholder', { index: index + 1 })}
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => removePublicInput(index)}
                >
                  <XCircle className="h-4 w-4" />
                </Button>
              </div>
            ))}
            <Button
              variant="outline"
              onClick={addPublicInput}
              className="w-full"
            >
              <Plus className="h-4 w-4 mr-2" />
              {t('proof.addInput')}
            </Button>
          </div>
        </div>
      )}

      <div>
        <Label htmlFor="proofBytes">{t('proof.proofBytes')}</Label>
        <Textarea
          id="proofBytes"
          value={proof.proofBytes}
          onChange={(e) => onChange({ ...proof, proofBytes: e.target.value })}
          placeholder={t('proof.proofBytesPlaceholder')}
          rows={4}
        />
      </div>

      <div>
        <Label htmlFor="expiresAt">{t('proof.expirationDateOptional')}</Label>
        <Input
          id="expiresAt"
          type="date"
          value={proof.expiresAt}
          onChange={(e) => onChange({ ...proof, expiresAt: e.target.value })}
        />
      </div>

      <Button onClick={onSubmit} disabled={loading} className="w-full">
        {loading ? t('proof.creating') : t('proof.create')}
      </Button>
    </div>
  );
};

interface ProofDetailViewProps {
  proof: ZKProof;
}

const ProofDetailView: React.FC<ProofDetailViewProps> = ({ proof }) => {
  const { t, format } = useTranslation();
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">{t('proof.proofId')}</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1 break-all">
            {proof.proofId}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">{t('proof.circuitId')}</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {proof.circuitId}
          </code>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">{t('proof.verifierAddress')}</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {proof.verifierAddress}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">{t('proof.createdAt')}</Label>
          <p className="text-sm mt-1">
            {format.formatDateTime(new Date(proof.createdAt))}
          </p>
        </div>
      </div>

      {proof.expiresAt && (
        <div>
          <Label className="text-sm font-medium">{t('proof.expiresAt')}</Label>
          <p className="text-sm mt-1">
            {format.formatDateTime(new Date(proof.expiresAt))}
          </p>
        </div>
      )}

      <div>
        <Label className="text-sm font-medium">{t('proof.publicInputs')}</Label>
        <div className="space-y-1 mt-1">
          {proof.publicInputs.map((input, index) => (
            <code key={index} className="block bg-gray-100 px-3 py-2 rounded text-sm">
              {input}
            </code>
          ))}
        </div>
      </div>

      <div>
        <Label className="text-sm font-medium">{t('proof.proofBytes')}</Label>
        <pre className="bg-gray-100 p-4 rounded text-sm mt-1 overflow-x-auto">
          {proof.proofBytes}
        </pre>
      </div>

      {Object.keys(proof.metadata).length > 0 && (
        <div>
          <Label className="text-sm font-medium">{t('proof.metadata')}</Label>
          <div className="grid grid-cols-2 gap-2 mt-1">
            {Object.entries(proof.metadata).map(([key, value]) => (
              <div key={key} className="bg-gray-100 p-2 rounded text-sm">
                <span className="font-medium">{key}:</span> {value}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
