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
      setError(error.message || 'Failed to load proofs');
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
      console.error('Failed to load circuits:', error);
    }
  };

  const createProof = async () => {
    try {
      setLoading(true);
      setError(null);
      
      if (!newProof.circuitId || !newProof.proofBytes) {
        setError('Please fill in all required fields');
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

      setSuccess(`Proof created successfully: ${proofId}`);
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
      setError(error.message || 'Failed to create proof');
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

      setSuccess(`Age proof created successfully: ${proofId}`);
      await loadProofs();
    } catch (error: any) {
      setError(error.message || 'Failed to create age proof');
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

      setSuccess(`Income proof created successfully: ${proofId}`);
      await loadProofs();
    } catch (error: any) {
      setError(error.message || 'Failed to create income proof');
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
      setError(error.message || 'Failed to verify proof');
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
      return <Badge variant="default">Valid</Badge>;
    }
    return <Badge variant="destructive">Invalid</Badge>;
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
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Loading zero-knowledge proofs...</span>
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
              Zero-Knowledge Proofs
            </CardTitle>
            <div className="space-x-2">
              <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Proof
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-2xl">
                  <DialogHeader>
                    <DialogTitle>Create Zero-Knowledge Proof</DialogTitle>
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
              <TabsTrigger value="quick-actions">Quick Actions</TabsTrigger>
              <TabsTrigger value="my-proofs">My Proofs</TabsTrigger>
              <TabsTrigger value="circuits">Available Circuits</TabsTrigger>
            </TabsList>
            
            <TabsContent value="quick-actions" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="hover:shadow-md transition-shadow">
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="font-medium flex items-center">
                          <Calendar className="h-4 w-4 mr-2" />
                          Age Verification
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          Prove you're over 18 without revealing your age
                        </p>
                      </div>
                      <Button
                        onClick={() => createAgeProof(18)}
                        disabled={loading}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        Create Proof
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
                          Income Verification
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          Prove minimum income without revealing exact amount
                        </p>
                      </div>
                      <Button
                        onClick={() => createIncomeProof(50000)}
                        disabled={loading}
                      >
                        <Lock className="h-4 w-4 mr-2" />
                        Create Proof
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
                          Identity Verification
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          Prove you own a credential without revealing details
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
                        Create Proof
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
                          Custom Proof
                        </h3>
                        <p className="text-sm text-gray-600 mt-1">
                          Create a custom zero-knowledge proof
                        </p>
                      </div>
                      <Button
                        onClick={() => setShowCreateDialog(true)}
                      >
                        <Plus className="h-4 w-4 mr-2" />
                        Custom
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
                  <p>No proofs found</p>
                  <p className="text-sm">Create your first zero-knowledge proof</p>
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
                                  {new Date(proof.createdAt).toLocaleDateString()}
                                </span>
                              </div>
                              
                              <h3 className="font-medium mb-1">
                                {proof.circuitId.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                              </h3>
                              
                              <p className="text-sm text-gray-600 mb-2">
                                Circuit: {proof.circuitId}
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
                                  Expires: {new Date(proof.expiresAt).toLocaleDateString()}
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
                              {circuit.active ? 'Active' : 'Inactive'}
                            </Badge>
                          </div>
                          <p className="text-sm text-gray-600 mb-2">{circuit.description}</p>
                          <div className="text-xs text-gray-500">
                            <p>Public inputs: {circuit.publicInputCount}</p>
                            <p>Private inputs: {circuit.privateInputCount}</p>
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
                          Use Circuit
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
              <DialogTitle>Proof Details</DialogTitle>
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
        <Label>Circuit</Label>
        <Select
          value={proof.circuitId}
          onValueChange={(value) => onChange({ 
            ...proof, 
            circuitId: value,
            publicInputs: new Array(circuits.find(c => c.circuitId === value)?.publicInputCount || 0).fill('')
          })}
        >
          <SelectTrigger>
            <SelectValue placeholder="Select circuit" />
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
          <Label>Public Inputs</Label>
          <div className="space-y-2 mt-2">
            {proof.publicInputs.map((input: string, index: number) => (
              <div key={index} className="flex space-x-2">
                <Input
                  value={input}
                  onChange={(e) => updatePublicInput(index, e.target.value)}
                  placeholder={`Input ${index + 1}`}
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
              Add Input
            </Button>
          </div>
        </div>
      )}

      <div>
        <Label htmlFor="proofBytes">Proof Bytes</Label>
        <Textarea
          id="proofBytes"
          value={proof.proofBytes}
          onChange={(e) => onChange({ ...proof, proofBytes: e.target.value })}
          placeholder="Generated proof bytes from ZK circuit"
          rows={4}
        />
      </div>

      <div>
        <Label htmlFor="expiresAt">Expiration Date (Optional)</Label>
        <Input
          id="expiresAt"
          type="date"
          value={proof.expiresAt}
          onChange={(e) => onChange({ ...proof, expiresAt: e.target.value })}
        />
      </div>

      <Button onClick={onSubmit} disabled={loading} className="w-full">
        {loading ? 'Creating...' : 'Create Proof'}
      </Button>
    </div>
  );
};

interface ProofDetailViewProps {
  proof: ZKProof;
}

const ProofDetailView: React.FC<ProofDetailViewProps> = ({ proof }) => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">Proof ID</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1 break-all">
            {proof.proofId}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">Circuit ID</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {proof.circuitId}
          </code>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <Label className="text-sm font-medium">Verifier Address</Label>
          <code className="block bg-gray-100 px-3 py-2 rounded text-sm mt-1">
            {proof.verifierAddress}
          </code>
        </div>
        <div>
          <Label className="text-sm font-medium">Created At</Label>
          <p className="text-sm mt-1">
            {new Date(proof.createdAt).toLocaleString()}
          </p>
        </div>
      </div>

      {proof.expiresAt && (
        <div>
          <Label className="text-sm font-medium">Expires At</Label>
          <p className="text-sm mt-1">
            {new Date(proof.expiresAt).toLocaleString()}
          </p>
        </div>
      )}

      <div>
        <Label className="text-sm font-medium">Public Inputs</Label>
        <div className="space-y-1 mt-1">
          {proof.publicInputs.map((input, index) => (
            <code key={index} className="block bg-gray-100 px-3 py-2 rounded text-sm">
              {input}
            </code>
          ))}
        </div>
      </div>

      <div>
        <Label className="text-sm font-medium">Proof Bytes</Label>
        <pre className="bg-gray-100 p-4 rounded text-sm mt-1 overflow-x-auto">
          {proof.proofBytes}
        </pre>
      </div>

      {Object.keys(proof.metadata).length > 0 && (
        <div>
          <Label className="text-sm font-medium">Metadata</Label>
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
