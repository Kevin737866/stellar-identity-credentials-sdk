import React, { useState } from 'react';
import {
  Card,
  CardHeader,
  CardTitle,
  CardContent,
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
  DialogTrigger,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import {
  PredicateType,
  PredicateInfo,
  SelectiveDisclosureProof,
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import {
  Eye,
  EyeOff,
  Lock,
  Unlock,
  Plus,
  AlertCircle,
  CheckCircle,
  XCircle,
  GitCompare,
  Filter,
  Share2,
} from 'lucide-react';

interface SelectiveDisclosureProps {
  sdk: any;
  address: string;
  keypair: Keypair;
}

export const SelectiveDisclosure: React.FC<SelectiveDisclosureProps> = ({
  sdk,
  address,
  keypair,
}) => {
  const [disclosures, setDisclosures] = useState<SelectiveDisclosureProof[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [creationMode, setCreationMode] = useState<string>('range');
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [pendingDisclosures, setPendingDisclosures] = useState<string[]>([]);

  // Form state
  const [formData, setFormData] = useState({
    attributeName: '',
    attributeValue: '',
    threshold: '',
    min: '',
    max: '',
    circuitId: 'selective_disclosure',
    credentialId: '',
    predicateType: PredicateType.Range,
  });

  const handleCreate = async () => {
    try {
      setLoading(true);
      setError(null);

      if (!formData.attributeName || !formData.credentialId) {
        setError('Attribute name and credential ID are required');
        return;
      }

      let proofId: string;
      const val = Number(formData.attributeValue);

      switch (formData.predicateType) {
        case PredicateType.GreaterThan:
        case PredicateType.GreaterThanOrEqual:
          proofId = await sdk.zkProofs.createGreaterThanProof(
            keypair,
            formData.attributeName,
            val,
            Number(formData.threshold),
            formData.credentialId,
            formData.circuitId,
          );
          break;
        case PredicateType.Range:
          proofId = await sdk.zkProofs.createRangeProof(
            keypair,
            formData.attributeName,
            val,
            Number(formData.min),
            Number(formData.max),
            formData.credentialId,
            formData.circuitId,
          );
          break;
        case PredicateType.Equality:
          proofId = await sdk.zkProofs.createEqualityDisclosure(
            keypair,
            formData.attributeName,
            val,
            formData.credentialId,
            formData.circuitId,
          );
          break;
        default:
          proofId = await sdk.zkProofs.createSelectiveDisclosureProof(keypair, {
            circuitId: formData.circuitId,
            credentialId: formData.credentialId,
            publicInputs: [formData.attributeValue],
            proofBytes: '{}',
            nullifier: `sd_${Date.now()}`,
            revealedAttributes: [],
            hiddenAttributes: [formData.attributeName],
            predicates: [{
              attributeName: formData.attributeName,
              predicateType: formData.predicateType,
            }],
          });
      }

      setSuccess(`Selective disclosure proof created: ${proofId}`);
      setShowCreateDialog(false);
      resetForm();

      if (sdk.zkProofs.getSelectiveDisclosure) {
        try {
          const proof = await sdk.zkProofs.getSelectiveDisclosure(proofId);
          setDisclosures(prev => [...prev, proof]);
        } catch {}
      }
    } catch (err: any) {
      setError(err.message || 'Failed to create selective disclosure proof');
    } finally {
      setLoading(false);
    }
  };

  const handleCombine = async () => {
    if (pendingDisclosures.length < 2) {
      setError('Select at least 2 disclosures to combine');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const combinedId = await sdk.zkProofs.combineSelectiveDisclosures(
        keypair,
        pendingDisclosures,
        { combined_by: address, created_at: String(Date.now()) }
      );
      setSuccess(`Combined disclosure created: ${combinedId}`);
      setPendingDisclosures([]);
    } catch (err: any) {
      setError(err.message || 'Failed to combine disclosures');
    } finally {
      setLoading(false);
    }
  };

  const togglePending = (proofId: string) => {
    setPendingDisclosures(prev =>
      prev.includes(proofId)
        ? prev.filter(id => id !== proofId)
        : [...prev, proofId]
    );
  };

  const resetForm = () => {
    setFormData({
      attributeName: '',
      attributeValue: '',
      threshold: '',
      min: '',
      max: '',
      circuitId: 'selective_disclosure',
      credentialId: '',
      predicateType: PredicateType.Range,
    });
  };

  const getPredicateLabel = (predicate: PredicateInfo): string => {
    switch (predicate.predicateType) {
      case PredicateType.GreaterThan: return `> ${predicate.threshold}`;
      case PredicateType.GreaterThanOrEqual: return `>= ${predicate.threshold}`;
      case PredicateType.LessThan: return `< ${predicate.threshold}`;
      case PredicateType.LessThanOrEqual: return `<= ${predicate.threshold}`;
      case PredicateType.Equality: return `== ${predicate.threshold}`;
      case PredicateType.Range: return `[${predicate.rangeMin}, ${predicate.rangeMax}]`;
      case PredicateType.InSet: return `in {${(predicate.allowedValues || []).join(', ')}}`;
      case PredicateType.NotInSet: return `not in {${(predicate.allowedValues || []).join(', ')}}`;
    }
  };

  const getPredicateIcon = (type: PredicateType) => {
    switch (type) {
      case PredicateType.GreaterThan:
      case PredicateType.GreaterThanOrEqual:
      case PredicateType.LessThan:
      case PredicateType.LessThanOrEqual:
        return <GitCompare className="h-4 w-4" />;
      case PredicateType.Range:
        return <Filter className="h-4 w-4" />;
      case PredicateType.Equality:
        return <CheckCircle className="h-4 w-4" />;
      default:
        return <Lock className="h-4 w-4" />;
    }
  };

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
              <Share2 className="h-5 w-5 mr-2" />
              Selective Disclosure
            </CardTitle>
            <div className="space-x-2">
              {pendingDisclosures.length >= 2 && (
                <Button onClick={handleCombine} disabled={loading} variant="outline">
                  <GitCompare className="h-4 w-4 mr-2" />
                  Combine ({pendingDisclosures.length})
                </Button>
              )}
              <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="h-4 w-4 mr-2" />
                    Create Disclosure
                  </Button>
                </DialogTrigger>
                <DialogContent className="max-w-lg">
                  <DialogHeader>
                    <DialogTitle>Create Selective Disclosure Proof</DialogTitle>
                  </DialogHeader>
                  <div className="space-y-4">
                    <div>
                      <Label>Predicate Type</Label>
                      <Select
                        value={formData.predicateType}
                        onValueChange={(v) => setFormData({ ...formData, predicateType: v as PredicateType })}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select predicate type" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value={PredicateType.Range}>Range [min, max]</SelectItem>
                          <SelectItem value={PredicateType.GreaterThan}>Greater Than</SelectItem>
                          <SelectItem value={PredicateType.GreaterThanOrEqual}>Greater Than or Equal</SelectItem>
                          <SelectItem value={PredicateType.LessThan}>Less Than</SelectItem>
                          <SelectItem value={PredicateType.LessThanOrEqual}>Less Than or Equal</SelectItem>
                          <SelectItem value={PredicateType.Equality}>Equality (Reveal)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div>
                      <Label htmlFor="attributeName">Attribute Name</Label>
                      <Input
                        id="attributeName"
                        value={formData.attributeName}
                        onChange={(e) => setFormData({ ...formData, attributeName: e.target.value })}
                        placeholder="e.g., age, income, credit_score"
                      />
                    </div>

                    <div>
                      <Label htmlFor="attributeValue">Attribute Value (private)</Label>
                      <Input
                        id="attributeValue"
                        type="number"
                        value={formData.attributeValue}
                        onChange={(e) => setFormData({ ...formData, attributeValue: e.target.value })}
                        placeholder="The actual value (kept secret)"
                      />
                    </div>

                    {formData.predicateType === PredicateType.Range && (
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <Label htmlFor="min">Min Value</Label>
                          <Input
                            id="min"
                            type="number"
                            value={formData.min}
                            onChange={(e) => setFormData({ ...formData, min: e.target.value })}
                            placeholder="Minimum"
                          />
                        </div>
                        <div>
                          <Label htmlFor="max">Max Value</Label>
                          <Input
                            id="max"
                            type="number"
                            value={formData.max}
                            onChange={(e) => setFormData({ ...formData, max: e.target.value })}
                            placeholder="Maximum"
                          />
                        </div>
                      </div>
                    )}

                    {(formData.predicateType === PredicateType.GreaterThan ||
                      formData.predicateType === PredicateType.GreaterThanOrEqual ||
                      formData.predicateType === PredicateType.LessThan ||
                      formData.predicateType === PredicateType.LessThanOrEqual ||
                      formData.predicateType === PredicateType.Equality) && (
                      <div>
                        <Label htmlFor="threshold">Threshold / Value</Label>
                        <Input
                          id="threshold"
                          type="number"
                          value={formData.threshold}
                          onChange={(e) => setFormData({ ...formData, threshold: e.target.value })}
                          placeholder={
                            formData.predicateType === PredicateType.Equality
                              ? 'Value to reveal'
                              : 'Threshold value'
                          }
                        />
                      </div>
                    )}

                    <div>
                      <Label htmlFor="credentialId">Credential ID</Label>
                      <Input
                        id="credentialId"
                        value={formData.credentialId}
                        onChange={(e) => setFormData({ ...formData, credentialId: e.target.value })}
                        placeholder="ID of the credential containing this attribute"
                      />
                    </div>

                    <Button onClick={handleCreate} disabled={loading} className="w-full">
                      {loading ? 'Creating...' : 'Create Selective Disclosure Proof'}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="disclosures" className="w-full">
            <TabsList>
              <TabsTrigger value="disclosures">
                <EyeOff className="h-4 w-4 mr-2" />
                My Disclosures
              </TabsTrigger>
              <TabsTrigger value="combine">
                <GitCompare className="h-4 w-4 mr-2" />
                Combine
              </TabsTrigger>
            </TabsList>

            <TabsContent value="disclosures" className="space-y-4">
              {disclosures.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <EyeOff className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p>No selective disclosures yet</p>
                  <p className="text-sm">Create a proof that reveals only what's needed</p>
                </div>
              ) : (
                <div className="grid gap-4">
                  {disclosures.map((proof) => (
                    <Card key={proof.proofId} className="hover:shadow-md transition-shadow">
                      <CardContent className="p-4">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-2">
                              <EyeOff className="h-4 w-4 text-purple-500" />
                              <span className="font-mono text-sm text-gray-500">
                                {proof.proofId.slice(0, 16)}...
                              </span>
                            </div>

                            <div className="flex flex-wrap gap-2 mb-2">
                              {proof.predicates.map((pred, idx) => (
                                <Badge key={idx} variant="outline" className="flex items-center gap-1">
                                  {getPredicateIcon(pred.predicateType)}
                                  <span>{pred.attributeName}</span>
                                  <span className="text-xs text-gray-500">
                                    {getPredicateLabel(pred)}
                                  </span>
                                </Badge>
                              ))}
                            </div>

                            <div className="flex gap-2 text-xs text-gray-500">
                              {proof.revealedAttributes.length > 0 && (
                                <span className="flex items-center gap-1">
                                  <Eye className="h-3 w-3 text-green-500" />
                                  Revealed: {proof.revealedAttributes.join(', ')}
                                </span>
                              )}
                              {proof.hiddenAttributes.length > 0 && (
                                <span className="flex items-center gap-1">
                                  <EyeOff className="h-3 w-3 text-purple-500" />
                                  Hidden: {proof.hiddenAttributes.join(', ')}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="flex items-center space-x-2">
                            <input
                              type="checkbox"
                              checked={pendingDisclosures.includes(proof.proofId)}
                              onChange={() => togglePending(proof.proofId)}
                              className="rounded"
                            />
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            <TabsContent value="combine" className="space-y-4">
              <Card>
                <CardContent className="p-4">
                  <div className="text-center">
                    <GitCompare className="h-8 w-8 mx-auto mb-2 text-gray-400" />
                    <h3 className="font-medium mb-1">Combine Disclosures</h3>
                    <p className="text-sm text-gray-600 mb-4">
                      Select multiple disclosures from the list above, then combine them into
                      a single proof that satisfies all predicates simultaneously.
                    </p>
                    {pendingDisclosures.length > 0 ? (
                      <div className="space-y-2">
                        <p className="text-sm font-medium">
                          {pendingDisclosures.length} disclosure(s) selected
                        </p>
                        <Button onClick={handleCombine} disabled={pendingDisclosures.length < 2}>
                          <GitCompare className="h-4 w-4 mr-2" />
                          Combine into Single Proof
                        </Button>
                      </div>
                    ) : (
                      <p className="text-sm text-gray-400">
                        Check the boxes next to disclosures above to select them
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>

              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardContent className="p-4">
                    <h4 className="text-sm font-medium flex items-center mb-2">
                      <Unlock className="h-4 w-4 mr-2 text-green-500" />
                      Predicate Combinations
                    </h4>
                    <ul className="text-sm text-gray-600 space-y-1">
                      <li>• Age &gt; 18 AND Income &gt; $50k</li>
                      <li>• Credit score in [650, 850] AND age &gt; 21</li>
                      <li>• Country is in approved list AND age &gt; 18</li>
                      <li>• Multiple range proofs combined</li>
                    </ul>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4">
                    <h4 className="text-sm font-medium flex items-center mb-2">
                      <Lock className="h-4 w-4 mr-2 text-purple-500" />
                      Privacy Guarantees
                    </h4>
                    <ul className="text-sm text-gray-600 space-y-1">
                      <li>• Actual attribute values never revealed</li>
                      <li>• Verifier only learns predicate outcome</li>
                      <li>• Each proof uses unique nullifier</li>
                      <li>• Selective disclosure per attribute</li>
                    </ul>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};
