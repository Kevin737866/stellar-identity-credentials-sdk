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
import { Skeleton, SkeletonDetail } from '@/components/ui/skeleton';
import { DIDClient } from '@stellar-identity/sdk';
import { VerificationMethod, Service, DIDDocument, StellarIdentityConfig } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { useTranslation } from '@/i18n';
import { Copy, Plus, Trash2, Edit, CheckCircle, AlertCircle } from 'lucide-react';
import { useStellarIdentity } from '../hooks/useStellarIdentity';

interface DIDManagerProps {
  sdk: any;
  address: string;
  keypair: Keypair;
}

export const DIDManager: React.FC<DIDManagerProps> = ({ sdk, address, keypair }) => {
  const [didDocument, setDidDocument] = useState<DIDDocument | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // Form states
  const [verificationMethods, setVerificationMethods] = useState<VerificationMethod[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [newVerificationMethod, setNewVerificationMethod] = useState<VerificationMethod>({
    id: '',
    type: 'Ed25519VerificationKey2018',
    controller: address,
    publicKey: ''
  });
  const [newService, setNewService] = useState<Service>({
    id: '',
    type: '',
    endpoint: ''
  });

  const { t, format } = useTranslation();

  useEffect(() => {
    loadDIDDocument();
  }, [address]);

  const loadDIDDocument = async () => {
    try {
      setLoading(true);
      const did = sdk.did.generateDID(address);
      const result = await sdk.did.resolveDID(did);
      setDidDocument(result.didDocument);
      setVerificationMethods(result.didDocument.verificationMethod);
      setServices(result.didDocument.service);
    } catch (error) {
      // DID might not exist yet
      setDidDocument(null);
    } finally {
      setLoading(false);
    }
  };

  const createDID = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const did = await sdk.did.createDID(keypair, {
        verificationMethods,
        services
      });
      
      setSuccess(t('did.createSucceeded', { did }));
      setShowCreateDialog(false);
      await loadDIDDocument();
    } catch (error: any) {
      setError(error.message || t('did.createFailed'));
    } finally {
      setLoading(false);
    }
  };

  const updateDID = async () => {
    try {
      setLoading(true);
      setError(null);
      
      await sdk.did.updateDID(keypair, verificationMethods, services);
      setSuccess(t('did.updateSucceeded'));
      await loadDIDDocument();
    } catch (error: any) {
      setError(error.message || t('did.updateFailed'));
    } finally {
      setLoading(false);
    }
  };

  const deactivateDID = async () => {
    if (!confirm(t('did.deactivateConfirm'))) {
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      await sdk.did.deactivateDID(keypair);
      setSuccess(t('did.deactivateSucceeded'));
      setDidDocument(null);
    } catch (error: any) {
      setError(error.message || t('did.deactivateFailed'));
    } finally {
      setLoading(false);
    }
  };

  const addVerificationMethod = () => {
    if (!newVerificationMethod.id || !newVerificationMethod.publicKey) {
      setError(t('did.vmRequired'));
      return;
    }
    setVerificationMethods([...verificationMethods, { ...newVerificationMethod }]);
    setNewVerificationMethod({
      id: '',
      type: 'Ed25519VerificationKey2018',
      controller: address,
      publicKey: ''
    });
  };

  const removeVerificationMethod = (index: number) => {
    setVerificationMethods(verificationMethods.filter((_, i) => i !== index));
  };

  const addService = () => {
    if (!newService.id || !newService.type || !newService.endpoint) {
      setError(t('did.serviceRequired'));
      return;
    }
    setServices([...services, { ...newService }]);
    setNewService({ id: '', type: '', endpoint: '' });
  };

  const removeService = (index: number) => {
    setServices(services.filter((_, i) => i !== index));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess(t('common.copied'));
  };

  if (loading) {
    // A skeleton matching the card layout below, so content does not jump
    // when the DID resolves.
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
                <Skeleton height={16} shape="text" width={5} />
                <div style={{ height: 'var(--space-2)' }} />
                <Skeleton height={11} shape="text" width={8} />
              </div>
            </div>
            <SkeletonDetail fields={4} />
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
            <CardTitle>{t('did.title')}</CardTitle>
            <div className="space-x-2">
              {!didDocument ? (
                <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="h-4 w-4 mr-2" />
                      {t('did.create')}
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                    <DialogHeader>
                      <DialogTitle>{t('did.createNew')}</DialogTitle>
                    </DialogHeader>
                    <CreateDIDForm
                      verificationMethods={verificationMethods}
                      services={services}
                      newVerificationMethod={newVerificationMethod}
                      newService={newService}
                      onVerificationMethodChange={setNewVerificationMethod}
                      onServiceChange={setNewService}
                      onAddVerificationMethod={addVerificationMethod}
                      onRemoveVerificationMethod={removeVerificationMethod}
                      onAddService={addService}
                      onRemoveService={removeService}
                      onCreate={createDID}
                      loading={loading}
                    />
                  </DialogContent>
                </Dialog>
              ) : (
                <div className="space-x-2">
                  <Button variant="outline" onClick={updateDID}>
                    <Edit className="h-4 w-4 mr-2" />
                    {t('did.update')}
                  </Button>
                  <Button variant="destructive" onClick={deactivateDID}>
                    <Trash2 className="h-4 w-4 mr-2" />
                    {t('did.deactivate')}
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {didDocument ? (
            <DIDDocumentDisplay 
              didDocument={didDocument} 
              onCopy={copyToClipboard}
            />
          ) : (
            <div className="text-center py-8 text-gray-500">
              <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
              <p>{t('did.empty')}</p>
              <p className="text-sm">{t('did.emptyHint')}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

interface CreateDIDFormProps {
  verificationMethods: VerificationMethod[];
  services: Service[];
  newVerificationMethod: VerificationMethod;
  newService: Service;
  onVerificationMethodChange: (method: VerificationMethod) => void;
  onServiceChange: (service: Service) => void;
  onAddVerificationMethod: () => void;
  onRemoveVerificationMethod: (index: number) => void;
  onAddService: () => void;
  onRemoveService: (index: number) => void;
  onCreate: () => void;
  loading: boolean;
}

const CreateDIDForm: React.FC<CreateDIDFormProps> = ({
  verificationMethods,
  services,
  newVerificationMethod,
  newService,
  onVerificationMethodChange,
  onServiceChange,
  onAddVerificationMethod,
  onRemoveVerificationMethod,
  onAddService,
  onRemoveService,
  onCreate,
  loading
}) => {
  const { t } = useTranslation();

  return (
    <Tabs defaultValue="verification" className="w-full">
      <TabsList className="grid w-full grid-cols-2">
        <TabsTrigger value="verification">{t('did.verificationMethods')}</TabsTrigger>
        <TabsTrigger value="services">{t('did.services')}</TabsTrigger>
      </TabsList>
      
      <TabsContent value="verification" className="space-y-4">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">{t('did.verificationMethods')}</h3>
          
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label htmlFor="vm-id">ID</Label>
              <Input
                id="vm-id"
                value={newVerificationMethod.id}
                onChange={(e) => onVerificationMethodChange({
                  ...newVerificationMethod,
                  id: e.target.value
                })}
                placeholder="e.g., #key-1"
              />
            </div>
            <div>
              <Label htmlFor="vm-publicKey">{t('did.publicKey')}</Label>
              <Input
                id="vm-publicKey"
                value={newVerificationMethod.publicKey}
                onChange={(e) => onVerificationMethodChange({
                  ...newVerificationMethod,
                  publicKey: e.target.value
                })}
                placeholder="Stellar public key"
              />
            </div>
          </div>
          
          <Button onClick={onAddVerificationMethod} className="w-full">
            <Plus className="h-4 w-4 mr-2" />
            {t('did.addMethod')}
          </Button>
          
          {verificationMethods.length > 0 && (
            <div className="space-y-2">
              <h4 className="font-medium">{t('did.currentMethods')}</h4>
              {verificationMethods.map((method, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded">
                  <div>
                    <p className="font-medium">{method.id}</p>
                    <p className="text-sm text-gray-600">{method.type}</p>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => onRemoveVerificationMethod(index)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </TabsContent>
      
      <TabsContent value="services" className="space-y-4">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold">{t('did.services')}</h3>
          
          <div className="grid grid-cols-3 gap-4">
            <div>
              <Label htmlFor="service-id">ID</Label>
              <Input
                id="service-id"
                value={newService.id}
                onChange={(e) => onServiceChange({
                  ...newService,
                  id: e.target.value
                })}
                placeholder="e.g., #hub"
              />
            </div>
            <div>
              <Label htmlFor="service-type">{t('credential.type')}</Label>
              <Input
                id="service-type"
                value={newService.type}
                onChange={(e) => onServiceChange({
                  ...newService,
                  type: e.target.value
                })}
                placeholder="e.g., IdentityHub"
              />
            </div>
            <div>
              <Label htmlFor="service-endpoint">{t('did.endpoint')}</Label>
              <Input
                id="service-endpoint"
                value={newService.endpoint}
                onChange={(e) => onServiceChange({
                  ...newService,
                  endpoint: e.target.value
                })}
                placeholder="https://example.com/hub"
              />
            </div>
          </div>
          
          <Button onClick={onAddService} className="w-full">
            <Plus className="h-4 w-4 mr-2" />
            {t('did.addService')}
          </Button>
          
          {services.length > 0 && (
            <div className="space-y-2">
              <h4 className="font-medium">{t('did.currentServices')}</h4>
              {services.map((service, index) => (
                <div key={index} className="flex items-center justify-between p-3 border rounded">
                  <div>
                    <p className="font-medium">{service.id}</p>
                    <p className="text-sm text-gray-600">{service.type}</p>
                    <p className="text-xs text-gray-500">{service.endpoint}</p>
                  </div>
                  <Button
                    variant="destructive"
                    size="sm"
                    onClick={() => onRemoveService(index)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </TabsContent>
      
      <div className="flex justify-end space-x-2 pt-4">
        <Button onClick={onCreate} disabled={loading}>
          {loading ? t('did.creating') : t('did.create')}
        </Button>
      </div>
    </Tabs>
  );
};

interface DIDDocumentDisplayProps {
  didDocument: DIDDocument;
  onCopy: (text: string) => void;
}

const DIDDocumentDisplay: React.FC<DIDDocumentDisplayProps> = ({ didDocument, onCopy }) => {
  const { t, format } = useTranslation();

  return (
    <div className="space-y-6">
      <div>
        <Label className="text-sm font-medium">DID</Label>
        <div className="flex items-center space-x-2 mt-1">
          <code className="bg-gray-100 px-3 py-2 rounded text-sm flex-1">{didDocument.id}</code>
          <Button variant="outline" size="sm" onClick={() => onCopy(didDocument.id)}>
            <Copy className="h-4 w-4" />
          </Button>
        </div>
      </div>
      
      <div>
        <Label className="text-sm font-medium">{t('did.controller')}</Label>
        <div className="flex items-center space-x-2 mt-1">
          <code className="bg-gray-100 px-3 py-2 rounded text-sm flex-1">{didDocument.controller}</code>
          <Button variant="outline" size="sm" onClick={() => onCopy(didDocument.controller)}>
            <Copy className="h-4 w-4" />
          </Button>
        </div>
      </div>
      
      <div>
        <Label className="text-sm font-medium">{t('did.created')}</Label>
        <p className="text-sm text-gray-600 mt-1">
          {format.formatDateTime(didDocument.created)}
        </p>
      </div>
      
      <div>
        <Label className="text-sm font-medium">{t('did.lastUpdated')}</Label>
        <p className="text-sm text-gray-600 mt-1">
          {format.formatDateTime(didDocument.updated)}
        </p>
      </div>
      
      {didDocument.verificationMethod.length > 0 && (
        <div>
          <Label className="text-sm font-medium">{t('did.verificationMethods')}</Label>
          <div className="space-y-2 mt-2">
            {didDocument.verificationMethod.map((method, index) => (
              <Card key={index}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-medium">{method.id}</p>
                      <p className="text-sm text-gray-600">{method.type}</p>
                      <p className="text-xs text-gray-500 mt-1">{t('did.controller')}: {method.controller}</p>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => onCopy(method.publicKey)}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                  <div className="mt-2">
                    <Label className="text-xs">{t('did.publicKey')}</Label>
                    <code className="block bg-gray-100 px-2 py-1 rounded text-xs mt-1 break-all">
                      {method.publicKey}
                    </code>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
      
      {didDocument.service.length > 0 && (
        <div>
          <Label className="text-sm font-medium">{t('did.services')}</Label>
          <div className="space-y-2 mt-2">
            {didDocument.service.map((service, index) => (
              <Card key={index}>
                <CardContent className="p-4">
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-medium">{service.id}</p>
                      <p className="text-sm text-gray-600">{service.type}</p>
                      <p className="text-xs text-gray-500 mt-1">{service.endpoint}</p>
                    </div>
                    <Button variant="outline" size="sm" onClick={() => onCopy(service.endpoint)}>
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

interface ConnectedDIDManagerProps {
  config: StellarIdentityConfig;
  autoConnect?: boolean;
}

export const ConnectedDIDManager: React.FC<ConnectedDIDManagerProps> = ({
  config,
  autoConnect = false,
}) => {
  const { t } = useTranslation();
  const { sdk, address, keypair, isLoading, error } = useStellarIdentity({
    config,
    autoConnect,
  });

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">{t('did.connecting')}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>{error}</AlertDescription>
      </Alert>
    );
  }

  if (!sdk || !address || !keypair) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center py-8 text-gray-500">
            <AlertCircle className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>{t('did.notConnected')}</p>
            <p className="text-sm">{t('did.notConnectedHint')}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return <DIDManager sdk={sdk} address={address} keypair={keypair} />;
};
