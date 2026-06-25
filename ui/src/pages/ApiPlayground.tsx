import React, { useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select';
import { Textarea } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Alert, AlertDescription } from '../components/ui/alert';
import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

// ---------------------------------------------------------------------------
// SDK function catalogue
// ---------------------------------------------------------------------------

interface ParamDef {
  name: string;
  type: 'string' | 'json' | 'boolean' | 'number';
  placeholder: string;
}

interface FunctionDef {
  group: string;
  label: string;
  fn: (sdk: StellarIdentitySDK, params: Record<string, string>) => Promise<unknown>;
  params: ParamDef[];
  codeTemplate: (params: Record<string, string>) => string;
}

const SDK_FUNCTIONS: FunctionDef[] = [
  {
    group: 'DID',
    label: 'resolveDID',
    params: [{ name: 'did', type: 'string', placeholder: 'did:stellar:G...' }],
    fn: (sdk, p) => sdk.did.resolveDID(p.did),
    codeTemplate: p => `const result = await sdk.did.resolveDID("${p.did ?? '<did>'}");`,
  },
  {
    group: 'DID',
    label: 'createDID (random keypair)',
    params: [],
    fn: (sdk) => {
      const kp = Keypair.random();
      return sdk.did.createDID(kp, { verificationMethods: [], services: [] });
    },
    codeTemplate: () =>
      `const kp = Keypair.random();\nconst did = await sdk.did.createDID(kp, { verificationMethods: [], services: [] });`,
  },
  {
    group: 'Credentials',
    label: 'verifyCredential',
    params: [{ name: 'credentialId', type: 'string', placeholder: 'cred-...' }],
    fn: (sdk, p) => sdk.credentials.verifyCredential(p.credentialId),
    codeTemplate: p => `const result = await sdk.credentials.verifyCredential("${p.credentialId ?? '<id>'}");`,
  },
  {
    group: 'Credentials',
    label: 'getSubjectCredentials',
    params: [{ name: 'address', type: 'string', placeholder: 'G...' }],
    fn: (sdk, p) => sdk.credentials.getSubjectCredentials(p.address),
    codeTemplate: p => `const ids = await sdk.credentials.getSubjectCredentials("${p.address ?? '<address>'}");`,
  },
  {
    group: 'Reputation',
    label: 'getReputationScore',
    params: [{ name: 'address', type: 'string', placeholder: 'G...' }],
    fn: (sdk, p) => sdk.reputation.getReputationScore(p.address),
    codeTemplate: p => `const score = await sdk.reputation.getReputationScore("${p.address ?? '<address>'}");`,
  },
  {
    group: 'Reputation',
    label: 'getReputationData',
    params: [{ name: 'address', type: 'string', placeholder: 'G...' }],
    fn: (sdk, p) => sdk.reputation.getReputationData(p.address),
    codeTemplate: p => `const data = await sdk.reputation.getReputationData("${p.address ?? '<address>'}");`,
  },
  {
    group: 'ZK Proofs',
    label: 'verifyProof',
    params: [{ name: 'proofId', type: 'string', placeholder: 'proof-...' }],
    fn: (sdk, p) => sdk.zkProofs.verifyProof(p.proofId),
    codeTemplate: p => `const result = await sdk.zkProofs.verifyProof("${p.proofId ?? '<id>'}");`,
  },
  {
    group: 'Identity',
    label: 'getIdentityProfile',
    params: [{ name: 'address', type: 'string', placeholder: 'G...' }],
    fn: (sdk, p) => sdk.getIdentityProfile(p.address),
    codeTemplate: p => `const profile = await sdk.getIdentityProfile("${p.address ?? '<address>'}");`,
  },
];

const GROUPS = [...new Set(SDK_FUNCTIONS.map(f => f.group))];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export interface ApiPlaygroundProps {
  rpcUrl?: string;
}

export function ApiPlayground({ rpcUrl }: ApiPlaygroundProps) {
  const [selectedFn, setSelectedFn] = useState<FunctionDef>(SDK_FUNCTIONS[0]);
  const [params, setParams] = useState<Record<string, string>>({});
  const [result, setResult] = useState<string>('');
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState(false);

  const sdk = new StellarIdentitySDK({
    ...DEFAULT_CONFIGS.testnet,
    ...(rpcUrl ? { rpcUrl } : {}),
  });

  const handleSelect = useCallback((label: string) => {
    const fn = SDK_FUNCTIONS.find(f => `${f.group}.${f.label}` === label);
    if (fn) {
      setSelectedFn(fn);
      setParams({});
      setResult('');
      setError('');
    }
  }, []);

  const handleRun = useCallback(async () => {
    setLoading(true);
    setResult('');
    setError('');
    try {
      const out = await selectedFn.fn(sdk, params);
      setResult(JSON.stringify(out, null, 2));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [sdk, selectedFn, params]);

  const codeSnippet = selectedFn.codeTemplate(params);

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold">API Playground</h1>
        <p className="text-sm text-gray-500 mt-1">
          Explore SDK functions interactively. Results are shown in real-time.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Function selector */}
        <Card className="md:col-span-1">
          <CardHeader>
            <CardTitle className="text-sm font-medium">Function</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {GROUPS.map(group => (
              <div key={group}>
                <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1">{group}</p>
                {SDK_FUNCTIONS.filter(f => f.group === group).map(f => (
                  <button
                    key={`${f.group}.${f.label}`}
                    onClick={() => handleSelect(`${f.group}.${f.label}`)}
                    className={`w-full text-left text-sm px-2 py-1 rounded transition-colors ${
                      selectedFn.label === f.label && selectedFn.group === f.group
                        ? 'bg-blue-100 text-blue-800 font-medium'
                        : 'hover:bg-gray-100'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Params + run */}
        <div className="md:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Badge variant="outline">{selectedFn.group}</Badge>
                {selectedFn.label}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedFn.params.length === 0 && (
                <p className="text-sm text-gray-500 italic">No parameters required.</p>
              )}
              {selectedFn.params.map(param => (
                <div key={param.name}>
                  <label className="text-xs font-medium text-gray-600 block mb-1">{param.name}</label>
                  <input
                    type="text"
                    className="w-full border rounded px-3 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-400"
                    placeholder={param.placeholder}
                    value={params[param.name] ?? ''}
                    onChange={e => setParams(prev => ({ ...prev, [param.name]: e.target.value }))}
                  />
                </div>
              ))}
              <Button onClick={handleRun} disabled={loading} className="w-full">
                {loading ? 'Running…' : '▶ Run'}
              </Button>
            </CardContent>
          </Card>

          {/* Code snippet */}
          <Card>
            <CardHeader>
              <CardTitle className="text-xs font-medium text-gray-500">Equivalent TypeScript</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-gray-900 text-green-400 text-xs rounded p-3 overflow-auto whitespace-pre-wrap">
                {`import { StellarIdentitySDK, DEFAULT_CONFIGS } from '@stellar-identity/sdk';\n\nconst sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);\n\n${codeSnippet}`}
              </pre>
            </CardContent>
          </Card>

          {/* Result */}
          {(result || error) && (
            <Card>
              <CardHeader>
                <CardTitle className="text-xs font-medium text-gray-500">
                  {error ? '⚠ Error' : '✓ Result'}
                </CardTitle>
              </CardHeader>
              <CardContent>
                {error ? (
                  <Alert variant="destructive">
                    <AlertDescription className="font-mono text-xs break-all">{error}</AlertDescription>
                  </Alert>
                ) : (
                  <pre className="bg-gray-50 text-gray-800 text-xs rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap">
                    {result}
                  </pre>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

export default ApiPlayground;
