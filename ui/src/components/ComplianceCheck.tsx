import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardContent 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { 
  ComplianceRecord, 
  ComplianceResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { 
  Shield, 
  CheckCircle, 
  XCircle, 
  AlertTriangle, 
  Search,
  RefreshCw,
  Eye,
  Flag,
  Ban,
  CheckSquare,
  Activity,
  Globe,
  Database
} from 'lucide-react';

interface ComplianceCheckProps {
  sdk: any; // StellarIdentitySDK instance
  address: string;
  keypair: Keypair;
}

export const ComplianceCheck: React.FC<ComplianceCheckProps> = ({ sdk, address, keypair }) => {
  const [complianceData, setComplianceData] = useState<ComplianceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [checkingAddress, setCheckingAddress] = useState(address);
  const [customAddress, setCustomAddress] = useState('');

  useEffect(() => {
    performComplianceCheck(checkingAddress);
  }, [checkingAddress]);

  const performComplianceCheck = async (addr: string) => {
    try {
      setLoading(true);
      setError(null);
      
      const result = await sdk.performComplianceCheck(addr);
      setComplianceData(result);
    } catch (error: any) {
      setError(error.message || 'Failed to perform compliance check');
    } finally {
      setLoading(false);
    }
  };

  const checkCustomAddress = () => {
    if (customAddress && sdk.did.validateDIDFormat(`did:stellar:${customAddress}`)) {
      setCheckingAddress(customAddress);
    } else {
      setError('Invalid Stellar address format');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'cleared':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'flagged':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case 'blocked':
        return <XCircle className="h-5 w-5 text-red-500" />;
      default:
        return <Search className="h-5 w-5 text-gray-500" />;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'cleared':
        return <Badge className="bg-green-100 text-green-800">Cleared</Badge>;
      case 'flagged':
        return <Badge className="bg-yellow-100 text-yellow-800">Flagged</Badge>;
      case 'blocked':
        return <Badge className="bg-red-100 text-red-800">Blocked</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 80) {
      return { level: 'High Risk', color: 'bg-red-500', textColor: 'text-red-700' };
    } else if (score >= 60) {
      return { level: 'Medium Risk', color: 'bg-yellow-500', textColor: 'text-yellow-700' };
    } else if (score >= 40) {
      return { level: 'Low Risk', color: 'bg-blue-500', textColor: 'text-blue-700' };
    } else {
      return { level: 'Very Low Risk', color: 'bg-green-500', textColor: 'text-green-700' };
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Performing compliance check...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <div className="flex justify-between items-center">
            <CardTitle className="flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              Compliance Check
            </CardTitle>
            <div className="flex space-x-2">
              <Button
                variant="outline"
                onClick={() => performComplianceCheck(checkingAddress)}
                disabled={loading}
              >
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex space-x-2">
              <input
                type="text"
                value={customAddress}
                onChange={(e) => setCustomAddress(e.target.value)}
                placeholder="Enter Stellar address (G...)"
                className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
              <Button onClick={checkCustomAddress} disabled={loading}>
                <Search className="h-4 w-4 mr-2" />
                Check
              </Button>
            </div>
            
            <div className="text-sm text-gray-600">
              Currently checking: <code className="bg-gray-100 px-2 py-1 rounded">{checkingAddress}</code>
            </div>
          </div>
        </CardContent>
      </Card>

      {complianceData && (
        <>
          <Card className={`border-2 ${
            complianceData.status === 'blocked' ? 'border-red-200 bg-red-50' :
            complianceData.status === 'flagged' ? 'border-yellow-200 bg-yellow-50' :
            'border-green-200 bg-green-50'
          }`}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center space-x-2">
                  {getStatusIcon(complianceData.status)}
                  <span>Compliance Status</span>
                </CardTitle>
                {getStatusBadge(complianceData.status)}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="text-sm font-medium text-gray-600">Risk Score</label>
                    <div className="flex items-center space-x-2 mt-1">
                      <Progress value={complianceData.riskScore} className="flex-1" />
                      <span className="font-medium">{complianceData.riskScore}/100</span>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-600">Risk Level</label>
                    <div className="mt-1">
                      <Badge className={getRiskLevel(complianceData.riskScore).color}>
                        {getRiskLevel(complianceData.riskScore).level}
                      </Badge>
                    </div>
                  </div>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="text-gray-600">Sanctions Lists:</span>
                    <span className="ml-2 font-medium">
                      {complianceData.sanctionsLists.length > 0 ? 
                        `${complianceData.sanctionsLists.length} found` : 
                        'None found'
                      }
                    </span>
                  </div>
                  <div>
                    <span className="text-gray-600">Last Checked:</span>
                    <span className="ml-2 font-medium">
                      {new Date(complianceData.lastChecked).toLocaleString()}
                    </span>
                  </div>
                </div>

                {complianceData.sanctionsLists.length > 0 && (
                  <div>
                    <label className="text-sm font-medium text-gray-600">Sanctions Lists</label>
                    <div className="mt-2 space-y-1">
                      {complianceData.sanctionsLists.map((list, index) => (
                        <Badge key={index} variant="destructive" className="mr-2">
                          <Ban className="h-3 w-3 mr-1" />
                          {list}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center text-lg">
                  <Activity className="h-5 w-5 mr-2" />
                  Compliance Metrics
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <span className="text-sm font-medium">Overall Compliance Score</span>
                    <Badge variant="outline">{complianceData.complianceScore}/100</Badge>
                  </div>
                  <Progress value={complianceData.complianceScore} />
                  
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="text-center p-3 bg-gray-50 rounded">
                      <div className="text-lg font-bold text-blue-600">
                        {complianceData.totalCredentials}
                      </div>
                      <div className="text-gray-600">Total Credentials</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded">
                      <div className="text-lg font-bold text-green-600">
                        {complianceData.validCredentials}
                      </div>
                      <div className="text-gray-600">Valid Credentials</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center text-lg">
                  <CheckSquare className="h-5 w-5 mr-2" />
                  Recommendations
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {complianceData.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                      <span className="text-sm">{recommendation}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center text-lg">
                <Database className="h-5 w-5 mr-2" />
                Detailed Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className={`text-2xl font-bold ${
                      complianceData.riskScore < 40 ? 'text-green-600' :
                      complianceData.riskScore < 60 ? 'text-blue-600' :
                      complianceData.riskScore < 80 ? 'text-yellow-600' :
                      'text-red-600'
                    }`}>
                      {complianceData.riskScore}
                    </div>
                    <div className="text-sm text-gray-600">Risk Score</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-600">
                      {complianceData.totalCredentials}
                    </div>
                    <div className="text-sm text-gray-600">Credentials</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">
                      {complianceData.validCredentials}
                    </div>
                    <div className="text-sm text-gray-600">Valid</div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <h4 className="font-medium">Compliance Summary:</h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                    <div className="flex items-center space-x-2">
                      <Globe className="h-4 w-4 text-blue-500" />
                      <span>Sanctions Screening: {complianceData.sanctionsLists.length === 0 ? 'Clear' : 'Alert'}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Eye className="h-4 w-4 text-green-500" />
                      <span>Identity Verification: {complianceData.validCredentials > 0 ? 'Verified' : 'Not Verified'}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Flag className="h-4 w-4 text-yellow-500" />
                      <span>Risk Assessment: {getRiskLevel(complianceData.riskScore).level}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-500" />
                      <span>Overall Status: {complianceData.status}</span>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
};
