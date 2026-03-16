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
  ReputationClient, 
  ReputationScoreResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { 
  TrendingUp, 
  TrendingDown, 
  Minus, 
  Star, 
  Shield, 
  Award,
  AlertCircle,
  CheckCircle,
  BarChart3,
  Target,
  Activity
} from 'lucide-react';

interface ReputationBadgeProps {
  sdk: any; // StellarIdentitySDK instance
  address: string;
  keypair: Keypair;
}

export const ReputationBadge: React.FC<ReputationBadgeProps> = ({ sdk, address, keypair }) => {
  const [reputationData, setReputationData] = useState<ReputationScoreResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadReputationData();
  }, [address]);

  const loadReputationData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const data = await sdk.reputation.getReputationAnalysis(address);
      setReputationData(data);
    } catch (error: any) {
      setError(error.message || 'Failed to load reputation data');
    } finally {
      setLoading(false);
    }
  };

  const getReputationTier = (score: number) => {
    if (score >= 90) {
      return {
        tier: 'Excellent',
        color: 'bg-green-500',
        textColor: 'text-green-700',
        bgColor: 'bg-green-50',
        borderColor: 'border-green-200',
        icon: <Award className="h-5 w-5" />
      };
    } else if (score >= 75) {
      return {
        tier: 'Good',
        color: 'bg-blue-500',
        textColor: 'text-blue-700',
        bgColor: 'bg-blue-50',
        borderColor: 'border-blue-200',
        icon: <Star className="h-5 w-5" />
      };
    } else if (score >= 60) {
      return {
        tier: 'Fair',
        color: 'bg-yellow-500',
        textColor: 'text-yellow-700',
        bgColor: 'bg-yellow-50',
        borderColor: 'border-yellow-200',
        icon: <Shield className="h-5 w-5" />
      };
    } else if (score >= 40) {
      return {
        tier: 'Poor',
        color: 'bg-orange-500',
        textColor: 'text-orange-700',
        bgColor: 'bg-orange-50',
        borderColor: 'border-orange-200',
        icon: <AlertCircle className="h-5 w-5" />
      };
    } else {
      return {
        tier: 'Very Poor',
        color: 'bg-red-500',
        textColor: 'text-red-700',
        bgColor: 'bg-red-50',
        borderColor: 'border-red-200',
        icon: <AlertCircle className="h-5 w-5" />
      };
    }
  };

  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-4 w-4 text-green-500" />;
      case 'down':
        return <TrendingDown className="h-4 w-4 text-red-500" />;
      default:
        return <Minus className="h-4 w-4 text-gray-500" />;
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <span className="ml-2">Loading reputation data...</span>
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

  if (!reputationData) {
    return (
      <Card>
        <CardContent className="p-6">
          <div className="text-center text-gray-500">
            <BarChart3 className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>No reputation data available</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const tier = getReputationTier(reputationData.score);
  const trend = sdk.reputation.calculateReputationTrend(reputationData.history);

  return (
    <div className="space-y-6">
      <Card className={`${tier.bgColor} ${tier.borderColor} border-2`}>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center space-x-2">
              {tier.icon}
              <span className={tier.textColor}>Reputation Score</span>
            </CardTitle>
            <Badge className={`${tier.color} text-white`}>
              {tier.tier}
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="text-center">
              <div className="text-4xl font-bold mb-2">{reputationData.score}</div>
              <div className="flex items-center justify-center space-x-2">
                {getTrendIcon(trend.trend)}
                <span className="text-sm text-gray-600">
                  {trend.trend === 'up' ? '+' : ''}{trend.change.toFixed(1)} ({trend.percentage.toFixed(1)}%)
                </span>
              </div>
            </div>
            
            <Progress value={reputationData.score} className="w-full" />
            
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-gray-600">Percentile:</span>
                <span className="ml-2 font-medium">{reputationData.percentile}%</span>
              </div>
              <div>
                <span className="text-gray-600">Last Updated:</span>
                <span className="ml-2 font-medium">
                  {new Date(reputationData.lastUpdated).toLocaleDateString()}
                </span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Target className="h-5 w-5 mr-2" />
              Reputation Factors
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(reputationData.factors).map(([factor, count]) => (
                <div key={factor} className="flex justify-between items-center">
                  <span className="text-sm font-medium capitalize">
                    {factor.replace(/_/g, ' ')}
                  </span>
                  <Badge variant="outline">{count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Activity className="h-5 w-5 mr-2" />
              Recent Activity
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {reputationData.history.slice(-5).reverse().map((score, index) => (
                <div key={index} className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">
                    {index === 0 ? 'Current' : `${index} updates ago`}
                  </span>
                  <span className="font-medium">{score}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Reputation Insights</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-blue-600">
                  {reputationData.score}
                </div>
                <div className="text-sm text-gray-600">Current Score</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-green-600">
                  {reputationData.percentile}%
                </div>
                <div className="text-sm text-gray-600">Percentile Rank</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className="text-2xl font-bold text-purple-600">
                  {Object.keys(reputationData.factors).length}
                </div>
                <div className="text-sm text-gray-600">Active Factors</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-medium">Recommendations:</h4>
              <ul className="text-sm text-gray-600 space-y-1">
                {reputationData.score < 60 && (
                  <li>• Focus on successful transactions to improve your score</li>
                )}
                {Object.keys(reputationData.factors).length < 3 && (
                  <li>• Obtain more verifiable credentials to strengthen your reputation</li>
                )}
                {trend.trend === 'down' && (
                  <li>• Recent activity shows a declining trend - consider reviewing recent transactions</li>
                )}
                {reputationData.score >= 80 && (
                  <li>• Excellent reputation! Maintain your current activity level</li>
                )}
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
