import React, { useState, useEffect, useMemo } from 'react';
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
import { Skeleton } from '@/components/ui/skeleton';
import { 
  ReputationClient, 
  ReputationScoreResult 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { useTranslation } from '../i18n';
import { 
  TrendingUp, 
  TrendingDown, 
  Minus, 
  Star, 
  Medal,
  Award,
  AlertCircle,
  CheckCircle,
  BarChart3,
  Target,
  Activity,
  Info,
  Gem,
  Shield,
} from 'lucide-react';

type BadgeSize = 'sm' | 'md' | 'lg';

interface TierConfig {
  /**
   * Stable identifier. Never compare or branch on the display name — it is a
   * translated string and changes with the active language.
   */
  id: string;
  /** Catalogue key for the display name. */
  nameKey: string;
  minScore: number;
  color: string;
  textColor: string;
  bgColor: string;
  borderColor: string;
  icon: React.ReactNode;
}

interface ReputationBadgeProps {
  sdk: any;
  address: string;
  keypair: Keypair;
  size?: BadgeSize;
}

const TIERS: TierConfig[] = [
  {
    id: 'platinum',
    nameKey: 'reputation.tiers.platinum',
    minScore: 751,
    color: 'bg-gradient-to-r from-purple-500 via-pink-500 to-amber-400',
    textColor: 'text-purple-700',
    bgColor: 'bg-purple-50',
    borderColor: 'border-purple-300',
    icon: <Gem className="h-5 w-5 text-purple-600" />,
  },
  {
    id: 'gold',
    nameKey: 'reputation.tiers.gold',
    minScore: 501,
    color: 'bg-amber-500',
    textColor: 'text-amber-700',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-300',
    icon: <Award className="h-5 w-5 text-amber-600" />,
  },
  {
    id: 'silver',
    nameKey: 'reputation.tiers.silver',
    minScore: 251,
    color: 'bg-gray-400',
    textColor: 'text-gray-700',
    bgColor: 'bg-gray-50',
    borderColor: 'border-gray-300',
    icon: <Medal className="h-5 w-5 text-gray-500" />,
  },
  {
    id: 'bronze',
    nameKey: 'reputation.tiers.bronze',
    minScore: 0,
    color: 'bg-amber-700',
    textColor: 'text-amber-800',
    bgColor: 'bg-amber-50',
    borderColor: 'border-amber-500',
    icon: <Shield className="h-5 w-5 text-amber-700" />,
  },
];

const sizeConfig = {
  sm: {
    cardPadding: 'p-3',
    scoreText: 'text-2xl',
    titleSize: 'text-sm',
    iconSize: 'h-4 w-4',
    badgeSize: 'text-xs',
    gap: 'gap-2',
  },
  md: {
    cardPadding: 'p-4',
    scoreText: 'text-3xl',
    titleSize: 'text-base',
    iconSize: 'h-5 w-5',
    badgeSize: 'text-sm',
    gap: 'gap-3',
  },
  lg: {
    cardPadding: 'p-6',
    scoreText: 'text-5xl',
    titleSize: 'text-lg',
    iconSize: 'h-6 w-6',
    badgeSize: 'text-base',
    gap: 'gap-4',
  },
};

const LoadingSkeleton: React.FC<{ size: BadgeSize }> = ({ size }) => {
  const cfg = sizeConfig[size];
  const { t } = useTranslation();
  return (
    <Card>
      <CardContent className={cfg.cardPadding}>
        <div
          role="status"
          aria-live="polite"
          aria-busy="true"
          aria-label={t('reputation.loading')}
        >
          <div className={`flex items-center justify-between ${cfg.gap}`}>
            <Skeleton height={16} shape="text" width={4} />
            <Skeleton height={24} shape="rect" width={64} />
          </div>
          <div className="flex justify-center" style={{ marginTop: 'var(--space-4)' }}>
            <Skeleton shape="circle" height={48} width={80} />
          </div>
          <div style={{ marginTop: 'var(--space-3)' }}>
            <Skeleton height={12} shape="text" />
          </div>
          <div className="grid grid-cols-2 gap-2" style={{ marginTop: 'var(--space-3)' }}>
            <Skeleton height={16} shape="text" />
            <Skeleton height={16} shape="text" />
          </div>
          <span className="sr-only">{t('reputation.loading')}</span>
        </div>
      </CardContent>
    </Card>
  );
};

export const ReputationBadge: React.FC<ReputationBadgeProps> = ({
  sdk,
  address,
  keypair,
  size = 'md',
}) => {
  const [reputationData, setReputationData] = useState<ReputationScoreResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showTooltip, setShowTooltip] = useState(false);
  const [prevScore, setPrevScore] = useState<number | null>(null);
  const [scoreChanged, setScoreChanged] = useState(false);

  const { t, format } = useTranslation();

  const cfg = sizeConfig[size];

  // Tier display names are resolved per render, so they follow the language.
  const tierName = (tier: TierConfig) => t(tier.nameKey);

  useEffect(() => {
    loadReputationData();
  }, [address]);

  useEffect(() => {
    if (prevScore !== null && reputationData && reputationData.score !== prevScore) {
      setScoreChanged(true);
      const timer = setTimeout(() => setScoreChanged(false), 1000);
      return () => clearTimeout(timer);
    }
    if (reputationData) {
      setPrevScore(reputationData.score);
    }
  }, [reputationData?.score]);

  const loadReputationData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const data = await sdk.reputation.getReputationAnalysis(address);
      setReputationData(data);
    } catch (error: any) {
      setError(error.message || t('reputation.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const toTierScore = (score: number): number => score <= 100 ? score * 10 : score;

  const getTier = (score: number): TierConfig => {
    const normalizedScore = toTierScore(score);
    return TIERS.find(t => normalizedScore >= t.minScore) || TIERS[TIERS.length - 1];
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

  const getScoreWithinTier = (score: number, tier: TierConfig): number => {
    const normalizedScore = toTierScore(score);
    const tierIndex = TIERS.indexOf(tier);
    if (tierIndex === 0) return 100;
    const nextTierMin = TIERS[tierIndex - 1].minScore;
    const range = nextTierMin - tier.minScore;
    return ((normalizedScore - tier.minScore) / range) * 100;
  };

  if (loading) {
    return <LoadingSkeleton size={size} />;
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
        <CardContent className={cfg.cardPadding}>
          <div className="text-center text-gray-500">
            <BarChart3 className="h-12 w-12 mx-auto mb-4 text-gray-400" />
            <p>{t('reputation.noData')}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  const tier = getTier(reputationData.score);
  const trend = sdk.reputation.calculateReputationTrend(reputationData.history);
  const progressInTier = getScoreWithinTier(reputationData.score, tier);

  return (
    <div className="space-y-6">
      <Card
        className={`${tier.bgColor} ${tier.borderColor} border-2 transition-all duration-500 ${
          scoreChanged ? 'scale-105 shadow-lg' : 'scale-100'
        }`}
      >
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className={`flex items-center space-x-2 ${cfg.titleSize}`}>
              {React.cloneElement(tier.icon as React.ReactElement, {
                className: `${cfg.iconSize} ${tier.textColor}`,
              })}
              <span className={tier.textColor}>{t('reputation.title')}</span>
            </CardTitle>
            <div className="relative">
              <Badge
                className={`${tier.color} text-white ${cfg.badgeSize} cursor-help`}
                onMouseEnter={() => setShowTooltip(true)}
                onMouseLeave={() => setShowTooltip(false)}
                onClick={() => setShowTooltip(!showTooltip)}
              >
                {tierName(tier)}
              </Badge>
              {showTooltip && reputationData && (
                <div className="absolute top-full right-0 mt-2 w-72 bg-white border rounded-lg shadow-xl z-50 p-4">
                  <div className="space-y-3">
                    <div className="flex items-center space-x-2 border-b pb-2">
                      {tier.icon}
                      <span className="font-semibold">
                        {t('reputation.tierLabel', { tier: tierName(tier) })}
                      </span>
                    </div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">{t('reputation.scoreRange')}</span>
                        <span className="font-medium">
                          {format.formatNumber(tier.minScore)} - {format.formatNumber(tier.id === 'platinum' ? 100 : TIERS[TIERS.indexOf(tier) - 1]?.minScore ?? 100)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">{t('reputation.totalTransactions')}</span>
                        <span className="font-medium">
                          {reputationData.factors?.transactionCount
                            ? format.formatNumber(reputationData.factors.transactionCount)
                            : t('reputation.notAvailable')}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">{t('reputation.successRate')}</span>
                        <span className="font-medium">
                          {reputationData.factors?.successRate
                            ? format.formatPercent(reputationData.factors.successRate * 100, 1)
                            : t('reputation.notAvailable')}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">{t('reputation.credentialCount')}</span>
                        <span className="font-medium">
                          {reputationData.factors?.credentialCount
                            ? format.formatNumber(reputationData.factors.credentialCount)
                            : t('reputation.notAvailable')}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">{t('reputation.percentile')}</span>
                        <span className="font-medium">
                          {format.formatPercent(reputationData.percentile)}
                        </span>
                      </div>
                    </div>
                    <div className="border-t pt-2 text-xs text-gray-500">
                      <p>
                        {TIERS[TIERS.indexOf(tier) - 1]
                          ? t('reputation.nextTier', {
                              tier: tierName(TIERS[TIERS.indexOf(tier) - 1]),
                            })
                          : t('reputation.maximum')}{' '}
                        {t('reputation.atPoints', {
                          count: format.formatNumber(
                            TIERS[TIERS.indexOf(tier) - 1]?.minScore || reputationData.score
                          ),
                        })}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className={`space-y-4 ${cfg.gap}`}>
            <div className="text-center">
              <div
                className={`${cfg.scoreText} font-bold mb-2 transition-all duration-700 ${
                  scoreChanged ? 'text-green-500' : tier.textColor
                }`}
              >
                {format.formatNumber(reputationData.score)}
              </div>
              <div className="flex items-center justify-center space-x-2">
                {getTrendIcon(trend.trend)}
                <span className="text-sm text-gray-600">
                  {trend.trend === 'up' ? '+' : ''}
                  {format.formatNumber(trend.change ?? 0, {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1,
                  })}{' '}
                  ({format.formatNumber(trend.percentage ?? 0, {
                    minimumFractionDigits: 1,
                    maximumFractionDigits: 1,
                  })}%)
                </span>
              </div>
            </div>
            
            <div className="relative">
              <Progress
                value={reputationData.score}
                className={`w-full transition-all duration-1000 ${tier.color}`}
              />
              <div className="flex justify-between text-xs text-gray-400 mt-1">
                <span>0</span>
                <span>25</span>
                <span>50</span>
                <span>75</span>
                <span>100</span>
              </div>
            </div>

            <div className={`grid grid-cols-2 gap-4 text-sm ${size === 'lg' ? '' : 'text-xs'}`}>
              <div>
                <span className="text-gray-600">{t('reputation.percentile')}:</span>
                <span className="ml-2 font-medium">
                  {format.formatPercent(reputationData.percentile)}
                </span>
              </div>
              <div>
                <span className="text-gray-600">{t('reputation.tierProgress')}</span>
                <span className="ml-2 font-medium">
                  {format.formatPercent(progressInTier)}
                </span>
              </div>
              <div>
                <span className="text-gray-600">{t('reputation.lastUpdated')}:</span>
                <span className="ml-2 font-medium">
                  {format.formatDate(reputationData.lastUpdated)}
                </span>
              </div>
              <div>
                <span className="text-gray-600">{t('reputation.tier')}</span>
                <span className={`ml-2 font-medium ${tier.textColor}`}>{tierName(tier)}</span>
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
              {t('reputation.factors')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {Object.entries(reputationData.factors || {}).map(([factor, count]) => (
                <div key={factor} className="flex justify-between items-center">
                  <span className="text-sm font-medium capitalize">
                    {factor.replace(/_/g, ' ')}
                  </span>
                  <Badge variant="outline">{String(count)}</Badge>
                </div>
              ))}
              {(!reputationData.factors || Object.keys(reputationData.factors).length === 0) && (
                <p className="text-sm text-gray-400">{t('reputation.noFactors')}</p>
              )}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Activity className="h-5 w-5 mr-2" />
              {t('reputation.activity')}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {(reputationData.history || []).slice(-5).reverse().map((score, index) => (
                <div key={index} className="flex justify-between items-center">
                  <span className="text-sm text-gray-600">
                    {index === 0
                      ? t('reputation.current')
                      : t('reputation.updatesAgo', { count: index })}
                  </span>
                  <span className="font-medium">{score}</span>
                </div>
              ))}
              {(!reputationData.history || reputationData.history.length === 0) && (
                <p className="text-sm text-gray-400">{t('reputation.noHistory')}</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className={cfg.titleSize}>{t('reputation.insights')}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${cfg.scoreText} font-bold text-blue-600`}>
                  {format.formatNumber(reputationData.score)}
                </div>
                <div className="text-sm text-gray-600">{t('reputation.currentScore')}</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${size === 'lg' ? 'text-2xl' : 'text-xl'} font-bold text-green-600`}>
                  {format.formatPercent(reputationData.percentile)}
                </div>
                <div className="text-sm text-gray-600">{t('reputation.percentileRank')}</div>
              </div>
              <div className="text-center p-4 bg-gray-50 rounded-lg">
                <div className={`${size === 'lg' ? 'text-2xl' : 'text-xl'} font-bold text-purple-600`}>
                  {format.formatNumber(Object.keys(reputationData.factors || {}).length)}
                </div>
                <div className="text-sm text-gray-600">{t('reputation.activeFactors')}</div>
              </div>
            </div>
            
            <div className="space-y-2">
              <h4 className="font-medium">{t('reputation.recommendations')}</h4>
              <ul className="text-sm text-gray-600 space-y-1">
                {reputationData.score < 60 && (
                  <li>{t('reputation.recommendationTransactions')}</li>
                )}
                {Object.keys(reputationData.factors || {}).length < 3 && (
                  <li>{t('reputation.recommendationCredentials')}</li>
                )}
                {trend.trend === 'down' && (
                  <li>{t('reputation.recommendationDeclining')}</li>
                )}
                {reputationData.score >= 80 && (
                  <li>{t('reputation.recommendationExcellent')}</li>
                )}
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};
