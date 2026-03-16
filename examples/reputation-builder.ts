/**
 * Build reputation through transaction history and credential validation
 * This example demonstrates how to establish and improve reputation on Stellar
 */

import { 
  StellarIdentitySDK, 
  DEFAULT_CONFIGS,
  UTILS 
} from '@stellar-identity/sdk';
import { Keypair, Server, TransactionBuilder, Networks, Asset, PaymentOperation } from 'stellar-sdk';

interface Transaction {
  hash: string;
  successful: boolean;
  amount: number;
  timestamp: number;
  type: 'payment' | 'exchange' | 'contract';
}

interface CredentialRecord {
  type: string;
  valid: boolean;
  issuer: string;
  issuanceDate: number;
  verificationCount: number;
}

async function main() {
  console.log('🚀 Starting Reputation Builder Example...\n');

  // Initialize SDK for testnet
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // Generate keypair for the user building reputation
  const userKeypair = UTILS.generateKeypair();
  console.log(`👤 User Address: ${userKeypair.publicKey()}`);

  try {
    // Step 1: Initialize reputation tracking
    console.log('\n📊 Step 1: Initializing Reputation Tracking...');
    await sdk.reputation.initializeReputation(userKeypair.publicKey());
    let currentScore = await sdk.reputation.getReputationScore(userKeypair.publicKey());
    console.log(`   Initial Score: ${currentScore}/100`);

    // Step 2: Build reputation through successful transactions
    console.log('\n💰 Step 2: Building Transaction History...');
    const transactions = await generateTransactionHistory(userKeypair.publicKey());
    
    for (const tx of transactions) {
      const newScore = await sdk.reputation.updateTransactionReputation(
        userKeypair.publicKey(),
        tx.successful,
        tx.amount
      );
      console.log(`   Transaction ${tx.hash.substring(0, 8)}...: ${newScore}/100 (${tx.successful ? '✅' : '❌'})`);
    }

    // Step 3: Add credentials to boost reputation
    console.log('\n📜 Step 3: Adding Verifiable Credentials...');
    const credentials = await generateCredentialHistory(userKeypair.publicKey());
    
    for (const cred of credentials) {
      const newScore = await sdk.reputation.updateCredentialReputation(
        userKeypair.publicKey(),
        cred.valid,
        cred.type
      );
      console.log(`   ${cred.type}: ${newScore}/100 (${cred.valid ? '✅' : '❌'})`);
    }

    // Step 4: Get comprehensive reputation analysis
    console.log('\n📈 Step 4: Reputation Analysis...');
    const reputationAnalysis = await sdk.reputation.getReputationAnalysis(userKeypair.publicKey());
    
    console.log(`   Final Score: ${reputationAnalysis.score}/100`);
    console.log(`   Percentile: ${reputationAnalysis.percentile}%`);
    console.log(`   Factors: ${JSON.stringify(reputationAnalysis.factors, null, 2)}`);

    // Step 5: Analyze reputation trends
    console.log('\n📊 Step 5: Reputation Trends...');
    const trend = sdk.reputation.calculateReputationTrend(reputationAnalysis.history);
    console.log(`   Trend: ${trend.trend} (${trend.change > 0 ? '+' : ''}${trend.change.toFixed(1)} points)`);
    console.log(`   Percentage Change: ${trend.percentage.toFixed(1)}%`);

    // Step 6: Get reputation tier and recommendations
    console.log('\n🏆 Step 6: Reputation Tier & Recommendations...');
    const tierInfo = sdk.reputation.getReputationTier(reputationAnalysis.score);
    console.log(`   Tier: ${tierInfo.tier}`);
    console.log(`   Color: ${tierInfo.color}`);
    console.log(`   Description: ${tierInfo.description}`);

    // Step 7: Simulate ongoing reputation building
    console.log('\n🔄 Step 7: Ongoing Reputation Building...');
    await simulateOngoingReputationBuilding(sdk, userKeypair.publicKey());

    // Step 8: Generate reputation report
    console.log('\n📋 Step 8: Generating Reputation Report...');
    const report = await generateReputationReport(sdk, userKeypair.publicKey());
    console.log('\n📊 Reputation Report:');
    console.log(JSON.stringify(report, null, 2));

    return {
      address: userKeypair.publicKey(),
      finalScore: reputationAnalysis.score,
      tier: tierInfo.tier,
      percentile: reputationAnalysis.percentile,
      trend: trend.trend,
      factors: reputationAnalysis.factors
    };

  } catch (error) {
    console.error('❌ Reputation Builder Failed:', error);
    throw error;
  }
}

/**
 * Generate sample transaction history for reputation building
 */
async function generateTransactionHistory(userAddress: string): Promise<Transaction[]> {
  const transactions: Transaction[] = [];
  
  // Generate successful transactions (build reputation)
  for (let i = 0; i < 15; i++) {
    transactions.push({
      hash: `tx_success_${i}_${Date.now()}`,
      successful: true,
      amount: Math.floor(Math.random() * 1000) + 100,
      timestamp: Date.now() - (i * 24 * 60 * 60 * 1000), // Daily transactions
      type: 'payment'
    });
  }

  // Add some failed transactions (realistic scenario)
  for (let i = 0; i < 3; i++) {
    transactions.push({
      hash: `tx_failed_${i}_${Date.now()}`,
      successful: false,
      amount: Math.floor(Math.random() * 500) + 50,
      timestamp: Date.now() - ((i + 20) * 24 * 60 * 60 * 1000),
      type: 'payment'
    });
  }

  // Add some high-value transactions (more impact)
  for (let i = 0; i < 5; i++) {
    transactions.push({
      hash: `tx_high_value_${i}_${Date.now()}`,
      successful: true,
      amount: Math.floor(Math.random() * 5000) + 2000,
      timestamp: Date.now() - ((i + 30) * 24 * 60 * 60 * 1000),
      type: 'exchange'
    });
  }

  return transactions.sort((a, b) => a.timestamp - b.timestamp);
}

/**
 * Generate sample credential history for reputation building
 */
async function generateCredentialHistory(userAddress: string): Promise<CredentialRecord[]> {
  const credentials: CredentialRecord[] = [
    {
      type: 'KYCVerification',
      valid: true,
      issuer: 'kyc-provider.example.com',
      issuanceDate: Date.now() - (90 * 24 * 60 * 60 * 1000),
      verificationCount: 25
    },
    {
      type: 'EducationCredential',
      valid: true,
      issuer: 'university.example.com',
      issuanceDate: Date.now() - (60 * 24 * 60 * 60 * 1000),
      verificationCount: 15
    },
    {
      type: 'ProfessionalLicense',
      valid: true,
      issuer: 'licensing-board.example.com',
      issuanceDate: Date.now() - (30 * 24 * 60 * 60 * 1000),
      verificationCount: 8
    },
    {
      type: 'IdentityVerification',
      valid: true,
      issuer: 'identity-provider.example.com',
      issuanceDate: Date.now() - (15 * 24 * 60 * 60 * 1000),
      verificationCount: 12
    },
    {
      type: 'AgeVerification',
      valid: true,
      issuer: 'age-verification.example.com',
      issuanceDate: Date.now() - (7 * 24 * 60 * 60 * 1000),
      verificationCount: 5
    }
  ];

  return credentials;
}

/**
 * Simulate ongoing reputation building activities
 */
async function simulateOngoingReputationBuilding(
  sdk: StellarIdentitySDK, 
  userAddress: string
): Promise<void> {
  console.log('   Simulating weekly reputation activities...');
  
  for (let week = 1; week <= 4; week++) {
    // Simulate weekly transactions
    const weeklyTransactions = 5 + Math.floor(Math.random() * 5);
    let weeklyScore = 0;
    
    for (let tx = 0; tx < weeklyTransactions; tx++) {
      const success = Math.random() > 0.1; // 90% success rate
      const amount = Math.floor(Math.random() * 1000) + 100;
      
      weeklyScore = await sdk.reputation.updateTransactionReputation(
        userAddress,
        success,
        amount
      );
    }
    
    console.log(`   Week ${week}: ${weeklyTransactions} transactions, Score: ${weeklyScore}/100`);
    
    // Simulate credential verification
    if (week === 2) {
      const credScore = await sdk.reputation.updateCredentialReputation(
        userAddress,
        true,
        'IncomeVerification'
      );
      console.log(`   Week ${week}: Income verified, Score: ${credScore}/100`);
    }
  }
}

/**
 * Generate comprehensive reputation report
 */
async function generateReputationReport(
  sdk: StellarIdentitySDK, 
  userAddress: string
): Promise<any> {
  const reputationData = await sdk.reputation.getReputationData(userAddress);
  const reputationAnalysis = await sdk.reputation.getReputationAnalysis(userAddress);
  const tierInfo = sdk.reputation.getReputationTier(reputationAnalysis.score);
  const trend = sdk.reputation.calculateReputationTrend(reputationAnalysis.history);
  
  return {
    address: userAddress,
    timestamp: Date.now(),
    currentScore: reputationAnalysis.score,
    tier: tierInfo.tier,
    percentile: reputationAnalysis.percentile,
    trend: {
      direction: trend.trend,
      change: trend.change,
      percentage: trend.percentage
    },
    statistics: {
      transactionCount: reputationData.transactionCount,
      successfulTransactions: reputationData.successfulTransactions,
      credentialCount: reputationData.credentialCount,
      validCredentials: reputationData.validCredentials,
      successRate: reputationData.transactionCount > 0 
        ? (reputationData.successfulTransactions / reputationData.transactionCount * 100).toFixed(1) + '%'
        : 'N/A'
    },
    factors: reputationAnalysis.factors,
    history: reputationAnalysis.history.slice(-10), // Last 10 entries
    recommendations: generateRecommendations(reputationAnalysis.score, tierInfo.tier),
    projectedScore: calculateProjectedScore(reputationAnalysis.score, trend.trend)
  };
}

/**
 * Generate personalized recommendations based on reputation
 */
function generateRecommendations(score: number, tier: string): string[] {
  const recommendations: string[] = [];
  
  if (score < 40) {
    recommendations.push('Focus on successful transactions to build basic reputation');
    recommendations.push('Obtain basic identity verification credentials');
    recommendations.push('Maintain consistent transaction activity');
  } else if (score < 60) {
    recommendations.push('Increase transaction volume and success rate');
    recommendations.push('Add professional or educational credentials');
    recommendations.push('Participate in more verification processes');
  } else if (score < 80) {
    recommendations.push('Maintain current activity level');
    recommendations.push('Add specialized credentials for your field');
    recommendations.push('Consider becoming a credential issuer');
  } else {
    recommendations.push('Excellent reputation! Maintain current standards');
    recommendations.push('Help others build reputation through endorsements');
    recommendations.push('Consider reputation-based services and opportunities');
  }
  
  return recommendations;
}

/**
 * Calculate projected score based on current trend
 */
function calculateProjectedScore(currentScore: number, trend: 'up' | 'down' | 'stable'): number {
  const trendMultiplier = trend === 'up' ? 1.05 : trend === 'down' ? 0.95 : 1.0;
  const projectedScore = Math.min(100, Math.max(0, currentScore * trendMultiplier));
  return Math.round(projectedScore);
}

/**
 * Advanced reputation building strategies
 */
export class ReputationBuilder {
  private sdk: StellarIdentitySDK;

  constructor(sdk: StellarIdentitySDK) {
    this.sdk = sdk;
  }

  /**
   * Implement rapid reputation building strategy
   */
  async rapidBuildStrategy(userAddress: string, duration: number = 30): Promise<void> {
    console.log(`🚀 Starting rapid reputation build for ${duration} days...`);
    
    const dailyTransactions = 10;
    const credentialTypes = [
      'IdentityVerification',
      'EmailVerification',
      'PhoneVerification',
      'SocialVerification',
      'AddressVerification'
    ];

    for (let day = 1; day <= duration; day++) {
      // Daily transactions
      for (let tx = 0; tx < dailyTransactions; tx++) {
        await this.sdk.reputation.updateTransactionReputation(
          userAddress,
          true, // High success rate
          Math.floor(Math.random() * 500) + 100
        );
      }

      // Weekly credential additions
      if (day % 7 === 0) {
        const credentialType = credentialTypes[Math.floor(day / 7) % credentialTypes.length];
        await this.sdk.reputation.updateCredentialReputation(
          userAddress,
          true,
          credentialType
        );
      }

      const currentScore = await this.sdk.reputation.getReputationScore(userAddress);
      console.log(`Day ${day}: Score ${currentScore}/100`);
    }
  }

  /**
   * Implement defensive reputation maintenance
   */
  async defensiveMaintenance(userAddress: string): Promise<void> {
    console.log('🛡️ Starting defensive reputation maintenance...');
    
    // Monitor reputation score daily
    const monitoringInterval = setInterval(async () => {
      const currentScore = await this.sdk.reputation.getReputationScore(userAddress);
      
      if (currentScore < 50) {
        console.warn('⚠️ Reputation score dropped below 50, initiating recovery...');
        await this.initiateRecoveryProtocol(userAddress);
      }
    }, 24 * 60 * 60 * 1000); // Daily check

    return monitoringInterval;
  }

  /**
   * Recovery protocol for declining reputation
   */
  private async initiateRecoveryProtocol(userAddress: string): Promise<void> {
    console.log('🔄 Initiating reputation recovery protocol...');
    
    // Boost with high-value successful transactions
    for (let i = 0; i < 5; i++) {
      await this.sdk.reputation.updateTransactionReputation(
        userAddress,
        true,
        2000 // High value transactions
      );
    }

    // Add verification credentials
    const recoveryCredentials = ['IdentityVerification', 'EmailVerification', 'PhoneVerification'];
    for (const credType of recoveryCredentials) {
      await this.sdk.reputation.updateCredentialReputation(
        userAddress,
        true,
        credType
      );
    }
  }

  /**
   * Reputation optimization algorithm
   */
  async optimizeReputation(userAddress: string): Promise<any> {
    const analysis = await this.sdk.reputation.getReputationAnalysis(userAddress);
    const factors = analysis.factors;
    
    // Identify weak areas
    const weakAreas = Object.entries(factors)
      .filter(([_, count]) => count < 3)
      .map(([factor, _]) => factor);

    // Suggest improvements
    const suggestions = {
      weakAreas,
      recommendations: weakAreas.map(area => {
        switch (area) {
          case 'KYCVerification':
            return 'Complete KYC verification for significant reputation boost';
          case 'ProfessionalLicense':
            return 'Add professional licenses to establish expertise';
          case 'EducationCredential':
            return 'Verify educational credentials for credibility';
          default:
            return `Increase ${area} activities`;
        }
      }),
      potentialScoreIncrease: weakAreas.length * 5 // Estimate
    };

    return suggestions;
  }
}

// Run example
if (require.main === module) {
  main()
    .then((result) => {
      console.log('\n✨ Reputation building completed successfully!');
      console.log('\n📝 Results:', JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Reputation building failed:', error);
      process.exit(1);
    });
}

export { main as reputationBuilderExample };
