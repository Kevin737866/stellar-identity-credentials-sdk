/**
 * Loan Application Example
 * 
 * This example demonstrates how a lending institution can verify loan eligibility
 * criteria (credit score, income, employment) without revealing the applicant's
 * complete financial information using zero-knowledge proofs.
 */

import { 
  StellarIdentitySDK, 
  ZKProofsClient,
  StellarIdentityConfig,
  Keypair 
} from '../sdk/src';

// Configuration for the Stellar Identity network
const config: StellarIdentityConfig = {
  network: 'testnet',
  contracts: {
    didRegistry: 'GD...',
    credentialIssuer: 'GD...',
    reputationScore: 'GD...',
    zkAttestation: 'GD...',
    complianceFilter: 'GD...'
  },
  rpcUrl: 'https://soroban-testnet.stellar.org'
};

// Initialize SDK
const sdk = new StellarIdentitySDK(config);
const zkClient = new ZKProofsClient(config);

/**
 * Loan Applicant class
 */
class LoanApplicant {
  private keypair: Keypair;
  private profile: {
    income: number;
    creditScore: number;
    employmentMonths: number;
    debtAmount: number;
    residenceProof: string;
    residenceMerkleProof: string[][];
    residenceIndex: number;
    residenceMerkleRoot: string;
  };

  constructor(profile: any) {
    this.keypair = Keypair.random();
    this.profile = profile;
  }

  /**
   * Generate comprehensive loan application proof
   */
  async generateLoanApplicationProof(loanAmount: number, loanPurpose: string): Promise<string> {
    console.log(`🏦 Applicant: Generating loan proof for $${loanAmount} (${loanPurpose})`);

    try {
      const application = {
        applicantId: this.keypair.publicKey(),
        income: this.profile.income,
        creditScore: this.profile.creditScore,
        employmentMonths: this.profile.employmentMonths,
        debtAmount: this.profile.debtAmount,
        residenceProof: this.profile.residenceProof,
        residenceMerkleProof: this.profile.residenceMerkleProof,
        residenceIndex: this.profile.residenceIndex,
        residenceMerkleRoot: this.profile.residenceMerkleRoot,
        loanAmount,
        minIncome: loanAmount * 0.4, // 40% of loan amount as minimum income
        minCreditScore: 650,
        maxDebtToIncome: 45, // 45% max debt-to-income ratio
        minEmploymentMonths: 6, // 6 months minimum employment
      };

      const proofId = await zkClient.createLoanApplicationProof(application, {
        context: `loan_application_${loanPurpose}`,
        expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // Valid for 7 days
      });

      console.log(`✅ Loan application proof generated: ${proofId}`);
      return proofId;
    } catch (error) {
      console.error('❌ Failed to generate loan proof:', error.message);
      throw error;
    }
  }

  /**
   * Generate individual component proofs for partial verification
   */
  async generateComponentProofs(): Promise<{ income: string; credit: string; employment: string }> {
    console.log('🔍 Generating component proofs...');

    try {
      const incomeProof = await zkClient.createIncomeProof(
        this.profile.income,
        50000, // Minimum income requirement
        { context: 'loan_income_verification' }
      );

      // Note: Credit score and employment proofs would be similar
      // For brevity, we're showing just the income proof generation
      return {
        income: incomeProof,
        credit: 'credit_proof_id',
        employment: 'employment_proof_id'
      };
    } catch (error) {
      console.error('❌ Failed to generate component proofs:', error.message);
      throw error;
    }
  }

  getAddress(): string {
    return this.keypair.publicKey();
  }

  getProfile() {
    return {
      ...this.profile,
      address: this.getAddress()
    };
  }
}

/**
 * Lending Institution class
 */
class LendingInstitution {
  private name: string;
  private loanCriteria: {
    minCreditScore: number;
    maxDebtToIncome: number;
    minEmploymentMonths: number;
    minIncomeMultiplier: number;
  };
  private processedApplications: Map<string, any> = new Map();

  constructor(name: string, criteria: any) {
    this.name = name;
    this.loanCriteria = criteria;
  }

  /**
   * Process loan application with ZK proof verification
   */
  async processLoanApplication(
    proofId: string, 
    applicantAddress: string, 
    loanAmount: number, 
    loanPurpose: string
  ): Promise<{ approved: boolean; reason?: string; terms?: any }> {
    console.log(`🏦 ${this.name}: Processing loan application for $${loanAmount}`);

    try {
      // Verify the comprehensive loan proof
      const verification = await zkClient.verifyProofOnChain(proofId, []);
      
      if (!verification.valid) {
        return { approved: false, reason: 'Invalid proof verification' };
      }

      // Get proof details for decision making
      const proof = await zkClient.getProof(proofId);
      const metadata = proof.metadata;

      // Check if application was already processed
      if (this.processedApplications.has(proofId)) {
        return { approved: false, reason: 'Duplicate application' };
      }

      // Simulate loan decision based on verified criteria
      const decision = this.makeLoanDecision(loanAmount, loanPurpose, metadata);
      
      // Store application record
      this.processedApplications.set(proofId, {
        applicantAddress: applicantAddress.substring(0, 8) + '...',
        loanAmount,
        loanPurpose,
        decision: decision.approved ? 'APPROVED' : 'REJECTED',
        reason: decision.reason,
        processedAt: new Date().toISOString(),
        proofId
      });

      if (decision.approved) {
        console.log(`✅ Loan approved! Terms:`, decision.terms);
        return decision;
      } else {
        console.log(`❌ Loan denied: ${decision.reason}`);
        return { approved: false, reason: decision.reason };
      }
    } catch (error) {
      console.error('❌ Error processing application:', error.message);
      return { approved: false, reason: 'Processing error' };
    }
  }

  /**
   * Make loan decision based on verified criteria
   */
  private makeLoanDecision(loanAmount: number, loanPurpose: string, metadata: any): any {
    // In a real implementation, this would analyze the verified proof data
    // For demo purposes, we'll simulate decision logic
    
    const baseInterestRate = 5.5; // Base rate in percent
    let riskAdjustment = 0;
    let approved = true;
    let reason = '';

    // Simulate risk assessment based on loan purpose and amount
    if (loanPurpose === 'business') {
      riskAdjustment += 1.0;
    } else if (loanPurpose === 'personal') {
      riskAdjustment += 0.5;
    }

    if (loanAmount > 100000) {
      riskAdjustment += 0.5;
    }

    const finalRate = baseInterestRate + riskAdjustment;
    const monthlyPayment = this.calculateMonthlyPayment(loanAmount, finalRate, 360); // 30-year term

    // Simulate approval criteria
    if (loanAmount > 500000) {
      approved = false;
      reason = 'Loan amount exceeds maximum limit';
    } else if (loanPurpose === 'crypto') {
      approved = false;
      reason = 'High-risk loan purpose not supported';
    }

    if (approved) {
      return {
        approved: true,
        terms: {
          loanAmount,
          interestRate: finalRate,
          monthlyPayment,
          term: 360, // 30 years
          apr: finalRate + 0.25, // Include fees
          closingCosts: loanAmount * 0.03, // 3% closing costs
        }
      };
    } else {
      return { approved: false, reason };
    }
  }

  private calculateMonthlyPayment(principal: number, annualRate: number, months: number): number {
    const monthlyRate = annualRate / 100 / 12;
    const payment = principal * (monthlyRate * Math.pow(1 + monthlyRate, months)) / 
                   (Math.pow(1 + monthlyRate, months) - 1);
    return Math.round(payment * 100) / 100;
  }

  /**
   * Get lending statistics
   */
  getLendingStats() {
    const applications = Array.from(this.processedApplications.values());
    const approved = applications.filter(app => app.decision === 'APPROVED');
    const rejected = applications.filter(app => app.decision === 'REJECTED');

    return {
      institution: this.name,
      totalApplications: applications.length,
      approvedCount: approved.length,
      rejectedCount: rejected.length,
      approvalRate: applications.length > 0 ? (approved.length / applications.length * 100).toFixed(2) + '%' : '0%',
      totalLoanAmount: approved.reduce((sum, app) => sum + app.loanAmount, 0),
      criteria: this.loanCriteria
    };
  }

  /**
   * Export compliance report
   */
  generateComplianceReport(): any {
    const applications = Array.from(this.processedApplications.values());
    
    return {
      reportDate: new Date().toISOString(),
      institution: this.name,
      totalApplications: applications.length,
      approvalsByPurpose: this.groupBy(applications.filter(app => app.decision === 'APPROVED'), 'loanPurpose'),
      rejectionsByReason: this.groupBy(applications.filter(app => app.decision === 'REJECTED'), 'reason'),
      averageLoanSize: applications.length > 0 ? 
        applications.reduce((sum, app) => sum + app.loanAmount, 0) / applications.length : 0,
      privacyNote: 'All applicant data verified through zero-knowledge proofs - no sensitive financial data stored'
    };
  }

  private groupBy(items: any[], key: string): any {
    return items.reduce((groups, item) => {
      const group = item[key] || 'other';
      groups[group] = (groups[group] || 0) + 1;
      return groups;
    }, {});
  }
}

/**
 * Credit Bureau - provides credit scoring services
 */
class CreditBureau {
  private scores: Map<string, number> = new Map();

  constructor() {
    // Initialize some sample credit scores
    this.scores.set('high_credit', 750);
    this.scores.set('medium_credit', 680);
    this.scores.set('low_credit', 620);
  }

  getCreditScore(address: string): number {
    // In reality, this would involve secure data retrieval
    // For demo, return a sample score
    const scores = [750, 680, 720, 650, 690, 710];
    return scores[Math.floor(Math.random() * scores.length)];
  }

  generateCreditProof(address: string, minScore: number): string {
    console.log(`🏛️ Credit Bureau: Generating credit score proof for address ${address.substring(0, 8)}...`);
    return `credit_proof_${Date.now()}`;
  }
}

/**
 * Main demonstration function
 */
async function demonstrateLoanApplication() {
  console.log('💰 Loan Application Demo');
  console.log('========================\n');

  // Create participants
  const goodApplicant = new LoanApplicant({
    income: 85000,
    creditScore: 750,
    employmentMonths: 24,
    debtAmount: 15000,
    residenceProof: 'residence_hash_123',
    residenceMerkleProof: [['hash1', 'hash2'], ['hash3', 'hash4']],
    residenceIndex: 5,
    residenceMerkleRoot: 'merkle_root_hash'
  });

  const riskyApplicant = new LoanApplicant({
    income: 35000,
    creditScore: 620,
    employmentMonths: 3,
    debtAmount: 25000,
    residenceProof: 'residence_hash_456',
    residenceMerkleProof: [['hash5', 'hash6'], ['hash7', 'hash8']],
    residenceIndex: 12,
    residenceMerkleRoot: 'merkle_root_hash'
  });

  const lender = new LendingInstitution('Stellar Bank', {
    minCreditScore: 650,
    maxDebtToIncome: 45,
    minEmploymentMonths: 6,
    minIncomeMultiplier: 0.4
  });

  const creditBureau = new CreditBureau();

  console.log('👤 Applicants:');
  console.log(`- Good Applicant: Income $${goodApplicant.getProfile().income}, Credit ${goodApplicant.getProfile().creditScore}`);
  console.log(`- Risky Applicant: Income $${riskyApplicant.getProfile().income}, Credit ${riskyApplicant.getProfile().creditScore}`);
  console.log(`🏦 Lender: ${lender.name}\n`);

  // Scenario 1: Good applicant applies for business loan
  console.log('--- Scenario 1: Good Applicant - Business Loan ---');
  try {
    const proofId = await goodApplicant.generateLoanApplicationProof(250000, 'business');
    const result = await lender.processLoanApplication(proofId, goodApplicant.getAddress(), 250000, 'business');
    
    if (result.approved) {
      console.log(`🎉 Business loan approved! Monthly payment: $${result.terms.monthlyPayment}\n`);
    }
  } catch (error) {
    console.log('❌ Business loan application failed\n');
  }

  // Scenario 2: Risky applicant applies for personal loan
  console.log('--- Scenario 2: Risky Applicant - Personal Loan ---');
  try {
    const proofId = await riskyApplicant.generateLoanApplicationProof(50000, 'personal');
    const result = await lender.processLoanApplication(proofId, riskyApplicant.getAddress(), 50000, 'personal');
    
    if (!result.approved) {
      console.log(`🚫 Personal loan denied: ${result.reason}\n`);
    }
  } catch (error) {
    console.log('❌ Personal loan application failed\n');
  }

  // Scenario 3: Component proof verification
  console.log('--- Scenario 3: Component Proof Verification ---');
  try {
    const componentProofs = await goodApplicant.generateComponentProofs();
    console.log('✅ Component proofs generated for selective verification');
    console.log(`- Income proof: ${componentProofs.income}`);
    console.log(`- Credit proof: ${componentProofs.credit}`);
    console.log(`- Employment proof: ${componentProofs.employment}\n`);
  } catch (error) {
    console.log('❌ Component proof generation failed\n');
  }

  // Generate lending statistics
  console.log('--- Lending Statistics ---');
  const stats = lender.getLendingStats();
  console.log(JSON.stringify(stats, null, 2));

  // Generate compliance report
  console.log('\n--- Compliance Report ---');
  const report = lender.generateComplianceReport();
  console.log(JSON.stringify(report, null, 2));

  console.log('\n✨ Demo completed successfully!');
  console.log('\n🔒 Privacy Benefits:');
  console.log('- Applicant income, credit score, and employment verified without revealing exact values');
  console.log('- Lender makes informed decisions without storing sensitive financial data');
  console.log('- Regulatory compliance through auditable zero-knowledge proofs');
  console.log('- Reduced discrimination through objective, privacy-preserving verification');
}

/**
 * Performance benchmark for loan application proofs
 */
async function benchmarkLoanProofs() {
  console.log('\n⚡ Loan Proof Performance Benchmark');
  console.log('===================================');

  const applicant = new LoanApplicant({
    income: 75000,
    creditScore: 700,
    employmentMonths: 12,
    debtAmount: 20000,
    residenceProof: 'test_proof',
    residenceMerkleProof: [],
    residenceIndex: 0,
    residenceMerkleRoot: 'test_root'
  });

  const iterations = 5;
  const times: number[] = [];

  console.log(`Running ${iterations} loan application proof generations...`);

  for (let i = 0; i < iterations; i++) {
    const startTime = Date.now();
    
    try {
      await applicant.generateLoanApplicationProof(100000, 'benchmark');
      const endTime = Date.now();
      const duration = endTime - startTime;
      times.push(duration);
      
      console.log(`Iteration ${i + 1}: ${duration}ms`);
    } catch (error) {
      console.log(`Iteration ${i + 1}: Failed - ${error.message}`);
    }
  }

  if (times.length > 0) {
    const avgTime = times.reduce((a, b) => a + b, 0) / times.length;
    const minTime = Math.min(...times);
    const maxTime = Math.max(...times);

    console.log('\n📊 Results:');
    console.log(`Average: ${avgTime.toFixed(2)}ms`);
    console.log(`Min: ${minTime}ms`);
    console.log(`Max: ${maxTime}ms`);
    console.log(`Target: <5000ms ✅ ${avgTime < 5000 ? 'PASSED' : 'FAILED'}`);
  }
}

// Run the demonstration
if (require.main === module) {
  demonstrateLoanApplication()
    .then(() => benchmarkLoanProofs())
    .catch(console.error);
}

export { LoanApplicant, LendingInstitution, CreditBureau };
