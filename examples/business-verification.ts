/**
 * Corporate credential issuance and verification for businesses
 * This example demonstrates B2B identity verification and credential management
 */

import { 
  StellarIdentitySDK, 
  DEFAULT_CONFIGS,
  UTILS 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

interface BusinessEntity {
  name: string;
  registrationNumber: string;
  jurisdiction: string;
  incorporationDate: string;
  businessType: string;
  address: string;
  directors: string[];
  authorizedSignatories: string[];
}

interface CorporateCredential {
  type: string;
  issuer: string;
  subject: string;
  businessData: BusinessEntity;
  issuanceDate: number;
  expirationDate?: number;
  verificationLevel: 'Basic' | 'Standard' | 'Enhanced';
}

interface VerificationRequest {
  requesterAddress: string;
  businessAddress: string;
  requiredCredentials: string[];
  purpose: string;
  verificationLevel: string;
}

async function main() {
  console.log('🏢 Starting Business Verification Example...\n');

  // Initialize SDK for testnet
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // Generate keypairs for participants
  const businessKeypair = UTILS.generateKeypair(); // Business entity
  const regulatorKeypair = UTILS.generateKeypair(); // Government regulator
  const bankKeypair = UTILS.generateKeypair(); // Verifying bank
  const auditorKeypair = UTILS.generateKeypair(); // Independent auditor

  console.log('🏛️ Participants:');
  console.log(`Business: ${businessKeypair.publicKey()}`);
  console.log(`Regulator: ${regulatorKeypair.publicKey()}`);
  console.log(`Bank: ${bankKeypair.publicKey()}`);
  console.log(`Auditor: ${auditorKeypair.publicKey()}\n`);

  try {
    // Step 1: Business creates corporate DID
    console.log('🆔 Step 1: Business Creates Corporate DID...');
    const businessDID = await sdk.did.createDID(businessKeypair, {
      verificationMethods: [
        {
          id: '#corporate-key-1',
          type: 'Ed25519VerificationKey2018',
          controller: businessKeypair.publicKey(),
          publicKey: businessKeypair.publicKey()
        },
        {
          id: '#authorized-signatory-1',
          type: 'Ed25519VerificationKey2018',
          controller: businessKeypair.publicKey(),
          publicKey: businessKeypair.publicKey()
        }
      ],
      services: [
        {
          id: '#corporate-registry',
          type: 'CorporateRegistry',
          endpoint: 'https://business-registry.example.com'
        },
        {
          id: '#verification-service',
          type: 'VerificationService',
          endpoint: 'https://verify.example.com'
        }
      ]
    });
    console.log(`✅ Corporate DID created: ${businessDID}\n`);

    // Step 2: Define business entity
    console.log('📋 Step 2: Defining Business Entity...');
    const businessEntity: BusinessEntity = {
      name: 'TechCorp Solutions Inc.',
      registrationNumber: 'BC123456789',
      jurisdiction: 'Delaware, USA',
      incorporationDate: '2020-01-15',
      businessType: 'Technology Services',
      address: '123 Business Ave, Wilmington, DE 19801',
      directors: ['Director One', 'Director Two'],
      authorizedSignatories: ['CEO Signature', 'CFO Signature']
    };
    console.log(`   Business: ${businessEntity.name}`);
    console.log(`   Registration: ${businessEntity.registrationNumber}`);
    console.log(`   Jurisdiction: ${businessEntity.jurisdiction}\n`);

    // Step 3: Regulator issues business registration credential
    console.log('🏛️ Step 3: Regulator Issues Business Registration...');
    const registrationCredential = await issueBusinessRegistrationCredential(
      sdk,
      regulatorKeypair,
      businessKeypair.publicKey(),
      businessEntity
    );
    console.log(`✅ Registration credential issued: ${registrationCredential}\n`);

    // Step 4: Auditor issues compliance credential
    console.log('🔍 Step 4: Auditor Issues Compliance Credential...');
    const complianceCredential = await issueComplianceCredential(
      sdk,
      auditorKeypair,
      businessKeypair.publicKey(),
      businessEntity
    );
    console.log(`✅ Compliance credential issued: ${complianceCredential}\n`);

    // Step 5: Business builds reputation through transactions
    console.log('📈 Step 5: Building Business Reputation...');
    await buildBusinessReputation(sdk, businessKeypair.publicKey());

    // Step 6: Bank requests business verification
    console.log('🏦 Step 6: Bank Requests Business Verification...');
    const verificationRequest: VerificationRequest = {
      requesterAddress: bankKeypair.publicKey(),
      businessAddress: businessKeypair.publicKey(),
      requiredCredentials: ['BusinessRegistration', 'TaxCompliance', 'FinancialAudit'],
      purpose: 'Corporate Account Opening',
      verificationLevel: 'Enhanced'
    };
    console.log(`   Purpose: ${verificationRequest.purpose}`);
    console.log(`   Required Credentials: ${verificationRequest.requiredCredentials.join(', ')}\n`);

    // Step 7: Business creates verifiable presentation
    console.log('🎭 Step 7: Business Creates Verifiable Presentation...');
    const presentation = await createBusinessPresentation(
      sdk,
      businessKeypair,
      verificationRequest
    );
    console.log(`✅ Verifiable presentation created\n`);

    // Step 8: Bank verifies business credentials
    console.log('🔐 Step 8: Bank Verifies Business Credentials...');
    const verificationResult = await verifyBusinessCredentials(
      sdk,
      bankKeypair,
      presentation,
      verificationRequest
    );
    console.log(`✅ Verification Result: ${verificationResult.valid ? 'VALID' : 'INVALID'}`);
    console.log(`   Compliance Score: ${verificationResult.complianceScore}/100`);
    console.log(`   Risk Level: ${verificationResult.riskLevel}\n`);

    // Step 9: Perform compliance check
    console.log('🛡️ Step 9: Compliance Check...');
    const complianceCheck = await sdk.performComplianceCheck(businessKeypair.publicKey());
    console.log(`   Status: ${complianceCheck.status}`);
    console.log(`   Risk Score: ${complianceCheck.riskScore}/100`);
    console.log(`   Sanctions Lists: ${complianceCheck.sanctionsLists.length}\n`);

    // Step 10: Generate business verification report
    console.log('📊 Step 10: Generating Business Verification Report...');
    const report = await generateBusinessVerificationReport(
      sdk,
      businessKeypair.publicKey(),
      verificationResult
    );
    console.log('📋 Business Verification Report:');
    console.log(JSON.stringify(report, null, 2));

    return {
      businessAddress: businessKeypair.publicKey(),
      businessDID,
      registrationCredential,
      complianceCredential,
      verificationResult,
      complianceStatus: complianceCheck.status
    };

  } catch (error) {
    console.error('❌ Business Verification Failed:', error);
    throw error;
  }
}

/**
 * Issue business registration credential
 */
async function issueBusinessRegistrationCredential(
  sdk: StellarIdentitySDK,
  regulatorKeypair: Keypair,
  businessAddress: string,
  businessEntity: BusinessEntity
): Promise<string> {
  const credentialData = {
    businessRegistration: {
      ...businessEntity,
      verifiedBy: regulatorKeypair.publicKey(),
      verificationDate: new Date().toISOString(),
      registrationStatus: 'Active',
      licenseNumber: 'BL' + Math.random().toString(36).substr(2, 9).toUpperCase()
    },
    complianceChecks: {
      nameVerification: 'Passed',
      addressVerification: 'Passed',
      directorVerification: 'Passed',
      criminalBackgroundCheck: 'Clear'
    }
  };

  return await sdk.credentials.issueCredential(
    regulatorKeypair,
    {
      subject: businessAddress,
      credentialType: ['BusinessRegistration', 'VerifiableCredential'],
      credentialData,
      expirationDate: Date.now() + (365 * 24 * 60 * 60 * 1000), // 1 year
      proof: await generateBusinessProof(credentialData, regulatorKeypair)
    }
  );
}

/**
 * Issue compliance credential
 */
async function issueComplianceCredential(
  sdk: StellarIdentitySDK,
  auditorKeypair: Keypair,
  businessAddress: string,
  businessEntity: BusinessEntity
): Promise<string> {
  const credentialData = {
    complianceAudit: {
      auditDate: new Date().toISOString(),
      auditor: auditorKeypair.publicKey(),
      auditType: 'Annual Compliance Review',
      complianceScore: 95,
      findings: [
        'Financial records in order',
        'Regulatory filings up to date',
        'Internal controls adequate'
      ],
      recommendations: [
        'Implement enhanced AML procedures',
        'Regular staff training updates'
      ],
      nextAuditDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()
    },
    certifications: [
      'ISO 27001:2013',
      'SOC 2 Type II',
      'GDPR Compliant'
    ]
  };

  return await sdk.credentials.issueCredential(
    auditorKeypair,
    {
      subject: businessAddress,
      credentialType: ['ComplianceAudit', 'VerifiableCredential'],
      credentialData,
      expirationDate: Date.now() + (365 * 24 * 60 * 60 * 1000), // 1 year
      proof: await generateBusinessProof(credentialData, auditorKeypair)
    }
  );
}

/**
 * Build business reputation through transactions
 */
async function buildBusinessReputation(
  sdk: StellarIdentitySDK,
  businessAddress: string
): Promise<void> {
  // Simulate business transactions
  const businessTransactions = [
    { amount: 10000, successful: true, type: 'supplier_payment' },
    { amount: 25000, successful: true, type: 'client_receipt' },
    { amount: 5000, successful: true, type: 'tax_payment' },
    { amount: 15000, successful: true, type: 'investment_received' },
    { amount: 8000, successful: true, type: 'operational_expense' }
  ];

  for (const tx of businessTransactions) {
    await sdk.reputation.updateTransactionReputation(
      businessAddress,
      tx.successful,
      tx.amount
    );
  }

  // Add credential-based reputation
  await sdk.reputation.updateCredentialReputation(
    businessAddress,
    true,
    'BusinessRegistration'
  );

  await sdk.reputation.updateCredentialReputation(
    businessAddress,
    true,
    'ComplianceAudit'
  );

  const finalScore = await sdk.reputation.getReputationScore(businessAddress);
  console.log(`   Business reputation score: ${finalScore}/100`);
}

/**
 * Create verifiable presentation for business
 */
async function createBusinessPresentation(
  sdk: StellarIdentitySDK,
  businessKeypair: Keypair,
  request: VerificationRequest
): Promise<any> {
  // Get business credentials
  const credentials = await sdk.credentials.getSubjectCredentials(businessKeypair.publicKey());
  
  // Filter credentials based on request
  const relevantCredentials = [];
  for (const credentialId of credentials) {
    const credential = await sdk.credentials.getCredential(credentialId);
    if (request.requiredCredentials.some(req => 
      credential.type.includes(req)
    )) {
      relevantCredentials.push(credential);
    }
  }

  return await sdk.credentials.createPresentation(
    relevantCredentials,
    businessKeypair,
    request.requesterAddress,
    `business_verification_${Date.now()}`
  );
}

/**
 * Verify business credentials
 */
async function verifyBusinessCredentials(
  sdk: StellarIdentitySDK,
  verifierKeypair: Keypair,
  presentation: any,
  request: VerificationRequest
): Promise<any> {
  // Verify presentation
  const isValidPresentation = await sdk.credentials.verifyPresentation(presentation);
  
  if (!isValidPresentation) {
    return { valid: false, reason: 'Invalid presentation' };
  }

  // Verify each credential
  const credentialVerifications = [];
  for (const credential of presentation.verifiableCredential) {
    const verification = await sdk.credentials.verifyCredential(credential.id);
    credentialVerifications.push(verification);
  }

  // Calculate compliance score
  const validCredentials = credentialVerifications.filter(v => v.valid).length;
  const complianceScore = (validCredentials / request.requiredCredentials.length) * 100;

  // Determine risk level
  let riskLevel = 'Low';
  if (complianceScore < 70) riskLevel = 'High';
  else if (complianceScore < 90) riskLevel = 'Medium';

  return {
    valid: isValidPresentation && complianceScore >= 70,
    complianceScore: Math.round(complianceScore),
    riskLevel,
    credentialVerifications,
    verifiedAt: Date.now()
  };
}

/**
 * Generate comprehensive business verification report
 */
async function generateBusinessVerificationReport(
  sdk: StellarIdentitySDK,
  businessAddress: string,
  verificationResult: any
): Promise<any> {
  const reputationData = await sdk.reputation.getReputationAnalysis(businessAddress);
  const complianceCheck = await sdk.performComplianceCheck(businessAddress);
  const credentials = await sdk.credentials.getSubjectCredentials(businessAddress);

  return {
    businessAddress,
    verificationTimestamp: Date.now(),
    verificationResult,
    reputationAnalysis: {
      score: reputationData.score,
      percentile: reputationData.percentile,
      tier: sdk.reputation.getReputationTier(reputationData.score).tier,
      factors: reputationData.factors
    },
    complianceStatus: {
      status: complianceCheck.status,
      riskScore: complianceCheck.riskScore,
      sanctionsLists: complianceCheck.sanctionsLists,
      recommendations: complianceCheck.recommendations
    },
    credentialSummary: {
      totalCredentials: credentials.length,
      validCredentials: verificationResult.credentialVerifications.filter((v: any) => v.valid).length,
      credentialTypes: credentials.map(id => id.split('_')[0])
    },
    overallAssessment: {
      approved: verificationResult.valid && complianceCheck.status === 'cleared',
      riskLevel: verificationResult.riskLevel,
      confidenceLevel: verificationResult.complianceScore > 90 ? 'High' : 
                      verificationResult.complianceScore > 70 ? 'Medium' : 'Low'
    }
  };
}

/**
 * Generate business proof for credential
 */
async function generateBusinessProof(credentialData: any, issuerKeypair: Keypair): Promise<string> {
  const message = JSON.stringify(credentialData);
  return issuerKeypair.sign(Buffer.from(message)).toString('hex');
}

/**
 * Advanced business verification system
 */
export class BusinessVerificationSystem {
  private sdk: StellarIdentitySDK;

  constructor(sdk: StellarIdentitySDK) {
    this.sdk = sdk;
  }

  /**
   * Multi-jurisdictional business verification
   */
  async multiJurisdictionalVerification(
    businessAddress: string,
    jurisdictions: string[]
  ): Promise<any> {
    const jurisdictionVerifications = [];

    for (const jurisdiction of jurisdictions) {
      try {
        const jurisdictionCredential = await this.sdk.credentials.getCredential(
          `${businessAddress}_${jurisdiction}_registration`
        );
        const verification = await this.sdk.credentials.verifyCredential(
          jurisdictionCredential.id
        );
        
        jurisdictionVerifications.push({
          jurisdiction,
          valid: verification.valid,
          credentialId: jurisdictionCredential.id
        });
      } catch (error) {
        jurisdictionVerifications.push({
          jurisdiction,
          valid: false,
          error: 'No credential found'
        });
      }
    }

    return {
      businessAddress,
      jurisdictionVerifications,
      overallValid: jurisdictionVerifications.every(v => v.valid),
      verifiedAt: Date.now()
    };
  }

  /**
   * Continuous monitoring for business compliance
   */
  async continuousComplianceMonitoring(
    businessAddress: string,
    monitoringInterval: number = 24 * 60 * 60 * 1000 // Daily
  ): Promise<void> {
    const monitorCompliance = async () => {
      try {
        const complianceCheck = await this.sdk.performComplianceCheck(businessAddress);
        
        if (complianceCheck.status === 'flagged' || complianceCheck.status === 'blocked') {
          console.warn(`⚠️ Compliance alert for ${businessAddress}: ${complianceCheck.status}`);
          // Trigger alert mechanisms
          await this.triggerComplianceAlert(businessAddress, complianceCheck);
        }
      } catch (error) {
        console.error('Compliance monitoring error:', error);
      }
    };

    // Set up interval monitoring
    setInterval(monitorCompliance, monitoringInterval);
    console.log(`🔍 Started continuous compliance monitoring for ${businessAddress}`);
  }

  /**
   * Trigger compliance alert
   */
  private async triggerComplianceAlert(
    businessAddress: string,
    complianceCheck: any
  ): Promise<void> {
    const alert = {
      businessAddress,
      timestamp: Date.now(),
      status: complianceCheck.status,
      riskScore: complianceCheck.riskScore,
      sanctionsLists: complianceCheck.sanctionsLists,
      recommendations: complianceCheck.recommendations,
      alertLevel: complianceCheck.status === 'blocked' ? 'CRITICAL' : 'WARNING'
    };

    // In a real system, this would send notifications, create tickets, etc.
    console.log('🚨 COMPLIANCE ALERT:', JSON.stringify(alert, null, 2));
  }

  /**
   * Business credential lifecycle management
   */
  async manageCredentialLifecycle(
    businessAddress: string,
    credentialType: string
  ): Promise<any> {
    const credentials = await this.sdk.credentials.getSubjectCredentials(businessAddress);
    const relevantCredentials = credentials.filter(id => id.includes(credentialType));

    const lifecycleInfo = [];
    
    for (const credentialId of relevantCredentials) {
      const credential = await this.sdk.credentials.getCredential(credentialId);
      const verification = await this.sdk.credentials.verifyCredential(credentialId);
      
      lifecycleInfo.push({
        credentialId,
        type: credentialType,
        issuanceDate: credential.issuanceDate,
        expirationDate: credential.expirationDate,
        status: verification.valid ? 'Active' : verification.revoked ? 'Revoked' : 'Expired',
        daysUntilExpiration: credential.expirationDate ? 
          Math.ceil((credential.expirationDate - Date.now()) / (24 * 60 * 60 * 1000)) : 
          null
      });
    }

    return {
      businessAddress,
      credentialType,
      credentials: lifecycleInfo,
      renewalRequired: lifecycleInfo.some(c => c.daysUntilExpiration && c.daysUntilExpiration < 30)
    };
  }
}

// Run example
if (require.main === module) {
  main()
    .then((result) => {
      console.log('\n✨ Business verification completed successfully!');
      console.log('\n📝 Results:', JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Business verification failed:', error);
      process.exit(1);
    });
}

export { main as businessVerificationExample };
