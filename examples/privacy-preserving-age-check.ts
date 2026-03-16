/**
 * Privacy-preserving age verification using zero-knowledge proofs
 * This example demonstrates how to prove age > 18 without revealing birthdate
 */

import { 
  StellarIdentitySDK, 
  DEFAULT_CONFIGS,
  UTILS 
} from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';

interface AgeVerificationRequest {
  verifierAddress: string;
  minimumAge: number;
  purpose: string;
  challenge: string;
}

interface AgeProofResult {
  proofId: string;
  valid: boolean;
  minimumAge: number;
  verifiedAt: number;
  expiresAt?: number;
  verifierCommitment: string;
}

async function main() {
  console.log('🔒 Starting Privacy-Preserving Age Check Example...\n');

  // Initialize SDK for testnet
  const sdk = new StellarIdentitySDK(DEFAULT_CONFIGS.testnet);

  // Generate keypairs for participants
  const userKeypair = UTILS.generateKeypair(); // User proving age
  const verifierKeypair = UTILS.generateKeypair(); // Service requiring age verification
  const issuerKeypair = UTILS.generateKeypair(); // Trusted age credential issuer

  console.log('👥 Participants:');
  console.log(`User: ${userKeypair.publicKey()}`);
  console.log(`Verifier: ${verifierKeypair.publicKey()}`);
  console.log(`Trusted Issuer: ${issuerKeypair.publicKey()}\n`);

  try {
    // Step 1: User obtains age credential from trusted issuer
    console.log('📋 Step 1: User Obtains Age Credential...');
    const userAge = 25; // User's actual age (private)
    const credentialData = {
      ageVerified: true,
      verificationMethod: 'Government ID',
      verificationDate: new Date().toISOString(),
      issuer: issuerKeypair.publicKey(),
      ageCommitment: sdk.zkProofs.generateCommitment(userAge.toString(), 'user_salt_secret')
    };

    const ageCredentialId = await sdk.credentials.issueCredential(
      issuerKeypair,
      {
        subject: userKeypair.publicKey(),
        credentialType: ['AgeVerification', 'VerifiableCredential'],
        credentialData,
        expirationDate: Date.now() + (5 * 365 * 24 * 60 * 60 * 1000), // 5 years
        proof: await generateAgeProof(credentialData, issuerKeypair)
      }
    );
    console.log(`✅ Age credential issued: ${ageCredentialId}\n`);

    // Step 2: User receives age verification request
    console.log('🔍 Step 2: Age Verification Request Received...');
    const ageRequest: AgeVerificationRequest = {
      verifierAddress: verifierKeypair.publicKey(),
      minimumAge: 18,
      purpose: 'Access to age-restricted content',
      challenge: 'age_check_' + Date.now()
    };
    console.log(`   Verifier: ${ageRequest.verifierAddress}`);
    console.log(`   Minimum Age Required: ${ageRequest.minimumAge}`);
    console.log(`   Purpose: ${ageRequest.purpose}\n`);

    // Step 3: User creates zero-knowledge proof of age
    console.log('🔐 Step 3: Creating Zero-Knowledge Age Proof...');
    const ageProof = await createAgeProof(sdk, userKeypair, userAge, ageRequest);
    console.log(`✅ ZK Age proof created: ${ageProof.proofId}`);
    console.log(`   Verifier can verify user is ≥${ageRequest.minimumAge} without knowing actual age\n`);

    // Step 4: Verifier validates the age proof
    console.log('🛡️ Step 4: Verifier Validates Age Proof...');
    const verification = await verifyAgeProof(sdk, verifierKeypair, ageProof, ageRequest);
    console.log(`✅ Age verification result: ${verification.valid ? 'VALID' : 'INVALID'}`);
    console.log(`   Minimum age verified: ${verification.minimumAge}`);
    console.log(`   Verified at: ${new Date(verification.verifiedAt).toLocaleString()}\n`);

    // Step 5: Create selective disclosure for different age thresholds
    console.log('🎭 Step 5: Selective Disclosure for Different Services...');
    const scenarios = await demonstrateSelectiveDisclosure(sdk, userKeypair, userAge);
    
    scenarios.forEach((scenario, index) => {
      console.log(`   Scenario ${index + 1}: ${scenario.service}`);
      console.log(`     Required Age: ${scenario.requiredAge}`);
      console.log(`     Proof Valid: ${scenario.valid}`);
      console.log(`     Privacy Preserved: ${scenario.privacyPreserved ? '✅' : '❌'}`);
    });

    // Step 6: Demonstrate proof revocation and renewal
    console.log('\n🔄 Step 6: Proof Revocation and Renewal...');
    await demonstrateProofRevocation(sdk, userKeypair, ageProof.proofId);

    // Step 7: Advanced privacy features
    console.log('\n🔬 Step 7: Advanced Privacy Features...');
    await demonstrateAdvancedPrivacy(sdk, userKeypair, userAge, verifierKeypair.publicKey());

    // Step 8: Compliance and audit trail
    console.log('\n📊 Step 8: Compliance and Audit Trail...');
    const auditTrail = await generateAuditTrail(sdk, ageProof.proofId);
    console.log('📋 Audit Trail Generated:');
    console.log(JSON.stringify(auditTrail, null, 2));

    return {
      userAddress: userKeypair.publicKey(),
      verifierAddress: verifierKeypair.publicKey(),
      ageCredentialId,
      ageProofId: ageProof.proofId,
      verificationResult: verification.valid,
      scenarios
    };

  } catch (error) {
    console.error('❌ Privacy-Preserving Age Check Failed:', error);
    throw error;
  }
}

/**
 * Create zero-knowledge proof for age verification
 */
async function createAgeProof(
  sdk: StellarIdentitySDK,
  userKeypair: Keypair,
  userAge: number,
  request: AgeVerificationRequest
): Promise<AgeProofResult> {
  // Generate commitment to user's age (this would be done by a ZK circuit in practice)
  const ageCommitment = sdk.zkProofs.generateCommitment(userAge.toString(), 'user_salt_secret');
  
  // Create range proof proving age >= minimumAge
  const proofId = await sdk.zkProofs.createRangeProof(
    'age_range_verification',
    ageCommitment,
    request.minimumAge,
    120, // Maximum reasonable age
    'mock_range_proof_bytes' // In reality, generated by ZK circuit
  );

  return {
    proofId,
    valid: false, // Will be set after verification
    minimumAge: request.minimumAge,
    verifiedAt: Date.now(),
    verifierCommitment: sdk.zkProofs.generateCommitment(request.challenge, 'verifier_salt')
  };
}

/**
 * Verify age proof without learning actual age
 */
async function verifyAgeProof(
  sdk: StellarIdentitySDK,
  verifierKeypair: Keypair,
  ageProof: AgeProofResult,
  request: AgeVerificationRequest
): Promise<AgeProofResult> {
  // Verify the zero-knowledge proof
  const isValid = await sdk.zkProofs.verifyProof(ageProof.proofId);
  
  // Additional verifier-side checks
  const verifierCommitmentValid = sdk.zkProofs.generateCommitment(
    request.challenge, 
    'verifier_salt'
  ) === ageProof.verifierCommitment;

  return {
    ...ageProof,
    valid: isValid && verifierCommitmentValid,
    verifiedAt: Date.now()
  };
}

/**
 * Demonstrate selective disclosure for different age-restricted services
 */
async function demonstrateSelectiveDisclosure(
  sdk: StellarIdentitySDK,
  userKeypair: Keypair,
  userAge: number
): Promise<Array<{service: string, requiredAge: number, valid: boolean, privacyPreserved: boolean}>> {
  const services = [
    { name: 'Social Media', requiredAge: 13 },
    { name: 'Online Gaming', requiredAge: 16 },
    { name: 'Alcohol Purchase', requiredAge: 21 },
    { name: 'Car Rental', requiredAge: 25 },
    { name: 'Senior Discount', requiredAge: 65 }
  ];

  const results = [];

  for (const service of services) {
    try {
      const proof = await createAgeProof(sdk, userKeypair, userAge, {
        verifierAddress: 'service-provider.example.com',
        minimumAge: service.requiredAge,
        purpose: `Access to ${service.name}`,
        challenge: `service_${service.name}_${Date.now()}`
      });

      const verification = await verifyAgeProof(sdk, userKeypair, proof, {
        verifierAddress: 'service-provider.example.com',
        minimumAge: service.requiredAge,
        purpose: `Access to ${service.name}`,
        challenge: `service_${service.name}_${Date.now()}`
      });

      results.push({
        service: service.name,
        requiredAge: service.requiredAge,
        valid: verification.valid,
        privacyPreserved: true // Actual age never revealed
      });
    } catch (error) {
      results.push({
        service: service.name,
        requiredAge: service.requiredAge,
        valid: false,
        privacyPreserved: true
      });
    }
  }

  return results;
}

/**
 * Demonstrate proof revocation and renewal
 */
async function demonstrateProofRevocation(
  sdk: StellarIdentitySDK,
  userKeypair: Keypair,
  proofId: string
): Promise<void> {
  console.log('   Creating time-limited proof...');
  
  // Create proof with expiration
  const timeLimitedProofId = await sdk.zkProofs.submitProof({
    circuitId: 'age_verification',
    publicInputs: ['age_commitment', '18'],
    proofBytes: 'mock_time_limited_proof',
    expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour expiration
    metadata: { type: 'time_limited_age_proof' }
  });

  console.log(`   Time-limited proof created: ${timeLimitedProofId}`);
  console.log('   Proof will automatically expire in 1 hour');
}

/**
 * Demonstrate advanced privacy features
 */
async function demonstrateAdvancedPrivacy(
  sdk: StellarIdentitySDK,
  userKeypair: Keypair,
  userAge: number,
  verifierAddress: string
): Promise<void> {
  console.log('   🔹 Anonymous age verification (no user identification)');
  
  // Anonymous proof - doesn't reveal user address
  const anonymousProof = await sdk.zkProofs.submitProof({
    circuitId: 'anonymous_age_verification',
    publicInputs: ['age_commitment', '18'],
    proofBytes: 'mock_anonymous_proof',
    metadata: { 
      type: 'anonymous_verification',
      verifier: verifierAddress
    }
  });
  
  console.log(`   Anonymous proof created: ${anonymousProof}`);

  console.log('   🔹 Batch verification for multiple age checks');
  
  // Batch multiple age threshold proofs
  const batchProofs = await Promise.all([
    sdk.zkProofs.createAgeProof('batch_age_verification', 'age_commitment', 13, 'mock_proof_13'),
    sdk.zkProofs.createAgeProof('batch_age_verification', 'age_commitment', 18, 'mock_proof_18'),
    sdk.zkProofs.createAgeProof('batch_age_verification', 'age_commitment', 21, 'mock_proof_21')
  ]);
  
  const batchVerification = await sdk.zkProofs.batchVerifyProofs(batchProofs);
  console.log(`   Batch verification results: ${batchVerification.map(v => v.valid ? '✅' : '❌').join(', ')}`);

  console.log('   🔹 Revocable age proofs');
  
  // Create revocable proof
  const revocableProof = await sdk.zkProofs.submitProof({
    circuitId: 'revocable_age_verification',
    publicInputs: ['age_commitment', '18'],
    proofBytes: 'mock_revocable_proof',
    metadata: { 
      type: 'revocable_verification',
      revocationKey: 'user_revocation_key'
    }
  });
  
  console.log(`   Revocable proof created: ${revocableProof}`);
  console.log('   User can revoke this proof at any time');
}

/**
 * Generate audit trail for compliance
 */
async function generateAuditTrail(sdk: StellarIdentitySDK, proofId: string): Promise<any> {
  const proof = await sdk.zkProofs.getProof(proofId);
  const verification = await sdk.zkProofs.verifyProof(proofId);
  
  return {
    proofId,
    circuitId: proof.circuitId,
    createdAt: proof.createdAt,
    verifiedAt: verification.verifiedAt,
    expiresAt: proof.expiresAt,
    verificationResult: verification.valid,
    privacyLevel: 'ZERO_KNOWLEDGE',
    dataRevealed: ['age_threshold_met'], // Only what was proven
    dataConcealed: ['actual_age', 'birthdate', 'personal_identifiers'],
    complianceChecks: {
      gdprCompliant: true,
      dataMinimization: true,
      purposeLimitation: true,
      userConsent: true
    },
    auditHash: sdk.zkProofs.generateCommitment(
      JSON.stringify({ proofId, verifiedAt: verification.verifiedAt }),
      'audit_salt'
    )
  };
}

/**
 * Generate simple proof for age credential
 */
async function generateAgeProof(credentialData: any, issuerKeypair: Keypair): Promise<string> {
  const message = JSON.stringify(credentialData);
  return issuerKeypair.sign(Buffer.from(message)).toString('hex');
}

/**
 * Advanced age verification scenarios
 */
export class AgeVerificationSystem {
  private sdk: StellarIdentitySDK;

  constructor(sdk: StellarIdentitySDK) {
    this.sdk = sdk;
  }

  /**
   * Progressive age verification (gradually reveal age ranges)
   */
  async progressiveAgeVerification(
    userKeypair: Keypair,
    userAge: number,
    verifierAddress: string
  ): Promise<any> {
    const ageRanges = [
      { min: 0, max: 12, label: 'Child' },
      { min: 13, max: 17, label: 'Teenager' },
      { min: 18, max: 24, label: 'Young Adult' },
      { min: 25, max: 64, label: 'Adult' },
      { min: 65, max: 120, label: 'Senior' }
    ];

    const userRange = ageRanges.find(range => userAge >= range.min && userAge <= range.max);
    
    if (!userRange) {
      throw new Error('Invalid age');
    }

    // Create proof that age is within the range without revealing exact age
    const rangeProof = await this.sdk.zkProofs.createRangeProof(
      'age_range_verification',
      this.sdk.zkProofs.generateCommitment(userAge.toString()),
      userRange.min,
      userRange.max,
      'mock_range_proof'
    );

    return {
      ageRange: userRange.label,
      proofId: rangeProof,
      privacyLevel: 'AGE_RANGE_ONLY'
    };
  }

  /**
   * Time-bound age verification
   */
  async timeBoundAgeVerification(
    userKeypair: Keypair,
    userAge: number,
    minimumAge: number,
    validForMinutes: number
  ): Promise<any> {
    const expiresAt = Date.now() + (validForMinutes * 60 * 1000);
    
    const timeBoundProof = await this.sdk.zkProofs.submitProof({
      circuitId: 'time_bound_age_verification',
      publicInputs: ['age_commitment', minimumAge.toString()],
      proofBytes: 'mock_time_bound_proof',
      expiresAt,
      metadata: {
        type: 'time_bound_verification',
        validForMinutes,
        minimumAge
      }
    });

    return {
      proofId: timeBoundProof,
      expiresAt,
      validForMinutes,
      minimumAge
    };
  }

  /**
   * Multi-factor age verification
   */
  async multiFactorAgeVerification(
    userKeypair: Keypair,
    userAge: number,
    factors: Array<'document' | 'biometric' | 'government_database'>
  ): Promise<any> {
    const factorProofs = [];

    for (const factor of factors) {
      const factorProof = await this.sdk.zkProofs.submitProof({
        circuitId: `${factor}_age_verification`,
        publicInputs: ['age_commitment', '18'],
        proofBytes: `mock_${factor}_proof`,
        metadata: {
          type: 'multi_factor_verification',
          factor,
          verificationMethod: factor
        }
      });
      factorProofs.push(factorProof);
    }

    return {
      factorProofs,
      factorsVerified: factors,
      confidenceLevel: factors.length === 3 ? 'HIGH' : factors.length === 2 ? 'MEDIUM' : 'LOW'
    };
  }
}

// Run example
if (require.main === module) {
  main()
    .then((result) => {
      console.log('\n✨ Privacy-preserving age check completed successfully!');
      console.log('\n📝 Results:', JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n💥 Privacy-preserving age check failed:', error);
      process.exit(1);
    });
}

export { main as privacyPreservingAgeCheckExample };
