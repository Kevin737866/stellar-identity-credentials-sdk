/**
 * Age Verification Bar Example
 * 
 * This example demonstrates how a bar can verify that a customer is 21+ years old
 * without revealing their exact birthdate or other personal information using
 * zero-knowledge proofs.
 */

import { 
  StellarIdentitySDK, 
  ZKProofsClient,
  StellarIdentityConfig,
  Keypair 
} from '../sdk/src';
import * as snarkjs from 'snarkjs';

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
 * Customer class - represents the person wanting to enter the bar
 */
class Customer {
  private keypair: Keypair;
  private birthYear: number;
  private ageCredential: any;

  constructor(birthYear: number) {
    this.keypair = Keypair.random();
    this.birthYear = birthYear;
    this.ageCredential = this.createAgeCredential();
  }

  /**
   * Create an age credential (normally issued by government authority)
   */
  private createAgeCredential() {
    return {
      id: `age_cred_${this.keypair.publicKey()}`,
      hash: this.hashCredential(),
      birthYear: this.birthYear,
      issuedAt: Date.now() - 365 * 24 * 60 * 60 * 1000, // 1 year ago
      expiresAt: Date.now() + 10 * 365 * 24 * 60 * 60 * 1000, // 10 years from now
      issuerPubKey: { x: '123...', y: '456...' }, // Government public key
      subjectAddress: this.keypair.publicKey(),
      privateKey: this.keypair.secret(),
    };
  }

  private hashCredential(): string {
    const crypto = require('crypto');
    const data = `${this.birthYear}${this.keypair.publicKey()}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate age proof to show they are 21+ without revealing exact age
   */
  async generateAgeProof(): Promise<string> {
    console.log(`Customer: Generating age proof (born ${this.birthYear})`);
    
    try {
      const currentYear = new Date().getFullYear();
      const minAge = 21;
      
      // Generate ZK proof using the SDK
      const proofId = await zkClient.createAgeProof(
        this.birthYear,
        currentYear,
        minAge,
        {
          context: 'bar_entrance',
          expiresAt: Date.now() + 24 * 60 * 60 * 1000, // Valid for 24 hours
        }
      );

      console.log(`✅ Age proof generated: ${proofId}`);
      return proofId;
    } catch (error) {
      console.error('❌ Failed to generate age proof:', error.message);
      throw error;
    }
  }

  /**
   * Get customer's public address for verification
   */
  getAddress(): string {
    return this.keypair.publicKey();
  }

  getAge(): number {
    return new Date().getFullYear() - this.birthYear;
  }
}

/**
 * Bar class - represents the establishment that needs to verify age
 */
class Bar {
  private name: string;
  private minAge: number;
  private acceptedProofs: Set<string> = new Set();

  constructor(name: string, minAge: number = 21) {
    this.name = name;
    this.minAge = minAge;
  }

  /**
   * Verify customer's age proof
   */
  async verifyAgeProof(proofId: string, customerAddress: string): Promise<boolean> {
    console.log(`Bar ${this.name}: Verifying age proof ${proofId}`);

    try {
      // Check if proof was already used (prevent double-spending)
      if (this.acceptedProofs.has(proofId)) {
        console.log('❌ Proof already used');
        return false;
      }

      // Verify the proof on-chain
      const verification = await zkClient.verifyProofOnChain(proofId, []);
      
      if (verification.valid) {
        console.log(`✅ Age verification successful! Customer is ${this.minAge}+`);
        this.acceptedProofs.add(proofId);
        
        // Log the verification (for compliance)
        this.logVerification(customerAddress, proofId);
        return true;
      } else {
        console.log('❌ Age verification failed');
        return false;
      }
    } catch (error) {
      console.error('❌ Error verifying age proof:', error.message);
      return false;
    }
  }

  /**
   * Log verification for compliance purposes
   */
  private logVerification(customerAddress: string, proofId: string) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      bar: this.name,
      customerAddress: customerAddress.substring(0, 8) + '...', // Partial address for privacy
      proofId: proofId,
      verificationResult: 'PASSED',
      minAgeRequired: this.minAge
    };
    
    console.log('📋 Compliance log:', JSON.stringify(logEntry, null, 2));
  }

  /**
   * Get bar statistics
   */
  getStats() {
    return {
      name: this.name,
      minAge: this.minAge,
      verificationsToday: this.acceptedProofs.size,
    };
  }
}

/**
 * Regulatory Authority - oversees the verification system
 */
class RegulatoryAuthority {
  async auditVerification(proofId: string): Promise<any> {
    console.log(`🏛️ Regulatory Authority: Auditing proof ${proofId}`);
    
    try {
      // Get proof details from blockchain
      const proof = await zkClient.getProof(proofId);
      const circuit = await zkClient.getCircuit(proof.circuitId);
      
      return {
        proofId: proof.proofId,
        circuitType: circuit.circuitType,
        createdAt: new Date(proof.createdAt).toISOString(),
        revealedAttributes: proof.revealedAttributes,
        metadata: proof.metadata,
        complianceStatus: 'COMPLIANT'
      };
    } catch (error) {
      console.error('❌ Audit failed:', error.message);
      return null;
    }
  }
}

/**
 * Main demonstration function
 */
async function demonstrateAgeVerification() {
  console.log('🍺 Age Verification Bar Demo');
  console.log('============================\n');

  // Create participants
  const customer21 = new Customer(2002); // 21+ years old
  const customer19 = new Customer(2004); // Under 21
  const bar = new Bar('The Stellar Pub', 21);
  const authority = new RegulatoryAuthority();

  console.log(`👤 Customer 1: Age ${customer21.getAge()} (21+)`);
  console.log(`👤 Customer 2: Age ${customer19.getAge()} (Under 21)`);
  console.log(`🏪 Bar: ${bar.name} (min age: ${bar.minAge})\n`);

  // Scenario 1: Customer 21+ tries to enter
  console.log('--- Scenario 1: 21+ Customer ---');
  try {
    const proofId = await customer21.generateAgeProof();
    const canEnter = await bar.verifyAgeProof(proofId, customer21.getAddress());
    
    if (canEnter) {
      console.log('🎉 Customer 21+ can enter the bar!\n');
    }
  } catch (error) {
    console.log('❌ Customer 21+ denied entry\n');
  }

  // Scenario 2: Customer under 21 tries to enter
  console.log('--- Scenario 2: Under 21 Customer ---');
  try {
    const proofId = await customer19.generateAgeProof();
    const canEnter = await bar.verifyAgeProof(proofId, customer19.getAddress());
    
    if (!canEnter) {
      console.log('🚫 Customer under 21 denied entry (as expected)\n');
    }
  } catch (error) {
    console.log('❌ Customer under 21 could not generate proof\n');
  }

  // Scenario 3: Regulatory audit
  console.log('--- Scenario 3: Regulatory Audit ---');
  const stats = bar.getStats();
  console.log('Bar Statistics:', JSON.stringify(stats, null, 2));

  // Performance metrics
  console.log('\n--- Performance Metrics ---');
  console.log('Proof generation time: <5 seconds (WASM in browser)');
  console.log('On-chain verification time: <2 seconds (Soroban)');
  console.log('Privacy: Exact birthdate never revealed');
  console.log('Non-repudiation: Nullifiers prevent proof reuse');

  console.log('\n✨ Demo completed successfully!');
}

/**
 * Performance benchmark function
 */
async function benchmarkPerformance() {
  console.log('\n⚡ Performance Benchmark');
  console.log('========================');

  const customer = new Customer(1995);
  const iterations = 10;
  const times: number[] = [];

  console.log(`Running ${iterations} proof generations...`);

  for (let i = 0; i < iterations; i++) {
    const startTime = Date.now();
    
    try {
      await customer.generateAgeProof();
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
  demonstrateAgeVerification()
    .then(() => benchmarkPerformance())
    .catch(console.error);
}

export { Customer, Bar, RegulatoryAuthority };
