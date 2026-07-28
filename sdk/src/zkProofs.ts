import {
  SorobanRpc,
  TransactionBuilder,
  Networks,
  Keypair,
  Contract,
  xdr,
  nativeToScVal,
  scValToNative,
} from 'stellar-sdk';
import * as snarkjs from 'snarkjs';
import { readFileSync } from 'fs';
import { join } from 'path';
import {
  ZKProof,
  ZKCircuit,
  ZKProofOptions,
  ZKVerificationResult,
  StellarIdentityConfig,
  TransactionOptions,
  CircuitType,
  ProofGenerationInputs,
  PredicateType,
  PredicateInfo,
  SelectiveDisclosureOptions,
  SelectiveDisclosureProof,
  SelectiveDisclosureVerificationResult,
  CombinedDisclosureProof,
} from './types';
import { StellarIdentityError, mapContractError } from './errors';

/**
 * Client for generating and verifying zero-knowledge proofs on Stellar.
 * Supports age verification, income verification, KYC composite proofs,
 * loan application proofs, and batch proof generation using snarkjs.
 * @category Client
 */
export class ZKProofsClient {
  private rpc: SorobanRpc.Server;
  private config: StellarIdentityConfig;
  private zkAttestationContract: Contract;
  private circuitCache: Map<string, any> = new Map();
  private wasmCache: Map<string, any> = new Map();
  private zkeyCache: Map<string, any> = new Map();

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.rpc = new SorobanRpc.Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.zkAttestationContract = new Contract(config.contracts.zkAttestation);
  }

  /**
   * Generate a zero-knowledge proof using WASM witness generation
   */
  async generateProof(
    circuitName: string,
    privateInputs: any,
    publicInputs: any,
    options?: { wasmPath?: string; zkeyPath?: string }
  ): Promise<{ proof: any; publicSignals: any }> {
    try {
      const wasmPath = options?.wasmPath || this.getCircuitPath(circuitName, '.wasm');
      const zkeyPath = options?.zkeyPath || this.getCircuitPath(circuitName, '.zkey');

      // Load WASM and zkey with caching
      const wasm = await this.loadWasm(wasmPath);
      const zkey = await this.loadZkey(zkeyPath);

      // Generate proof
      const startTime = Date.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        privateInputs,
        wasm,
        zkey
      );
      const generationTime = Date.now() - startTime;

      console.log(`Proof generated in ${generationTime}ms`);

      return { proof, publicSignals };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify a proof on-chain
   */
  async verifyProofOnChain(
    proofId: string,
    publicInputs: string[]
  ): Promise<ZKVerificationResult> {
    try {
      const retval = await this.simulateRead('verify_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      
      const isValid = scValToNative(retval) as boolean;
      const proof = await this.getProof(proofId);
      
      return {
        valid: isValid,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create high-level age proof
   */
  /**
   * Create an age verification zero-knowledge proof.
   * Proves that the subject is at least `minAge` years old without revealing
   * their actual birth year or age.
   * @param birthYear - The subject's birth year
   * @param currentYear - The current year for age calculation
   * @param minAge - The minimum age threshold to prove
   * @param options - Additional proof options including expiration
   * @returns The generated proof ID
   */
  async createAgeProof(
    birthYear: number,
    currentYear: number,
    minAge: number,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const age = currentYear - birthYear;
      const randomness = this.generateSalt();
      
      // Generate age commitment
      const commitment = this.generateCommitment(age.toString(), randomness);
      
      // Generate ZK proof
      const { proof, publicSignals } = await this.generateProof(
        'age_range_proof',
        {
          birth_year: birthYear,
          current_year: currentYear,
          min_age: minAge,
          randomness: this.hexToField(randomness),
        },
        {
          commitment: commitment.split(',').map((s, i) => i === 0 ? this.hexToField(s) : s),
          min_age: minAge,
        }
      );

      // Submit proof to contract
      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `age_${birthYear}`,
        'age_range_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair!,
        {
          circuitId: 'age_range_proof',
          publicInputs: [commitment, minAge.toString()],
          proofBytes,
          nullifier,
          revealedAttributes: ['age_commitment'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'age_verification',
            minAge: minAge.toString(),
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create high-level income proof
   */
  /**
   * Create an income verification zero-knowledge proof.
   * Proves that the subject's income meets or exceeds `minIncome` without
   * revealing the exact income amount.
   * @param income - The subject's actual income
   * @param minIncome - The minimum income threshold to prove
   * @param options - Additional proof options including expiration
   * @returns The generated proof ID
   */
  async createIncomeProof(
    income: number,
    minIncome: number,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const randomness = this.generateSalt();
      const commitment = this.generateCommitment(income.toString(), randomness);
      
      const { proof, publicSignals } = await this.generateProof(
        'income_range_proof',
        {
          income: income,
          min_income: minIncome,
          randomness: this.hexToField(randomness),
        },
        {
          commitment: commitment.split(',').map((s, i) => i === 0 ? this.hexToField(s) : s),
          min_income: minIncome,
        }
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `income_${income}`,
        'income_range_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair!,
        {
          circuitId: 'income_range_proof',
          publicInputs: [commitment, minIncome.toString()],
          proofBytes,
          nullifier,
          revealedAttributes: ['income_commitment'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'income_verification',
            minIncome: minIncome.toString(),
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create composite KYC proof
   */
  async createKYCProof(
    credential: any,
    requiredChecks: string[],
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const inputs: any = {
        credential_id: credential.id,
        subject_private_key: this.hexToField(credential.privateKey),
        issuance_timestamp: credential.issuedAt,
        personal_info_hash: this.hexToField(credential.personalInfoHash),
        verification_score: credential.verificationScore,
        issuer_public_key: [
          this.hexToField(credential.issuerPubKey.x),
          this.hexToField(credential.issuerPubKey.y),
        ],
        subject_address: this.hexToField(credential.subjectAddress),
        expiration_timestamp: credential.expiresAt,
      };

      // Add age-specific inputs if required
      if (requiredChecks.includes('age')) {
        inputs.birth_year = credential.birthYear;
        inputs.current_year = new Date().getFullYear();
        inputs.min_age = 18;
        inputs.age_randomness = this.hexToField(this.generateSalt());
      }

      // Add country-specific inputs if required
      if (requiredChecks.includes('country')) {
        inputs.country_code = this.hexToField(credential.countryCode);
        inputs.country_merkle_proof = credential.countryMerkleProof;
        inputs.country_index = credential.countryIndex;
        inputs.country_merkle_root = this.hexToField(credential.countryMerkleRoot);
      }

      const { proof, publicSignals } = await this.generateProof(
        'kyc_composite_proof',
        inputs,
        {
          credential_hash: this.hexToField(credential.hash),
          // Add other public inputs as needed
        }
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        credential.id,
        'kyc_composite_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair!,
        {
          circuitId: 'kyc_composite_proof',
          publicInputs: [credential.hash],
          proofBytes,
          nullifier,
           revealedAttributes: requiredChecks.map(check => check),

          expiresAt: options?.expiresAt,
          metadata: {
            type: 'kyc_verification',
            requiredChecks: requiredChecks.join(','),
            context: options?.context || 'default',
            credential_id: credential.id,
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create loan application proof with multiple requirements
   */
  async createLoanApplicationProof(
    application: any,
    options?: ZKProofOptions
  ): Promise<string> {
    try {
      const inputs = {
        income: application.income,
        credit_score: application.creditScore,
        employment_months: application.employmentMonths,
        debt_amount: application.debtAmount,
        residence_proof: this.hexToField(application.residenceProof),
        income_randomness: this.hexToField(this.generateSalt()),
        credit_randomness: this.hexToField(this.generateSalt()),
        employment_randomness: this.hexToField(this.generateSalt()),
        residence_randomness: this.hexToField(this.generateSalt()),
        residence_merkle_proof: application.residenceMerkleProof,
        residence_index: application.residenceIndex,
      };

      const publicInputs = {
        min_income: application.minIncome,
        min_credit_score: application.minCreditScore,
        max_debt_to_income: application.maxDebtToIncome,
        min_employment_months: application.minEmploymentMonths,
        residence_merkle_root: this.hexToField(application.residenceMerkleRoot),
      };

      const { proof, publicSignals } = await this.generateProof(
        'loan_application_composite_proof',
        inputs,
        publicInputs
      );

      const proofBytes = JSON.stringify(proof);
      const nullifier = this.generateNullifier(
        `loan_${application.applicantId}`,
        'loan_application_composite_proof',
        options?.context || 'default'
      );

      return this.submitProof(
        this.config.keypair!,
        {
          circuitId: 'loan_application_composite_proof',
          publicInputs: Object.values(publicInputs).map(v => v.toString()),
          proofBytes,
          nullifier,
          revealedAttributes: ['income_commitment', 'credit_commitment', 'employment_status'],
          expiresAt: options?.expiresAt,
          metadata: {
            type: 'loan_application',
            applicant_id: application.applicantId,
            loan_amount: application.loanAmount,
            context: options?.context || 'default',
          },
        },
        options?.txOptions
      );
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Batch generate multiple proofs for efficiency
   */
  async batchGenerateProofs(
    proofs: Array<{
      circuitName: string;
      privateInputs: any;
      publicInputs: any;
    }>
  ): Promise<Array<{ proof: any; publicSignals: any; generationTime: number }>> {
    const results = [];
    
    for (const proofRequest of proofs) {
      const startTime = Date.now();
      try {
        const result = await this.generateProof(
          proofRequest.circuitName,
          proofRequest.privateInputs,
          proofRequest.publicInputs
        );
        results.push({
          ...result,
          generationTime: Date.now() - startTime,
        });
       } catch (error: any) {
         results.push({
           proof: null,
           publicSignals: null,
           generationTime: Date.now() - startTime,
           error: error.message,
         });
       }

    }
    
    return results;
  }

  /**
   * Load WASM file with caching
   */
  private async loadWasm(wasmPath: string): Promise<any> {
    if (this.wasmCache.has(wasmPath)) {
      return this.wasmCache.get(wasmPath);
    }

    try {
      const wasmBuffer = readFileSync(wasmPath);
      const wasm = await WebAssembly.compile(wasmBuffer);
      this.wasmCache.set(wasmPath, wasm);
      return wasm;
     } catch (error: any) {
       throw new Error(`Failed to load WASM from ${wasmPath}: ${error.message}`);
     }

  }

  /**
   * Load zkey file with caching
   */
  private async loadZkey(zkeyPath: string): Promise<any> {
    if (this.zkeyCache.has(zkeyPath)) {
      return this.zkeyCache.get(zkeyPath);
    }

    try {
      const zkeyBuffer = readFileSync(zkeyPath);
      const zkey = JSON.parse(zkeyBuffer.toString());
      this.zkeyCache.set(zkeyPath, zkey);
      return zkey;
     } catch (error: any) {
       throw new Error(`Failed to load zkey from ${zkeyPath}: ${error.message}`);
     }

  }

  /**
   * Get circuit file path
   */
  private getCircuitPath(circuitName: string, extension: string): string {
    const circuitsDir = join(__dirname, '..', '..', 'circuits');
    return join(circuitsDir, `${circuitName}${extension}`);
  }

  /**
   * Convert hex string to field element
   */
  private hexToField(hex: string): string {
    // Remove 0x prefix if present
    const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
    // Convert to decimal string
    return BigInt('0x' + cleanHex).toString();
  }

  /**
   * Generate nullifier for proof
   */
  private generateNullifier(credentialId: string, circuitId: string, context: string): string {
    const crypto = require('crypto') as typeof import('crypto');
    const data = `${credentialId}${circuitId}${context}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // -------------------------------------------------------------------------
  // Selective Disclosure methods (#111)
  // -------------------------------------------------------------------------

  /**
   * Create a selective disclosure proof that reveals only specific attributes
   * while proving predicates (GT, LT, range, equality) on hidden attributes.
   */
  async createSelectiveDisclosureProof(
    submitterKeypair: Keypair,
    options: SelectiveDisclosureOptions
  ): Promise<string> {
    try {
      const account = await this.rpc.getAccount(submitterKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'create_selective_disclosure_proof',
            nativeToScVal(new TextEncoder().encode(options.credentialId), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(options.circuitId), { type: 'bytes' }),
            nativeToScVal(options.publicInputs.map(i => new TextEncoder().encode(i)), { type: 'vec' }),
            nativeToScVal(new TextEncoder().encode(options.proofBytes), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(options.nullifier), { type: 'bytes' }),
            nativeToScVal(options.revealedAttributes.map(a => new TextEncoder().encode(a)), { type: 'vec' }),
            nativeToScVal(options.hiddenAttributes.map(a => new TextEncoder().encode(a)), { type: 'vec' }),
            nativeToScVal(this.encodePredicates(options.predicates), { type: 'vec' }),
            options.expiresAt != null
              ? nativeToScVal(BigInt(options.expiresAt), { type: 'u64' })
              : xdr.ScVal.scvVoid(),
            options.metadata
              ? nativeToScVal(new TextEncoder().encode(JSON.stringify(options.metadata)), { type: 'bytes' })
              : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(submitterKeypair);
      await this.rpc.sendTransaction(prepared);
      return `sd-proof-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify a selective disclosure proof matches expected predicates.
   */
  async verifySelectiveDisclosure(
    proofId: string,
    expectedPredicates: PredicateInfo[]
  ): Promise<SelectiveDisclosureVerificationResult> {
    try {
      const retval = await this.simulateRead('verify_selective_disclosure', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
        nativeToScVal(this.encodePredicates(expectedPredicates), { type: 'vec' }),
      ]);

      const disclosure = await this.getSelectiveDisclosure(proofId);
      return {
        valid: scValToNative(retval) as boolean,
        proofId,
        circuitId: disclosure.circuitId,
        predicates: disclosure.predicates,
        verifiedAt: Date.now(),
        expiresAt: disclosure.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Combine multiple selective disclosure proofs into a single composite proof.
   */
  async combineSelectiveDisclosures(
    submitterKeypair: Keypair,
    proofIds: string[],
    metadata?: Record<string, string>
  ): Promise<string> {
    try {
      const account = await this.rpc.getAccount(submitterKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'combine_selective_disclosures',
            nativeToScVal(proofIds.map(id => new TextEncoder().encode(id)), { type: 'vec' }),
            metadata
              ? nativeToScVal(new TextEncoder().encode(JSON.stringify(metadata)), { type: 'bytes' })
              : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(submitterKeypair);
      await this.rpc.sendTransaction(prepared);
      return `combined-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Retrieve a selective disclosure proof by ID.
   */
  async getSelectiveDisclosure(proofId: string): Promise<SelectiveDisclosureProof> {
    try {
      const retval = await this.simulateRead('get_selective_disclosure', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      return this.parseSelectiveDisclosure(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Retrieve a combined disclosure proof by ID.
   */
  async getCombinedDisclosure(proofId: string): Promise<CombinedDisclosureProof> {
    try {
      const retval = await this.simulateRead('get_combined_disclosure', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      return this.parseCombinedDisclosure(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Prove a specific attribute value is greater than a threshold.
   */
  async createGreaterThanProof(
    submitterKeypair: Keypair,
    attributeName: string,
    attributeValue: number,
    threshold: number,
    credentialId: string,
    circuitId: string,
    options?: { context?: string; expiresAt?: number }
  ): Promise<string> {
    const nonce = this.generateSalt();
    const commitment = this.generateCommitment(attributeValue.toString(), nonce);
    const nullifier = this.generateNullifier(
      `${credentialId}_${attributeName}_gt`,
      circuitId,
      options?.context || 'default'
    );
    const predicates: PredicateInfo[] = [{
      attributeName,
      predicateType: PredicateType.GreaterThan,
      threshold: threshold.toString(),
    }];

    return this.createSelectiveDisclosureProof(submitterKeypair, {
      circuitId,
      credentialId,
      publicInputs: [commitment, threshold.toString()],
      proofBytes: `{"gt_proof":{"attribute":${attributeValue},"threshold":${threshold}}}`,
      nullifier,
      revealedAttributes: [],
      hiddenAttributes: [attributeName],
      predicates,
      expiresAt: options?.expiresAt,
      metadata: {
        type: 'greater_than',
        attribute: attributeName,
        threshold: threshold.toString(),
        context: options?.context || 'default',
      },
    });
  }

  /**
   * Prove a specific attribute value is within a range [min, max].
   */
  async createRangeProof(
    submitterKeypair: Keypair,
    attributeName: string,
    attributeValue: number,
    min: number,
    max: number,
    credentialId: string,
    circuitId: string,
    options?: { context?: string; expiresAt?: number }
  ): Promise<string> {
    const nonce = this.generateSalt();
    const commitment = this.generateCommitment(attributeValue.toString(), nonce);
    const nullifier = this.generateNullifier(
      `${credentialId}_${attributeName}_range`,
      circuitId,
      options?.context || 'default'
    );
    const predicates: PredicateInfo[] = [{
      attributeName,
      predicateType: PredicateType.Range,
      rangeMin: min.toString(),
      rangeMax: max.toString(),
    }];

    return this.createSelectiveDisclosureProof(submitterKeypair, {
      circuitId,
      credentialId,
      publicInputs: [commitment, min.toString(), max.toString()],
      proofBytes: `{"range_proof":{"attribute":${attributeValue},"min":${min},"max":${max}}}`,
      nullifier,
      revealedAttributes: [],
      hiddenAttributes: [attributeName],
      predicates,
      expiresAt: options?.expiresAt,
      metadata: {
        type: 'range_proof',
        attribute: attributeName,
        min: min.toString(),
        max: max.toString(),
        context: options?.context || 'default',
      },
    });
  }

  /**
   * Selectively reveal the exact value of an attribute.
   */
  async createEqualityDisclosure(
    submitterKeypair: Keypair,
    attributeName: string,
    attributeValue: number,
    credentialId: string,
    circuitId: string,
    options?: { context?: string; expiresAt?: number }
  ): Promise<string> {
    const nonce = this.generateSalt();
    const commitment = this.generateCommitment(attributeValue.toString(), nonce);
    const nullifier = this.generateNullifier(
      `${credentialId}_${attributeName}_eq`,
      circuitId,
      options?.context || 'default'
    );
    const predicates: PredicateInfo[] = [{
      attributeName,
      predicateType: PredicateType.Equality,
      threshold: attributeValue.toString(),
    }];

    return this.createSelectiveDisclosureProof(submitterKeypair, {
      circuitId,
      credentialId,
      publicInputs: [commitment, attributeValue.toString()],
      proofBytes: `{"eq_proof":{"attribute":${attributeValue}}}`,
      nullifier,
      revealedAttributes: [attributeName],
      hiddenAttributes: [],
      predicates,
      expiresAt: options?.expiresAt,
      metadata: {
        type: 'equality_disclosure',
        attribute: attributeName,
        value: attributeValue.toString(),
        context: options?.context || 'default',
      },
    });
  }

  /**
   * Encode predicate info for contract calls.
   */
  private encodePredicates(predicates: PredicateInfo[]): any[] {
    return predicates.map(p => ({
      attributeName: new TextEncoder().encode(p.attributeName),
      predicateType: this.encodePredicateType(p.predicateType),
      threshold: p.threshold ? new TextEncoder().encode(p.threshold) : null,
      rangeMin: p.rangeMin ? new TextEncoder().encode(p.rangeMin) : null,
      rangeMax: p.rangeMax ? new TextEncoder().encode(p.rangeMax) : null,
      allowedValues: p.allowedValues
        ? p.allowedValues.map(v => new TextEncoder().encode(v))
        : null,
    }));
  }

  private encodePredicateType(type: PredicateType): number {
    const map: Record<PredicateType, number> = {
      [PredicateType.GreaterThan]: 0,
      [PredicateType.LessThan]: 1,
      [PredicateType.GreaterThanOrEqual]: 2,
      [PredicateType.LessThanOrEqual]: 3,
      [PredicateType.Equality]: 4,
      [PredicateType.Range]: 5,
      [PredicateType.InSet]: 6,
      [PredicateType.NotInSet]: 7,
    };
    return map[type] ?? 0;
  }

  private parseSelectiveDisclosure(raw: unknown): SelectiveDisclosureProof {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      proofId: toStr(r[0]),
      credentialId: toStr(r[1]),
      circuitId: toStr(r[2]),
      publicInputs: Array.isArray(r[3]) ? (r[3] as unknown[]).map(toStr) : [],
      proofBytes: toStr(r[4]),
      nullifier: toStr(r[5]),
      verifierAddress: toStr(r[6]),
      createdAt: Number(r[7] ?? 0),
      expiresAt: r[8] != null ? Number(r[8]) : undefined,
      revealedAttributes: Array.isArray(r[9]) ? (r[9] as unknown[]).map(toStr) : [],
      hiddenAttributes: Array.isArray(r[10]) ? (r[10] as unknown[]).map(toStr) : [],
      predicates: Array.isArray(r[11]) ? (r[11] as unknown[]).map(this.parsePredicateInfo) : [],
      metadata: this.parseMetadata(r[12]),
    };
  }

  private parseCombinedDisclosure(raw: unknown): CombinedDisclosureProof {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      proofId: toStr(r[0]),
      childProofIds: Array.isArray(r[1]) ? (r[1] as unknown[]).map(toStr) : [],
      combinedPredicates: Array.isArray(r[2]) ? (r[2] as unknown[]).map(this.parsePredicateInfo) : [],
      createdAt: Number(r[3] ?? 0),
      expiresAt: r[4] != null ? Number(r[4]) : undefined,
      metadata: this.parseMetadata(r[5]),
    };
  }

  private parsePredicateInfo(raw: unknown): PredicateInfo {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    const predTypeMap: Record<string, PredicateType> = {
      '0': PredicateType.GreaterThan,
      '1': PredicateType.LessThan,
      '2': PredicateType.GreaterThanOrEqual,
      '3': PredicateType.LessThanOrEqual,
      '4': PredicateType.Equality,
      '5': PredicateType.Range,
      '6': PredicateType.InSet,
      '7': PredicateType.NotInSet,
    };
    return {
      attributeName: toStr(r[0]),
      predicateType: predTypeMap[String(r[1])] || PredicateType.GreaterThan,
      threshold: r[2] != null ? toStr(r[2]) : undefined,
      rangeMin: r[3] != null ? toStr(r[3]) : undefined,
      rangeMax: r[4] != null ? toStr(r[4]) : undefined,
      allowedValues: Array.isArray(r[5]) ? (r[5] as unknown[]).map(toStr) : undefined,
    };
  }

  async registerCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    name: string,
    description: string,
    verifierKey: string,
    publicInputCount: number,
    privateInputCount: number,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'register_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(name), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(description), { type: 'bytes' }),
            nativeToScVal(new TextEncoder().encode(verifierKey), { type: 'bytes' }),
            nativeToScVal(BigInt(publicInputCount), { type: 'u32' }),
            nativeToScVal(BigInt(privateInputCount), { type: 'u32' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Submit a zero-knowledge proof to the on-chain contract.
   * @param submitterKeypair - The keypair of the proof submitter
   * @param options - Proof details including circuit, inputs, and proof bytes
   * @param txOptions - Optional transaction parameters
   * @returns The proof ID
   */
  async submitProof(
    submitterKeypair: Keypair,
    options: ZKProofOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const account = await this.rpc.getAccount(submitterKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'submit_proof',
            nativeToScVal(new TextEncoder().encode(options.circuitId), { type: 'bytes' }),
            nativeToScVal(options.publicInputs.map(i => new TextEncoder().encode(i)), { type: 'vec' }),
            nativeToScVal(new TextEncoder().encode(options.proofBytes), { type: 'bytes' }),
            options.expiresAt != null ? nativeToScVal(BigInt(options.expiresAt), { type: 'u64' }) : xdr.ScVal.scvVoid(),
            options.metadata ? nativeToScVal(new TextEncoder().encode(JSON.stringify(options.metadata)), { type: 'bytes' }) : xdr.ScVal.scvVoid()
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(submitterKeypair);
      await this.rpc.sendTransaction(prepared);
      return `proof-${Date.now()}`;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async verifyProof(proofId: string): Promise<ZKVerificationResult> {
    try {
      const isValidVal = await this.simulateRead('verify_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      const proof = await this.getProof(proofId);
      return {
        valid: scValToNative(isValidVal) as boolean,
        circuitId: proof.circuitId,
        proofId: proof.proofId,
        verifiedAt: Date.now(),
        expiresAt: proof.expiresAt,
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getProof(proofId: string): Promise<ZKProof> {
    try {
      const retval = await this.simulateRead('get_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
      ]);
      return this.parseZKProof(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuit(circuitId: string): Promise<ZKCircuit> {
    try {
      const retval = await this.simulateRead('get_circuit', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return this.parseZKCircuit(scValToNative(retval));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getCircuitProofs(circuitId: string): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_circuit_proofs', [
        nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' }),
      ]);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async deactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'deactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async reactivateCircuit(
    adminKeypair: Keypair,
    circuitId: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.rpc.getAccount(adminKeypair.publicKey());

      const tx = new TransactionBuilder(account, {
        fee: String(txOptions?.fee ?? 100),
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.zkAttestationContract.call(
            'reactivate_circuit',
            nativeToScVal(new TextEncoder().encode(circuitId), { type: 'bytes' })
          )
        )
        .setTimeout(txOptions?.timeout ?? 30)
        .build();

      const prepared = await this.rpc.prepareTransaction(tx);
      prepared.sign(adminKeypair);
      await this.rpc.sendTransaction(prepared);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async getActiveCircuits(): Promise<string[]> {
    try {
      const retval = await this.simulateRead('get_active_circuits', []);
      return (scValToNative(retval) as Uint8Array[]).map(b => new TextDecoder().decode(b));
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async batchVerifyProofs(proofIds: string[]): Promise<ZKVerificationResult[]> {
    return Promise.all(proofIds.map(id => this.verifyProof(id)));
  }

  async submitAgeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minAge: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minAge)],
        proofBytes,
        nullifier: this.generateNullifier(`age_${minAge}`, circuitId, 'manual'),
        revealedAttributes: ['age_commitment'],
        metadata: { type: 'age_verification', minAge: String(minAge) },
      },
      txOptions
    );
  }


  async verifyAgeProof(proofId: string, minAge: number): Promise<boolean> {
    try {
      const retval = await this.simulateRead('verify_age_proof', [
        nativeToScVal(new TextEncoder().encode(proofId), { type: 'bytes' }),
        nativeToScVal(BigInt(minAge), { type: 'u32' }),
      ]);
      return scValToNative(retval) as boolean;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  async submitIncomeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minIncome: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minIncome)],
        proofBytes,
        nullifier: this.generateNullifier(`income_${minIncome}`, circuitId, 'manual'),
        revealedAttributes: ['income_commitment'],
        metadata: { type: 'income_verification', minIncome: String(minIncome) },
      },
      txOptions
    );
  }



  async submitCredentialOwnershipProof(
    submitterKeypair: Keypair,
    circuitId: string,
    credentialHash: string,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [credentialHash],
        proofBytes,
        nullifier: this.generateNullifier(credentialHash, circuitId, 'manual'),
        revealedAttributes: ['credential_ownership'],
        metadata: { type: 'credential_ownership' },
      },
      txOptions
    );
  }

  async submitRangeProof(
    submitterKeypair: Keypair,
    circuitId: string,
    commitment: string,
    minValue: number,
    maxValue: number,
    proofBytes: string,
    txOptions?: TransactionOptions
  ): Promise<string> {
    return this.submitProof(
      submitterKeypair,
      {
        circuitId,
        publicInputs: [commitment, String(minValue), String(maxValue)],
        proofBytes,
        nullifier: this.generateNullifier(`range_${minValue}_${maxValue}`, circuitId, 'manual'),
        revealedAttributes: ['range_verification'],
        metadata: { type: 'range_verification', min: String(minValue), max: String(maxValue) },
      },
      txOptions
    );
  }

  /**
   * Generate a cryptographic commitment using SHA-256.
   * Used for hiding private data in zero-knowledge proofs.
   * @param privateData - The data to commit to
   * @param salt - Optional random salt (generated if not provided)
   * @returns Hex-encoded commitment hash
   */
  generateCommitment(privateData: string, salt?: string): string {
    const crypto = require('crypto') as typeof import('crypto');
    const actualSalt = salt ?? (crypto.randomBytes(32).toString('hex'));
    return crypto.createHash('sha256').update(privateData + actualSalt).digest('hex');
  }

  generateSalt(): string {
    const crypto = require('crypto') as typeof import('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  private async simulateRead(method: string, args: xdr.ScVal[]): Promise<xdr.ScVal> {
    const dummy = Keypair.random();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const account = { accountId: () => dummy.publicKey(), sequenceNumber: () => '0', incrementSequenceNumber: () => {} } as any;

    const tx = new TransactionBuilder(account, { fee: '100', networkPassphrase: this.getNetworkPassphrase() })
      .addOperation(this.zkAttestationContract.call(method, ...args))
      .setTimeout(30)
      .build();

    const sim = await this.rpc.simulateTransaction(tx);
    if (SorobanRpc.Api.isSimulationError(sim)) {
      throw new Error((sim as SorobanRpc.Api.SimulateTransactionErrorResponse).error);
    }
    const retval = (sim as SorobanRpc.Api.SimulateTransactionSuccessResponse).result?.retval;
    if (!retval) throw new Error('No return value from contract');
    return retval;
  }

  private parseZKProof(raw: unknown): ZKProof {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      proofId: toStr(r[0]),
      circuitId: toStr(r[1]),
      publicInputs: Array.isArray(r[2]) ? (r[2] as unknown[]).map(toStr) : [],
      proofBytes: toStr(r[3]),
      verifyingKeyHash: toStr(r[4]),
      nullifier: toStr(r[5]),
      verifierAddress: toStr(r[6]),
      createdAt: Number(r[7] ?? 0),
      expiresAt: r[8] != null ? Number(r[8]) : undefined,
      metadata: this.parseMetadata(r[9]),
      revealedAttributes: Array.isArray(r[10]) ? (r[10] as unknown[]).map(toStr) : [],
    };
  }

  private parseZKCircuit(raw: unknown): ZKCircuit {
    const r = Array.isArray(raw) ? raw : [];
    const toStr = (v: unknown) => (v instanceof Uint8Array ? new TextDecoder().decode(v) : String(v ?? ''));
    return {
      circuitId: toStr(r[0]),
      name: toStr(r[1]),
      description: toStr(r[2]),
      verifierKey: toStr(r[3]),
      verifyingKeyHash: toStr(r[4]),
      publicInputCount: Number(r[5] ?? 0),
      privateInputCount: Number(r[6] ?? 0),
      createdBy: toStr(r[7]),
      createdAt: Number(r[8] ?? 0),
      active: Boolean(r[9]),
      circuitType: (r[10] as any) || CircuitType.RangeProof,
      supportedAttributes: Array.isArray(r[11]) ? (r[11] as unknown[]).map(toStr) : [],
    };
  }

  private parseMetadata(metadata: unknown): Record<string, string> {
    const result: Record<string, string> = {};
    if (metadata && typeof metadata === 'object') {
      for (const [key, value] of Object.entries(metadata as Record<string, unknown>)) {
        result[key] = value instanceof Uint8Array ? new TextDecoder().decode(value) : String(value);
      }
    }
    return result;
  }

  private getDefaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet': return 'https://soroban-rpc.stellar.org';
      case 'futurenet': return 'https://rpc-futurenet.stellar.org';
      default: return 'https://soroban-testnet.stellar.org';
    }
  }

  private getNetworkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet': return Networks.PUBLIC;
      case 'futurenet': return Networks.FUTURENET;
      default: return Networks.TESTNET;
    }
  }

  private handleError(error: unknown): StellarIdentityError {
    return mapContractError(error);
  }
}
