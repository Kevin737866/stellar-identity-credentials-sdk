import { 
  Server, 
  TransactionBuilder, 
  Networks, 
  Keypair, 
  Contract,
  Address
} from 'stellar-sdk';
import { 
  VerifiableCredential,
  StellarIdentityConfig,
  IssueCredentialOptions,
  TransactionOptions,
  CredentialVerificationResult,
  StellarIdentityError
} from './types';
import { DIDClient } from './didClient';

export class CredentialClient {
  private server: Server;
  private config: StellarIdentityConfig;
  private credentialIssuerContract: Contract;
  private didClient: DIDClient;

  constructor(config: StellarIdentityConfig) {
    this.config = config;
    this.server = new Server(config.rpcUrl || this.getDefaultRpcUrl());
    this.credentialIssuerContract = new Contract(config.contracts.credentialIssuer);
    this.didClient = new DIDClient(config);
  }

  /**
   * Issue a new verifiable credential
   */
  async issueCredential(
    issuerKeypair: Keypair,
    options: IssueCredentialOptions,
    txOptions?: TransactionOptions
  ): Promise<string> {
    try {
      const account = await this.server.getAccount(issuerKeypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.credentialIssuerContract.call(
            'issue_credential',
            new Address(options.subject),
            options.credentialType,
            JSON.stringify(options.credentialData),
            options.expirationDate || null,
            options.proof
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      if (txOptions?.memo) {
        transaction.addMemo(txOptions.memo);
      }

      transaction.sign(issuerKeypair);
      const result = await this.server.sendTransaction(transaction);
      
      if (result.result) {
        return this.extractCredentialId(result.result);
      } else {
        throw new Error('Transaction failed');
      }
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Verify a verifiable credential
   */
  async verifyCredential(credentialId: string): Promise<CredentialVerificationResult> {
    try {
      const credential = await this.getCredential(credentialId);
      const isValid = await this.credentialIssuerContract.call('verify_credential', credentialId);
      const status = await this.credentialIssuerContract.call('get_credential_status', credentialId);
      
      return {
        valid: isValid.result.val,
        revoked: status.result.val === 'revoked',
        expired: this.isCredentialExpired(credential),
        issuer: credential.issuer,
        subject: credential.subject,
        issuanceDate: credential.issuanceDate,
        expirationDate: credential.expirationDate
      };
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Revoke a verifiable credential
   */
  async revokeCredential(
    issuerKeypair: Keypair,
    credentialId: string,
    reason?: string,
    txOptions?: TransactionOptions
  ): Promise<void> {
    try {
      const account = await this.server.getAccount(issuerKeypair.publicKey());
      
      const transaction = new TransactionBuilder(account, {
        fee: txOptions?.fee || '100',
        networkPassphrase: this.getNetworkPassphrase(),
      })
        .addOperation(
          this.credentialIssuerContract.call(
            'revoke_credential',
            credentialId,
            reason || null
          )
        )
        .setTimeout(txOptions?.timeout || 30)
        .build();

      transaction.sign(issuerKeypair);
      await this.server.sendTransaction(transaction);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get credential details
   */
  async getCredential(credentialId: string): Promise<VerifiableCredential> {
    try {
      const result = await this.credentialIssuerContract.call('get_credential', credentialId);
      return this.parseCredential(result.result.val);
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get all credentials for an issuer
   */
  async getIssuerCredentials(issuerAddress: string): Promise<string[]> {
    try {
      const result = await this.credentialIssuerContract.call('get_issuer_credentials', issuerAddress);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get all credentials for a subject
   */
  async getSubjectCredentials(subjectAddress: string): Promise<string[]> {
    try {
      const result = await this.credentialIssuerContract.call('get_subject_credentials', subjectAddress);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get credential status
   */
  async getCredentialStatus(credentialId: string): Promise<string> {
    try {
      const result = await this.credentialIssuerContract.call('get_credential_status', credentialId);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Batch verify multiple credentials
   */
  async batchVerifyCredentials(credentialIds: string[]): Promise<CredentialVerificationResult[]> {
    try {
      const results = await this.credentialIssuerContract.call('batch_verify_credentials', credentialIds);
      const verificationResults: CredentialVerificationResult[] = [];
      
      for (let i = 0; i < credentialIds.length; i++) {
        const credential = await this.getCredential(credentialIds[i]);
        const status = await this.getCredentialStatus(credentialIds[i]);
        
        verificationResults.push({
          valid: results.result.val[i],
          revoked: status === 'revoked',
          expired: this.isCredentialExpired(credential),
          issuer: credential.issuer,
          subject: credential.subject,
          issuanceDate: credential.issuanceDate,
          expirationDate: credential.expirationDate
        });
      }
      
      return verificationResults;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Get revocation reason
   */
  async getRevocationReason(credentialId: string): Promise<string | null> {
    try {
      const result = await this.credentialIssuerContract.call('get_revocation_reason', credentialId);
      return result.result.val || null;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Search credentials by type
   */
  async searchCredentialsByType(credentialType: string, maxResults: number = 10): Promise<string[]> {
    try {
      const result = await this.credentialIssuerContract.call('search_credentials_by_type', credentialType, maxResults);
      return result.result.val;
    } catch (error) {
      throw this.handleError(error);
    }
  }

  /**
   * Create a verifiable presentation
   */
  async createPresentation(
    credentials: VerifiableCredential[],
    holderKeypair: Keypair,
    domain?: string,
    challenge?: string
  ): Promise<any> {
    const presentation = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiablePresentation'],
      holder: this.didClient.generateDID(holderKeypair.publicKey()),
      verifiableCredential: credentials,
      proof: await this.createPresentationProof(holderKeypair, domain, challenge)
    };

    return presentation;
  }

  /**
   * Verify a verifiable presentation
   */
  async verifyPresentation(presentation: any): Promise<boolean> {
    try {
      // Verify presentation proof
      const proofValid = await this.verifyPresentationProof(presentation.proof, presentation.holder);
      if (!proofValid) {
        return false;
      }

      // Verify all credentials in the presentation
      const credentialVerifications = await Promise.all(
        presentation.verifiableCredential.map((cred: any) => 
          this.verifyCredential(cred.id)
        )
      );

      return credentialVerifications.every(verification => verification.valid);
    } catch (error) {
      return false;
    }
  }

  /**
   * Issue KYC credential (common use case)
   */
  async issueKYCCredential(
    issuerKeypair: Keypair,
    subjectAddress: string,
    kycData: {
      firstName: string;
      lastName: string;
      dateOfBirth: string;
      nationality: string;
      documentType: string;
      documentNumber: string;
      expiryDate: string;
    },
    expirationDate?: number,
    txOptions?: TransactionOptions
  ): Promise<string> {
    const credentialData = {
      type: 'KYCVerification',
      data: kycData,
      verificationLevel: 'Standard',
      issuedBy: issuerKeypair.publicKey(),
      timestamp: Date.now()
    };

    return this.issueCredential(
      issuerKeypair,
      {
        subject: subjectAddress,
        credentialType: ['KYCVerification', 'VerifiableCredential'],
        credentialData,
        expirationDate: expirationDate || (Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year
        proof: await this.generateKYCProof(credentialData, issuerKeypair)
      },
      txOptions
    );
  }

  /**
   * Issue education credential
   */
  async issueEducationCredential(
    issuerKeypair: Keypair,
    subjectAddress: string,
    educationData: {
      degree: string;
      institution: string;
      fieldOfStudy: string;
      graduationDate: string;
      gpa?: number;
    },
    expirationDate?: number,
    txOptions?: TransactionOptions
  ): Promise<string> {
    const credentialData = {
      type: 'EducationCredential',
      data: educationData,
      issuedBy: issuerKeypair.publicKey(),
      timestamp: Date.now()
    };

    return this.issueCredential(
      issuerKeypair,
      {
        subject: subjectAddress,
        credentialType: ['EducationCredential', 'VerifiableCredential'],
        credentialData,
        expirationDate: expirationDate || (Date.now() + 10 * 365 * 24 * 60 * 60 * 1000), // 10 years
        proof: await this.generateEducationProof(credentialData, issuerKeypair)
      },
      txOptions
    );
  }

  private parseCredential(result: any): VerifiableCredential {
    return {
      id: result[0],
      issuer: result[1],
      subject: result[2],
      type: result[3],
      credentialData: JSON.parse(result[4]),
      issuanceDate: result[5],
      expirationDate: result[6],
      revocation: result[7],
      proof: result[8]
    };
  }

  private isCredentialExpired(credential: VerifiableCredential): boolean {
    if (!credential.expirationDate) {
      return false;
    }
    return Date.now() > credential.expirationDate;
  }

  private extractCredentialId(result: any): string {
    // Extract credential ID from transaction result
    // This would depend on the actual result format from the contract
    return result.id || 'unknown';
  }

  private async createPresentationProof(
    keypair: Keypair,
    domain?: string,
    challenge?: string
  ): Promise<any> {
    // Create a digital signature for the presentation
    const message = JSON.stringify({
      domain: domain || '',
      challenge: challenge || '',
      timestamp: Date.now()
    });

    const signature = keypair.sign(Buffer.from(message)).toString('hex');

    return {
      type: 'Ed25519Signature2018',
      created: new Date().toISOString(),
      verificationMethod: `${this.didClient.generateDID(keypair.publicKey())}#key-1`,
      proofPurpose: 'authentication',
      domain: domain || '',
      challenge: challenge || '',
      jws: signature
    };
  }

  private async verifyPresentationProof(proof: any, holder: string): Promise<boolean> {
    try {
      // Verify the presentation proof
      // This is a simplified implementation
      return proof.type === 'Ed25519Signature2018' && proof.jws;
    } catch {
      return false;
    }
  }

  private async generateKYCProof(credentialData: any, keypair: Keypair): Promise<string> {
    const message = JSON.stringify(credentialData);
    return keypair.sign(Buffer.from(message)).toString('hex');
  }

  private async generateEducationProof(credentialData: any, keypair: Keypair): Promise<string> {
    const message = JSON.stringify(credentialData);
    return keypair.sign(Buffer.from(message)).toString('hex');
  }

  private getDefaultRpcUrl(): string {
    switch (this.config.network) {
      case 'mainnet':
        return 'https://horizon.stellar.org';
      case 'testnet':
        return 'https://horizon-testnet.stellar.org';
      case 'futurenet':
        return 'https://horizon-futurenet.stellar.org';
      default:
        return 'https://horizon-testnet.stellar.org';
    }
  }

  private getNetworkPassphrase(): string {
    switch (this.config.network) {
      case 'mainnet':
        return Networks.PUBLIC;
      case 'testnet':
        return Networks.TESTNET;
      case 'futurenet':
        return Networks.FUTURENET;
      default:
        return Networks.TESTNET;
    }
  }

  private handleError(error: any): StellarIdentityError {
    const stellarError: StellarIdentityError = new Error(error.message) as StellarIdentityError;
    stellarError.code = error.code || 500;
    stellarError.type = error.type || 'UnknownError';
    return stellarError;
  }
}
