/**
 * university-diploma.ts
 *
 * Full academic credential flow demonstrating:
 *   1. Schema registration for AcademicCredential
 *   2. Issuing a university diploma as a W3C Verifiable Credential
 *   3. Credential chaining: university attests degree, degree attests honors
 *   4. Creating a Verifiable Presentation for a job application
 *   5. Verifying the presentation against trusted issuers
 *   6. Selective disclosure: reveal only degree + institution (not GPA)
 *   7. Real-time revocation status check
 */

import { Keypair } from 'stellar-sdk';
import {
  CredentialsClient,
  CredentialSchema,
  W3CVerifiableCredential,
} from '../sdk/src/credentials';
import { StellarIdentityConfig } from '../sdk/src/types';

// ---------------------------------------------------------------------------
// Config — point at testnet
// ---------------------------------------------------------------------------

const config: StellarIdentityConfig = {
  network: 'testnet',
  contracts: {
    didRegistry:       process.env.DID_REGISTRY_CONTRACT       ?? 'PLACEHOLDER_DID_REGISTRY',
    credentialIssuer:  process.env.CREDENTIAL_ISSUER_CONTRACT  ?? 'PLACEHOLDER_CREDENTIAL_ISSUER',
    reputationScore:   process.env.REPUTATION_SCORE_CONTRACT   ?? 'PLACEHOLDER_REPUTATION_SCORE',
    zkAttestation:     process.env.ZK_ATTESTATION_CONTRACT     ?? 'PLACEHOLDER_ZK_ATTESTATION',
    complianceFilter:  process.env.COMPLIANCE_FILTER_CONTRACT  ?? 'PLACEHOLDER_COMPLIANCE_FILTER',
  },
  rpcUrl: 'https://soroban-testnet.stellar.org',
};

// ---------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------

// MIT — the issuing university
const universityKeypair = Keypair.fromSecret(
  process.env.UNIVERSITY_SECRET ?? Keypair.random().secret(),
);
const universityDID = `did:stellar:${universityKeypair.publicKey()}`;

// Alice — the graduating student
const studentKeypair = Keypair.fromSecret(
  process.env.STUDENT_SECRET ?? Keypair.random().secret(),
);
const studentDID = `did:stellar:${studentKeypair.publicKey()}`;

// Acme Corp — the employer verifying Alice's credentials
const employerKeypair = Keypair.random();

const client = new CredentialsClient(config);

// ---------------------------------------------------------------------------
// Step 1 — Register AcademicCredential schema
// ---------------------------------------------------------------------------

async function registerAcademicSchema(): Promise<void> {
  console.log('\n[1] Registering AcademicCredential schema...');

  const schema: CredentialSchema = {
    id: 'https://schema.stellar.org/credentials/academic/v1',
    type: 'JsonSchema',
    properties: JSON.stringify({
      institution:    { type: 'string' },
      degree:         { type: 'string' },
      fieldOfStudy:   { type: 'string' },
      graduationDate: { type: 'string', format: 'date' },
      honors:         { type: 'string' },
      gpa:            { type: 'number', minimum: 0, maximum: 4 },
    }),
    required: JSON.stringify(['institution', 'degree', 'fieldOfStudy', 'graduationDate']),
  };

  await client.registerSchema(universityKeypair, schema);
  console.log('   Schema registered:', schema.id);
}

// ---------------------------------------------------------------------------
// Step 2 — Issue the diploma credential
// ---------------------------------------------------------------------------

async function issueDiploma(): Promise<W3CVerifiableCredential> {
  console.log('\n[2] Issuing university diploma to Alice...');

  const diploma = await client.issueAcademicCredential(
    universityKeypair,
    universityDID,
    studentDID,
    {
      institution:    'Massachusetts Institute of Technology',
      degree:         'Bachelor of Science',
      fieldOfStudy:   'Computer Science',
      graduationDate: '2024-06-15',
      honors:         'Summa Cum Laude',
      gpa:            3.97,
    },
    // Expires in 50 years — diplomas are effectively permanent
    Date.now() + 50 * 365 * 24 * 60 * 60 * 1000,
  );

  console.log('   Credential ID:', diploma.id);
  console.log('   Issuer:       ', diploma.issuer);
  console.log('   Subject:      ', diploma.credentialSubject.id);
  console.log('   Type:         ', diploma.type.join(', '));
  console.log('   Proof type:   ', diploma.proof?.type);
  return diploma;
}

// ---------------------------------------------------------------------------
// Step 3 — Credential chaining: honors attestation references the diploma
// ---------------------------------------------------------------------------

async function issueHonorsAttestation(
  diplomaId: string,
): Promise<W3CVerifiableCredential> {
  console.log('\n[3] Issuing honors attestation (chained to diploma)...');

  const honors = await client.issueCredential(
    universityKeypair,
    universityDID,
    studentDID,
    {
      awardName:   'Dean\'s List — Spring 2024',
      awardedBy:   'Massachusetts Institute of Technology',
      awardedDate: '2024-05-01',
    },
    {
      type: ['AcademicCredential', 'HonorsAttestation'],
      parentCredentialId: diplomaId,   // A attests B
    },
  );

  console.log('   Honors credential ID:', honors.id);
  console.log('   Parent credential:   ', honors.parentCredential);
  return honors;
}

// ---------------------------------------------------------------------------
// Step 4 — Create a Verifiable Presentation for a job application
// ---------------------------------------------------------------------------

async function createJobApplicationPresentation(
  credentials: W3CVerifiableCredential[],
): Promise<void> {
  console.log('\n[4] Alice creates a Verifiable Presentation for Acme Corp...');

  const presentation = await client.createPresentation(
    studentKeypair,
    credentials,
    `challenge-${Date.now()}`,   // replay-protection challenge
    'https://acmecorp.example.com',
  );

  console.log('   Presentation ID:', presentation.id);
  console.log('   Holder:         ', presentation.holder);
  console.log('   Credentials:    ', presentation.verifiableCredential.length);
  console.log('   Proof purpose:  ', presentation.proof.proofPurpose);

  // ---------------------------------------------------------------------------
  // Step 5 — Employer verifies the presentation
  // ---------------------------------------------------------------------------
  console.log('\n[5] Acme Corp verifies the presentation...');

  const result = await client.verifyPresentation(presentation, [universityDID]);
  console.log('   Valid:  ', result.valid);
  if (result.errors.length > 0) {
    console.log('   Errors:', result.errors);
  }
}

// ---------------------------------------------------------------------------
// Step 6 — Selective disclosure: reveal only degree + institution
// ---------------------------------------------------------------------------

async function selectiveDisclosure(diploma: W3CVerifiableCredential): Promise<void> {
  console.log('\n[6] Alice derives a credential revealing only degree + institution...');

  const derived = client.deriveCredential(
    diploma,
    studentKeypair,
    ['degree', 'institution'],   // hide gpa, honors, graduationDate
  );

  console.log('   Derived credential ID:', derived.id);
  console.log('   Disclosed claims:     ', Object.keys(derived.credentialSubject).filter(k => k !== 'id'));
  console.log('   Hidden claims:        ', ['gpa', 'honors', 'graduationDate', 'fieldOfStudy']);
}

// ---------------------------------------------------------------------------
// Step 7 — Real-time revocation status check
// ---------------------------------------------------------------------------

async function checkRevocation(credentialId: string): Promise<void> {
  console.log('\n[7] Checking revocation status...');

  const status = await client.checkRevocationStatus(
    credentialId,
    universityKeypair.publicKey(),
  );

  console.log('   Credential ID:', status.credentialId);
  console.log('   Revoked:      ', status.revoked);
  console.log('   Checked at:   ', new Date(status.checkedAt).toISOString());

  // Issuer reputation
  const reputation = await client.getIssuerReputation(universityKeypair.publicKey());
  if (reputation) {
    console.log('\n   Issuer reputation:');
    console.log('     Total issued:  ', reputation.totalIssued);
    console.log('     Total revoked: ', reputation.totalRevoked);
    console.log('     Score:         ', reputation.reputationScore, '/ 100');
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('=== University Diploma — Full Academic Credential Flow ===');
  console.log('University DID:', universityDID);
  console.log('Student DID:   ', studentDID);

  try {
    await registerAcademicSchema();
    const diploma = await issueDiploma();
    const honors  = await issueHonorsAttestation(diploma.id);
    await createJobApplicationPresentation([diploma, honors]);
    await selectiveDisclosure(diploma);
    await checkRevocation(diploma.id);

    console.log('\n=== Flow complete ===');
  } catch (err) {
    // In a real run against testnet the contract calls will fail unless
    // the contracts are deployed and funded. This example demonstrates
    // the full API surface; swap in real contract addresses to run live.
    console.error('Error (expected in dry-run without deployed contracts):', err);
  }
}

main();
