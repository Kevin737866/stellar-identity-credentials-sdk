/**
 * did:stellar Lifecycle Example
 *
 * Demonstrates the complete W3C-compliant DID lifecycle on Stellar:
 *   1. Create  – Register a new DID anchored to a Stellar account
 *   2. Resolve – Fetch the DID document on-chain
 *   3. Update  – Add a service endpoint (e.g. LinkedIn profile)
 *   4. Rotate  – Replace the primary signing key (key rotation)
 *   5. Dereference – Look up a specific fragment inside the DID document
 *   6. Verify  – Verify an ed25519 signature using the DID's key
 *   7. Deactivate – Soft-delete (tombstone) the DID
 *   8. Post-deactivation resolve – Confirm tombstone flag
 *
 * Usage:
 *   npx ts-node examples/did-lifecycle.ts
 *
 * Prerequisites:
 *   - npm install (sdk dependencies)
 *   - A testnet account funded via https://friendbot.stellar.org
 */

import { Keypair } from 'stellar-sdk';
import { DIDResolver } from '../sdk/src/didResolver';
import { StellarIdentitySDK, DEFAULT_CONFIGS, UTILS } from '../sdk/src/index';

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

function separator(title: string): void {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log('─'.repeat(60));
}

function printJSON(label: string, value: unknown): void {
  console.log(`${label}:`);
  console.log(JSON.stringify(value, null, 2));
}

// ---------------------------------------------------------------------------
// Step 1 – Create DID
// ---------------------------------------------------------------------------

async function stepCreate(
  resolver: DIDResolver,
  keypair: Keypair
): Promise<string> {
  separator('Step 1: Create DID');

  const verificationMethods = [
    {
      id: '#key-1',
      type: 'Ed25519VerificationKey2020',
      controller: keypair.publicKey(),
      publicKey: Array.from(keypair.rawPublicKey() as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join(''),
    },
  ];

  const services = [
    {
      id: '#identity-hub',
      type: 'IdentityHub',
      endpoint: 'https://identity-hub.example.com',
    },
  ];

  console.log('Registering DID on Soroban testnet …');

  const did = await resolver.createDID(keypair, { verificationMethods, services });

  console.log(`Created DID: ${did}`);
  console.log(`  Address  : ${keypair.publicKey()}`);
  console.log(`  DID      : ${did}`);
  return did;
}

// ---------------------------------------------------------------------------
// Step 2 – Resolve DID
// ---------------------------------------------------------------------------

async function stepResolve(resolver: DIDResolver, did: string): Promise<void> {
  separator('Step 2: Resolve DID (W3C DID Resolution)');

  const result = await resolver.resolve(did);

  if (result.didResolutionMetadata.error) {
    console.error('Resolution error:', result.didResolutionMetadata.error);
    return;
  }

  printJSON('DID Document', result.didDocument);
  printJSON('Resolution Metadata', result.didResolutionMetadata);
  printJSON('Document Metadata', result.didDocumentMetadata);

  const isDeactivated = result.didDocumentMetadata.deactivated ?? false;
  console.log(`\nActive: ${!isDeactivated}`);
}

// ---------------------------------------------------------------------------
// Step 3 – Add Service Endpoint (Update)
// ---------------------------------------------------------------------------

async function stepAddService(
  resolver: DIDResolver,
  keypair: Keypair,
  did: string
): Promise<void> {
  separator('Step 3: Add Service Endpoint (LinkedIn profile)');

  await resolver.addService(
    keypair,
    did,
    'LinkedDomains',
    'https://www.linkedin.com/in/example-user',
    '#linkedin'
  );

  console.log('Added #linkedin service endpoint.');

  // Verify by re-resolving (cache is cleared by addService)
  const result = await resolver.resolve(did);
  const services = (result.didDocument as { service?: unknown[] }).service ?? [];
  console.log(`Services after update (${services.length} total):`);
  services.forEach((s: unknown) => {
    const svc = s as { id: string; type: string; endpoint: string };
    console.log(`  ${svc.id} [${svc.type}] → ${svc.endpoint}`);
  });
}

// ---------------------------------------------------------------------------
// Step 4 – Key Rotation
// ---------------------------------------------------------------------------

async function stepRotateKey(
  resolver: DIDResolver,
  keypair: Keypair,
  did: string
): Promise<Keypair> {
  separator('Step 4: Key Rotation (replace primary signing key)');

  const newKeypair = Keypair.random();
  console.log(`Old public key: ${keypair.publicKey()}`);
  console.log(`New public key: ${newKeypair.publicKey()}`);

  await resolver.updateVerificationMethod(
    keypair,
    did,
    'Ed25519VerificationKey2020',
    Array.from(newKeypair.rawPublicKey() as Uint8Array).map((b: number) => b.toString(16).padStart(2, '0')).join(''),
    0 // replace index 0 (primary key)
  );

  console.log('Key rotation complete.');

  // Confirm new key is on-chain
  const result = await resolver.resolve(did);
  const vms = (result.didDocument as { verificationMethod?: unknown[] }).verificationMethod ?? [];
  vms.forEach((vm: unknown, i: number) => {
    const v = vm as { id: string; type: string; publicKey: string };
    console.log(`  [${i}] ${v.id} (${v.type}) → ${v.publicKey.slice(0, 16)}…`);
  });

  return newKeypair;
}

// ---------------------------------------------------------------------------
// Step 5 – Dereference DID URL
// ---------------------------------------------------------------------------

async function stepDereference(resolver: DIDResolver, did: string): Promise<void> {
  separator('Step 5: Dereference DID URL Fragments');

  // Dereference a verification method
  const keyUrl = `${did}#key-1`;
  console.log(`Dereferencing: ${keyUrl}`);
  const keyResult = await resolver.dereference(keyUrl);
  if (keyResult.contentStream) {
    printJSON('Verification Method', keyResult.contentStream);
  } else {
    console.log('Fragment not found:', keyResult.dereferencingMetadata.message);
  }

  // Dereference a service
  const svcUrl = `${did}#linkedin`;
  console.log(`\nDereferencing: ${svcUrl}`);
  const svcResult = await resolver.dereference(svcUrl);
  if (svcResult.contentStream) {
    printJSON('Service Endpoint', svcResult.contentStream);
  } else {
    console.log('Fragment not found:', svcResult.dereferencingMetadata.message);
  }

  // Dereference by query parameter
  const queryUrl = `${did}?service=LinkedDomains`;
  console.log(`\nDereferencing: ${queryUrl}`);
  const qResult = await resolver.dereference(queryUrl);
  if (qResult.contentStream) {
    printJSON('Service (by query)', qResult.contentStream);
  }
}

// ---------------------------------------------------------------------------
// Step 6 – Verify Signature
// ---------------------------------------------------------------------------

async function stepVerifySignature(
  sdk: StellarIdentitySDK,
  keypair: Keypair,
  did: string
): Promise<void> {
  separator('Step 6: Verify Signature via DID Verification Key');

  // Simulate signing a message off-chain
  const messageText = 'Stellar DID signature verification demo';
  const message = new TextEncoder().encode(messageText);
  const signature = keypair.sign(message) as Uint8Array;

  console.log(`Message   : ${messageText}`);
  console.log(`Signature : ${Array.from(signature).map((b: number) => b.toString(16).padStart(2, '0')).join('').slice(0, 32)}…`);

  // The DID registry contract's verify_signature() would be called on-chain.
  // Here we demonstrate the equivalent off-chain using the resolved public key.
  const resolution = await sdk.did.resolveDID(did);
  const vm = resolution.didDocument.verificationMethod[0];

  if (vm) {
    const pubKeyBytes = Uint8Array.from(vm.publicKey.match(/.{2}/g)!.map((b: string) => parseInt(b, 16)));
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const isValid = Keypair.fromRawEd25519Seed(pubKeyBytes as any)
      .verify(message, signature);
    console.log(`Signature valid: ${isValid}`);
  } else {
    console.log('No verification method found to verify against.');
  }
}

// ---------------------------------------------------------------------------
// Step 7 – Deactivate DID (Tombstone)
// ---------------------------------------------------------------------------

async function stepDeactivate(
  sdk: StellarIdentitySDK,
  keypair: Keypair,
  did: string
): Promise<void> {
  separator('Step 7: Deactivate DID (soft-delete / tombstone)');

  console.log(`Submitting deactivate_did for ${did} …`);
  await sdk.did.deactivateDID(keypair);

  console.log('DID deactivated. The record is preserved on-chain for audit.');
}

// ---------------------------------------------------------------------------
// Step 8 – Post-deactivation Resolution
// ---------------------------------------------------------------------------

async function stepPostDeactivationResolve(
  resolver: DIDResolver,
  did: string
): Promise<void> {
  separator('Step 8: Post-deactivation Resolution');

  // Clear cache so we hit the chain
  resolver.clearCache();

  const result = await resolver.resolve(did);

  if (result.didResolutionMetadata.error) {
    // Some resolvers return notFound, but W3C spec allows returning the
    // tombstoned document with deactivated: true.
    console.log('Error from resolver:', result.didResolutionMetadata.error);
    return;
  }

  const deactivated = result.didDocumentMetadata.deactivated ?? false;
  console.log(`deactivated flag in document metadata: ${deactivated}`);
  printJSON('Tombstoned DID Document', result.didDocument);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log('did:stellar Lifecycle Demo');
  console.log('='.repeat(60));

  // ── Setup ──────────────────────────────────────────────────────────────
  const config = DEFAULT_CONFIGS.testnet;
  const sdk = new StellarIdentitySDK(config);
  const resolver = new DIDResolver(config);

  // Generate a fresh Stellar keypair for the demo
  const keypair = UTILS.generateKeypair() as Keypair;
  console.log(`\nGenerated controller keypair:`);
  console.log(`  Public key : ${keypair.publicKey()}`);
  console.log(`  (Fund this account at https://friendbot.stellar.org before running on testnet)`);

  let did: string;
  let activeKeypair = keypair;

  try {
    // ── Step 1: Create ────────────────────────────────────────────────────
    did = await stepCreate(resolver, activeKeypair);

    // ── Step 2: Resolve ───────────────────────────────────────────────────
    await stepResolve(resolver, did);

    // ── Step 3: Update (add service) ──────────────────────────────────────
    await stepAddService(resolver, activeKeypair, did);

    // ── Step 4: Key Rotation ──────────────────────────────────────────────
    activeKeypair = await stepRotateKey(resolver, activeKeypair, did);

    // ── Step 5: Dereference ───────────────────────────────────────────────
    await stepDereference(resolver, did);

    // ── Step 6: Verify Signature ──────────────────────────────────────────
    await stepVerifySignature(sdk, activeKeypair, did);

    // ── Step 7: Deactivate ────────────────────────────────────────────────
    await stepDeactivate(sdk, activeKeypair, did);

    // ── Step 8: Post-deactivation resolve ─────────────────────────────────
    await stepPostDeactivationResolve(resolver, did);

    separator('Lifecycle Complete');
    console.log('All steps completed successfully.');
    console.log(`Final DID: ${did}`);
  } catch (err: unknown) {
    throw new Error(`Lifecycle step failed: ${err instanceof Error ? err.message : String(err)}`);
  }
}

main();
