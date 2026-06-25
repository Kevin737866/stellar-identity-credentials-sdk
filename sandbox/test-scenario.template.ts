import { SorobanSandbox, MockDataGenerator, AssertionHelper } from './index';

describe('Sandbox Test Scenario', () => {
  let sandbox: SorobanSandbox;

  beforeAll(async () => {
    // Connect to the local docker sandbox
    sandbox = new SorobanSandbox('http://localhost:8000/soroban/rpc');
    await sandbox.initialize();
  });

  afterAll(async () => {
    await sandbox.teardown();
  });

  it('should verify a verifiable credential successfully', async () => {
    // 1. Generate Mock Data
    const issuerKeypair = MockDataGenerator.generateKeypair();
    const subjectDID = MockDataGenerator.generateDID();
    const mockCredential = MockDataGenerator.generateVerifiableCredential(issuerKeypair.publicKey(), subjectDID);

    // 2. Deploy Contract (example)
    const contractId = await sandbox.deployContract('path/to/stellar_identity.wasm');

    // 3. Interact with Contract (simulation)
    const result = await sandbox.invokeContract(contractId, 'verify_credential', [mockCredential]);

    // 4. Assert correctness
    AssertionHelper.assertSuccess(result);
  });
});
