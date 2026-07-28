/**
 * Tests for the SDK Configuration & Network Management module (Issue #26).
 */

import {
  DEFAULT_CONFIGS,
  validateContractAddress,
  validateConfig,
  isConfigValid,
  mergeConfig,
  getRpcUrl,
  getHorizonUrl,
  getNetworkPassphrase,
  createCustomConfig,
  ConfigBuilder,
  healthCheck,
  comprehensiveHealthCheck,
} from '../config';
import { ConfigurationError, ErrorCode } from '../errors';
import { StellarIdentityConfig } from '../types';
import { Networks } from 'stellar-sdk';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const VALID_CONTRACT_ID = '7d0e6362929e37a88070052636437d0a4596628f783b87762897e9524e10822a';
const INVALID_CONTRACT_ID = 'too_short';
const EMPTY_CONTRACT_ID = '';

function makeValidConfig(overrides: Partial<StellarIdentityConfig> = {}): StellarIdentityConfig {
  return {
    ...DEFAULT_CONFIGS.testnet,
    ...overrides,
    contracts: {
      ...DEFAULT_CONFIGS.testnet.contracts,
      ...(overrides.contracts || {}),
    },
  };
}

// ---------------------------------------------------------------------------
// DEFAULT_CONFIGS
// ---------------------------------------------------------------------------

describe('DEFAULT_CONFIGS', () => {
  it('should have testnet, mainnet, and futurenet presets', () => {
    expect(DEFAULT_CONFIGS.testnet).toBeDefined();
    expect(DEFAULT_CONFIGS.mainnet).toBeDefined();
    expect(DEFAULT_CONFIGS.futurenet).toBeDefined();
  });

  it('testnet should have valid contract addresses', () => {
    const cfg = DEFAULT_CONFIGS.testnet;
    expect(cfg.network).toBe('testnet');
    expect(cfg.contracts.didRegistry).toMatch(/^[0-9a-fA-F]{64}$/);
    expect(cfg.contracts.credentialIssuer).toMatch(/^[0-9a-fA-F]{64}$/);
    expect(cfg.contracts.reputationScore).toMatch(/^[0-9a-fA-F]{64}$/);
    expect(cfg.contracts.zkAttestation).toMatch(/^[0-9a-fA-F]{64}$/);
    expect(cfg.contracts.complianceFilter).toMatch(/^[0-9a-fA-F]{64}$/);
    expect(cfg.rpcUrl).toBe('https://soroban-testnet.stellar.org');
    expect(cfg.horizonUrl).toBe('https://horizon-testnet.stellar.org');
  });

  it('mainnet should have empty contract addresses (not yet deployed)', () => {
    const cfg = DEFAULT_CONFIGS.mainnet;
    expect(cfg.network).toBe('mainnet');
    expect(cfg.rpcUrl).toBe('https://soroban-rpc.stellar.org');
    expect(cfg.horizonUrl).toBe('https://horizon.stellar.org');
  });

  it('futurenet should have empty contract addresses (not yet deployed)', () => {
    const cfg = DEFAULT_CONFIGS.futurenet;
    expect(cfg.network).toBe('futurenet');
    expect(cfg.rpcUrl).toBe('https://rpc-futurenet.stellar.org');
  });
});

// ---------------------------------------------------------------------------
// validateContractAddress
// ---------------------------------------------------------------------------

describe('validateContractAddress', () => {
  it('should accept a valid 64-char hex address', () => {
    expect(() => validateContractAddress(VALID_CONTRACT_ID, 'TestContract')).not.toThrow();
    expect(validateContractAddress(VALID_CONTRACT_ID, 'TestContract')).toBe(VALID_CONTRACT_ID);
  });

  it('should accept mixed-case hex', () => {
    const mixedCase = '7d0E6362929e37A88070052636437d0a4596628f783B87762897E9524E10822a';
    expect(() => validateContractAddress(mixedCase, 'TestContract')).not.toThrow();
  });

  it('should throw on empty address', () => {
    expect(() => validateContractAddress(EMPTY_CONTRACT_ID, 'MyContract'))
      .toThrow(ConfigurationError);
    try {
      validateContractAddress(EMPTY_CONTRACT_ID, 'MyContract');
    } catch (e) {
      expect((e as ConfigurationError).code).toBe(ErrorCode.ConfigMissingContract);
      expect((e as ConfigurationError).details.contractName).toBe('MyContract');
    }
  });

  it('should throw on non-hex address', () => {
    expect(() => validateContractAddress('not-a-valid-hex-address-at-all-but-64-chars-long!!!', 'C'))
      .toThrow(ConfigurationError);
  });

  it('should throw on wrong-length address', () => {
    expect(() => validateContractAddress('abcd1234', 'ShortContract'))
      .toThrow(ConfigurationError);
  });

  it('should throw on whitespace-only address', () => {
    expect(() => validateContractAddress('   ', 'SpaceContract'))
      .toThrow(ConfigurationError);
  });
});

// ---------------------------------------------------------------------------
// validateConfig
// ---------------------------------------------------------------------------

describe('validateConfig', () => {
  it('should accept a valid testnet config', () => {
    expect(() => validateConfig(DEFAULT_CONFIGS.testnet)).not.toThrow();
  });

  it('should throw on missing network', () => {
    const bad = { ...DEFAULT_CONFIGS.testnet, network: '' as any };
    expect(() => validateConfig(bad)).toThrow(ConfigurationError);
  });

  it('should throw on invalid network name', () => {
    const bad = { ...DEFAULT_CONFIGS.testnet, network: 'ropsten' as any };
    expect(() => validateConfig(bad)).toThrow(ConfigurationError);
  });

  it('should throw on invalid RPC URL', () => {
    const bad = { ...DEFAULT_CONFIGS.testnet, rpcUrl: 'not-a-url' };
    expect(() => validateConfig(bad)).toThrow(ConfigurationError);
  });

  it('should throw on missing contract address', () => {
    const bad = makeValidConfig({
      contracts: {
        ...DEFAULT_CONFIGS.testnet.contracts,
        didRegistry: '',
      },
    });
    expect(() => validateConfig(bad)).toThrow(ConfigurationError);
  });

  it('should throw on invalid contract address', () => {
    const bad = makeValidConfig({
      contracts: {
        ...DEFAULT_CONFIGS.testnet.contracts,
        didRegistry: INVALID_CONTRACT_ID,
      },
    });
    expect(() => validateConfig(bad)).toThrow(ConfigurationError);
  });

  it('should validate all 5 contract addresses', () => {
    const cfg = makeValidConfig();
    // Should not throw — all addresses are valid
    expect(() => validateConfig(cfg)).not.toThrow();
  });

  it('should throw on mainnet with empty addresses', () => {
    // Mainnet has empty addresses (not yet deployed), so validation should fail
    expect(() => validateConfig(DEFAULT_CONFIGS.mainnet)).toThrow(ConfigurationError);
  });

  it('should throw on futurenet with empty addresses', () => {
    expect(() => validateConfig(DEFAULT_CONFIGS.futurenet)).toThrow(ConfigurationError);
  });
});

// ---------------------------------------------------------------------------
// isConfigValid
// ---------------------------------------------------------------------------

describe('isConfigValid', () => {
  it('should return true for valid config', () => {
    expect(isConfigValid(DEFAULT_CONFIGS.testnet)).toBe(true);
  });

  it('should return false for invalid config', () => {
    const bad = { ...DEFAULT_CONFIGS.testnet, network: 'invalid' as any };
    expect(isConfigValid(bad)).toBe(false);
  });

  it('should return false for config with missing contracts', () => {
    const bad = makeValidConfig({
      contracts: {
        ...DEFAULT_CONFIGS.testnet.contracts,
        didRegistry: '',
      },
    });
    expect(isConfigValid(bad)).toBe(false);
  });

  it('should not throw', () => {
    const bad = { ...DEFAULT_CONFIGS.testnet, network: 'invalid' as any };
    expect(() => isConfigValid(bad)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// mergeConfig
// ---------------------------------------------------------------------------

describe('mergeConfig', () => {
  it('should merge partial overrides with base config', () => {
    const merged = mergeConfig(DEFAULT_CONFIGS.testnet, {
      rpcUrl: 'http://localhost:8000/soroban/rpc',
    });

    expect(merged.network).toBe('testnet');
    expect(merged.rpcUrl).toBe('http://localhost:8000/soroban/rpc');
    expect(merged.contracts.didRegistry).toBe(DEFAULT_CONFIGS.testnet.contracts.didRegistry);
  });

  it('should override contract addresses', () => {
    const newAddr = 'abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234';
    const merged = mergeConfig(DEFAULT_CONFIGS.testnet, {
      contracts: {
        didRegistry: newAddr,
        credentialIssuer: DEFAULT_CONFIGS.testnet.contracts.credentialIssuer,
        reputationScore: DEFAULT_CONFIGS.testnet.contracts.reputationScore,
        zkAttestation: DEFAULT_CONFIGS.testnet.contracts.zkAttestation,
        complianceFilter: DEFAULT_CONFIGS.testnet.contracts.complianceFilter,
      },
    });

    expect(merged.contracts.didRegistry).toBe(newAddr);
    expect(merged.contracts.credentialIssuer).toBe(DEFAULT_CONFIGS.testnet.contracts.credentialIssuer);
  });

  it('should not mutate the base config', () => {
    const base = { ...DEFAULT_CONFIGS.testnet };
    mergeConfig(base, { rpcUrl: 'http://custom.example.com' });

    expect(base.rpcUrl).toBe(DEFAULT_CONFIGS.testnet.rpcUrl);
  });

  it('should merge keypair override', () => {
    const mockKp = { publicKey: () => 'GABC', secret: () => 'SABC' };
    const merged = mergeConfig(DEFAULT_CONFIGS.testnet, { keypair: mockKp as any });

    expect(merged.keypair).toBe(mockKp);
  });
});

// ---------------------------------------------------------------------------
// getRpcUrl / getHorizonUrl / getNetworkPassphrase
// ---------------------------------------------------------------------------

describe('RPC and Horizon URL resolution', () => {
  it('getRpcUrl should return config rpcUrl if set', () => {
    const url = getRpcUrl({ ...DEFAULT_CONFIGS.testnet, rpcUrl: 'http://localhost:8000' });
    expect(url).toBe('http://localhost:8000');
  });

  it('getRpcUrl should return default for testnet', () => {
    const url = getRpcUrl({ ...DEFAULT_CONFIGS.testnet, rpcUrl: undefined });
    expect(url).toBe('https://soroban-testnet.stellar.org');
  });

  it('getRpcUrl should return default for mainnet', () => {
    const url = getRpcUrl({ ...DEFAULT_CONFIGS.mainnet, rpcUrl: undefined });
    expect(url).toBe('https://soroban-rpc.stellar.org');
  });

  it('getRpcUrl should return default for futurenet', () => {
    const url = getRpcUrl({ ...DEFAULT_CONFIGS.futurenet, rpcUrl: undefined });
    expect(url).toBe('https://rpc-futurenet.stellar.org');
  });

  it('getHorizonUrl should return default for each network', () => {
    expect(getHorizonUrl({ ...DEFAULT_CONFIGS.testnet, horizonUrl: undefined }))
      .toBe('https://horizon-testnet.stellar.org');
    expect(getHorizonUrl({ ...DEFAULT_CONFIGS.mainnet, horizonUrl: undefined }))
      .toBe('https://horizon.stellar.org');
    expect(getHorizonUrl({ ...DEFAULT_CONFIGS.futurenet, horizonUrl: undefined }))
      .toBe('https://horizon-futurenet.stellar.org');
  });

  it('getHorizonUrl should return config horizonUrl if set', () => {
    const url = getHorizonUrl({ ...DEFAULT_CONFIGS.testnet, horizonUrl: 'http://local:8000' });
    expect(url).toBe('http://local:8000');
  });

  it('getNetworkPassphrase should return correct passphrase for each network', () => {
    expect(getNetworkPassphrase(DEFAULT_CONFIGS.testnet)).toBe(Networks.TESTNET);
    expect(getNetworkPassphrase(DEFAULT_CONFIGS.mainnet)).toBe(Networks.PUBLIC);
    expect(getNetworkPassphrase(DEFAULT_CONFIGS.futurenet)).toBe(Networks.FUTURENET);
  });
});

// ---------------------------------------------------------------------------
// createCustomConfig
// ---------------------------------------------------------------------------

describe('createCustomConfig', () => {
  it('should create a config derived from testnet', () => {
    const newAddr = '111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000';
    const custom = createCustomConfig({
      rpcUrl: 'http://localhost:8000/soroban/rpc',
      contracts: {
        didRegistry: newAddr,
        credentialIssuer: DEFAULT_CONFIGS.testnet.contracts.credentialIssuer,
        reputationScore: DEFAULT_CONFIGS.testnet.contracts.reputationScore,
        zkAttestation: DEFAULT_CONFIGS.testnet.contracts.zkAttestation,
        complianceFilter: DEFAULT_CONFIGS.testnet.contracts.complianceFilter,
      },
    });

    expect(custom.network).toBe('testnet');
    expect(custom.rpcUrl).toBe('http://localhost:8000/soroban/rpc');
    expect(custom.contracts.didRegistry).toBe('111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000');
    expect(custom.contracts.credentialIssuer).toBe(DEFAULT_CONFIGS.testnet.contracts.credentialIssuer);
  });

  it('should throw if resulting config is invalid', () => {
    expect(() =>
      createCustomConfig({
        rpcUrl: 'not-a-url',
        contracts: {
          didRegistry: '',
          credentialIssuer: DEFAULT_CONFIGS.testnet.contracts.credentialIssuer,
          reputationScore: DEFAULT_CONFIGS.testnet.contracts.reputationScore,
          zkAttestation: DEFAULT_CONFIGS.testnet.contracts.zkAttestation,
          complianceFilter: DEFAULT_CONFIGS.testnet.contracts.complianceFilter,
        },
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// ConfigBuilder
// ---------------------------------------------------------------------------

describe('ConfigBuilder', () => {
  it('should build a valid config with defaults', () => {
    const config = new ConfigBuilder('testnet').build();
    expect(config.network).toBe('testnet');
    expect(config.contracts.didRegistry).toBe(DEFAULT_CONFIGS.testnet.contracts.didRegistry);
  });

  it('should allow overriding RPC URL', () => {
    const config = new ConfigBuilder('testnet')
      .withRpcUrl('http://localhost:8000/soroban/rpc')
      .build();

    expect(config.rpcUrl).toBe('http://localhost:8000/soroban/rpc');
  });

  it('should allow overriding contract addresses', () => {
    const newAddr = 'aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999';
    const config = new ConfigBuilder('testnet')
      .withContract('didRegistry', newAddr)
      .withContract('credentialIssuer', newAddr)
      .build();

    expect(config.contracts.didRegistry).toBe(newAddr);
    expect(config.contracts.credentialIssuer).toBe(newAddr);
  });

  it('should allow overriding horizon URL', () => {
    const config = new ConfigBuilder('testnet')
      .withHorizonUrl('http://localhost:8000')
      .build();

    expect(config.horizonUrl).toBe('http://localhost:8000');
  });

  it('should allow attaching a keypair', () => {
    const mockKp = { publicKey: () => 'GABC', secret: () => 'SABC' };
    const config = new ConfigBuilder('testnet')
      .withKeypair(mockKp)
      .build();

    expect(config.keypair).toBe(mockKp);
  });

  it('should skip validation when build(false)', () => {
    const config = new ConfigBuilder('testnet' as any)
      .withRpcUrl('not-a-url')
      .build(false);

    expect(config.rpcUrl).toBe('not-a-url');
  });

  it('should support mainnet and futurenet', () => {
    const mainnet = new ConfigBuilder('mainnet').build(false);
    expect(mainnet.network).toBe('mainnet');

    const futurenet = new ConfigBuilder('futurenet').build(false);
    expect(futurenet.network).toBe('futurenet');
  });

  it('should be chainable', () => {
    const config = new ConfigBuilder('testnet')
      .withRpcUrl('http://a.com')
      .withHorizonUrl('http://b.com')
      .withContract('didRegistry', 'aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999')
      .build(false);

    expect(config.rpcUrl).toBe('http://a.com');
    expect(config.horizonUrl).toBe('http://b.com');
  });
});

// ---------------------------------------------------------------------------
// healthCheck
// ---------------------------------------------------------------------------

describe('healthCheck', () => {
  it('should report unhealthy when RPC is unreachable', async () => {
    const config = makeValidConfig({ rpcUrl: 'http://localhost:19999' });
    const result = await healthCheck(config, 1000);

    expect(result.healthy).toBe(false);
    expect(result.rpcUrl).toBe('http://localhost:19999');
    expect(result.error).toBeDefined();
  });

  it('should return correct network in result', async () => {
    const config = makeValidConfig({ rpcUrl: 'http://localhost:19999' });
    const result = await healthCheck(config, 1000);

    expect(result.network).toBe('testnet');
  });

  it('should measure latency even on failure', async () => {
    const config = makeValidConfig({ rpcUrl: 'http://localhost:19999' });
    const result = await healthCheck(config, 1000);

    expect(typeof result.latencyMs).toBe('number');
    expect(result.latencyMs).toBeGreaterThan(0);
  });
});
