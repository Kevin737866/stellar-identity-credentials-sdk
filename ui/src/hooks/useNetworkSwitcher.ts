/**
 * React hook for network switching (#212).
 *
 * Wraps {@link StellarIdentitySDK.switchNetwork} with the state a UI needs:
 * which network is active, what is available while the switch is in flight, and
 * a clear error when it fails.
 *
 * ```tsx
 * function NetworkPicker() {
 *   const { network, networks, switching, error, switchTo } = useNetworkSwitcher(sdk);
 *   return (
 *     <select value={network} onChange={(e) => switchTo(e.target.value as StellarNetworkName)}>
 *       {networks.map((n) => <option key={n} value={n}>{n}</option>)}
 *     </select>
 *   );
 * }
 * ```
 *
 * This lives in the UI package rather than the SDK so the SDK core stays
 * React-free: the network data and the compat rules it needs are exported
 * from `@stellar-identity/sdk`, and only this thin React wrapper depends on
 * `react`.
 *
 * @module useNetworkSwitcher
 * @category Client
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  NETWORK_PRESETS,
  STELLAR_NETWORKS,
  isCanonicalNetwork,
  describeNetwork,
  mapContractError,
} from '@stellar-identity/sdk';
import type {
  StellarIdentitySDK,
  StellarNetworkName,
  StellarNetworkConfig,
  StellarIdentityError,
} from '@stellar-identity/sdk';

// ── Types ────────────────────────────────────────────────────────────────────

/** A network the caller may switch to, along with why it may not be. */
export interface NetworkOption {
  /** The network identifier. */
  name: string;
  /** Human-readable label, e.g. `testnet — test (soroban-testnet.stellar.org)`. */
  label: string;
  /** The resolved network configuration. */
  config: StellarNetworkConfig;
  /** `true` for mainnet, testnet, and futurenet. */
  isCanonical: boolean;
  /**
   * `true` when the network is currently active.
   */
  isActive: boolean;
}

/** Everything a UI needs to render a network picker. */
export interface UseNetworkSwitcherResult {
  /** The active network identifier, or `null` before the SDK is ready. */
  network: string | null;
  /** The active network's full configuration, when known. */
  config: StellarNetworkConfig | null;
  /** Human-readable description of the active network. */
  description: string | null;
  /** Every selectable network. */
  networks: NetworkOption[];
  /** `true` while a switch is in flight. Disable the control during this. */
  switching: boolean;
  /** The last switch error, cleared on the next successful switch. */
  error: StellarIdentityError | null;
  /**
   * Switch to a canonical network.
   *
   * Returns `true` on success. The previous network is restored if the switch
   * throws, so the caller is never left with a half-applied state.
   */
  switchTo: (network: StellarNetworkName, overrides?: Partial<Parameters<StellarIdentitySDK['switchNetwork']>[1]>) => Promise<boolean>;
  /**
   * Add a custom network to the picker's list.
   *
   * Custom networks are not switched to via `switchNetwork` (which takes a
   * canonical name); construct an SDK instance for them instead. This exists so
   * a UI can still *display* them alongside the canonical ones.
   */
  registerCustomNetwork: (config: StellarNetworkConfig) => void;
  /** Re-read the active network from the SDK. */
  refresh: () => void;
}

// ── Hook ─────────────────────────────────────────────────────────────────────

/**
 * Network switching for a {@link StellarIdentitySDK} instance.
 *
 * @param sdk - The SDK to switch. Pass `null` while it is still initialising;
 *   the hook stays inert until a real instance arrives.
 *
 * @category Client
 */
export function useNetworkSwitcher(
  sdk: StellarIdentitySDK | null | undefined,
  options: { initialNetwork?: StellarNetworkName } = {},
): UseNetworkSwitcherResult {
  const [network, setNetwork] = useState<string | null>(
    options.initialNetwork ?? null,
  );
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<StellarIdentityError | null>(null);
  const [customNetworks, setCustomNetworks] = useState<StellarNetworkConfig[]>([]);
  const [tick, setTick] = useState(0);

  // Read the active network from the SDK whenever it changes. `tick` is
  // included so `refresh()` can force a re-read, since the SDK exposes no
  // network-change event.
  useEffect(() => {
    if (!sdk) return;
    try {
      const current = sdk.getConfig().network;
      if (typeof current === 'string' && current.length > 0) {
        setNetwork(current);
      }
    } catch {
      // A missing accessor should not take the picker down; the user can
      // still switch, and the state will correct itself on the next switch.
    }
  }, [sdk, tick]);

  const refresh = useCallback(() => setTick((t) => t + 1), []);

  const switchTo = useCallback(
    async (
      target: StellarNetworkName,
      overrides?: Partial<Parameters<StellarIdentitySDK['switchNetwork']>[1]>,
    ): Promise<boolean> => {
      if (!sdk) {
        setError(
          mapContractError(
            new Error('SDK is not initialised yet; wait for it before switching networks'),
          ),
        );
        return false;
      }
      if (!isCanonicalNetwork(target)) {
        setError(
          mapContractError(
            new Error(
              `"${target}" is not a canonical Stellar network. ` +
                'Construct a separate SDK instance with an explicit passphrase for custom networks.',
            ),
          ),
        );
        return false;
      }

      const previous = network;
      setSwitching(true);
      setError(null);
      try {
        sdk.switchNetwork(target, overrides);
        setNetwork(target);
        return true;
      } catch (err) {
        // switchNetwork mutates before it validates, so on failure the SDK may
        // be pointing at the new network already. Restore the previous one so
        // the UI and the SDK cannot disagree about where writes are going.
        if (previous && isCanonicalNetwork(previous)) {
          try {
            sdk.switchNetwork(previous);
            setNetwork(previous);
          } catch {
            // Restoring also failed; the surfaced error below is the useful one.
          }
        }
        setError(mapContractError(err));
        return false;
      } finally {
        setSwitching(false);
      }
    },
    [sdk, network],
  );

  const registerCustomNetwork = useCallback((config: StellarNetworkConfig) => {
    setCustomNetworks((prev: StellarNetworkConfig[]) =>
      prev.some((n: StellarNetworkConfig) => n.name === config.name) ? prev : [...prev, config],
    );
  }, []);

  const networks = useMemo<NetworkOption[]>(() => {
    const options: NetworkOption[] = STELLAR_NETWORKS.map((name: StellarNetworkName) => {
      const config = NETWORK_PRESETS[name];
      return {
        name,
        label: describeNetwork(config),
        config,
        isCanonical: true,
        isActive: network === name,
      };
    });
    for (const config of customNetworks) {
      options.push({
        name: config.name,
        label: describeNetwork(config),
        config,
        isCanonical: false,
        isActive: network === config.name,
      });
    }
    return options;
  }, [network, customNetworks]);

  const config = useMemo<StellarNetworkConfig | null>(() => {
    if (!network) return null;
    return networks.find((n) => n.name === network)?.config ?? null;
  }, [network, networks]);

  return {
    network,
    config,
    description: config ? describeNetwork(config) : null,
    networks,
    switching,
    error,
    switchTo,
    registerCustomNetwork,
    refresh,
  };
}
