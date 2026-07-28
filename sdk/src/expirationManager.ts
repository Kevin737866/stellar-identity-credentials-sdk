import {
  StellarIdentityConfig,
  VerifiableCredential,
  ExpirationEvent,
  ExpirationHandler,
  EventListener,
} from './types';
import { CredentialClient } from './credentialClient';
import { CacheManager, DataType } from './cacheManager';

export const DEFAULT_POLLING_INTERVAL_MS = 60 * 60 * 1000;

export class ExpirationManager implements EventListener {
  private credentialClient: CredentialClient;
  private cache: CacheManager;
  private handlers: Map<string, Set<(...args: any[]) => void>> = new Map();
  private pollingTimer: ReturnType<typeof setInterval> | null = null;
  private pollingIntervalMs: number;

  constructor(
    credentialClient: CredentialClient,
    pollingIntervalMs: number = DEFAULT_POLLING_INTERVAL_MS,
  ) {
    this.credentialClient = credentialClient;
    this.pollingIntervalMs = pollingIntervalMs;
    this.cache = new CacheManager();
  }

  on(event: string, handler: (...args: any[]) => void): void {
    if (!this.handlers.has(event)) {
      this.handlers.set(event, new Set());
    }
    this.handlers.get(event)!.add(handler);
  }

  off(event: string, handler: (...args: any[]) => void): void {
    const handlers = this.handlers.get(event);
    if (handlers) {
      handlers.delete(handler);
      if (handlers.size === 0) {
        this.handlers.delete(event);
      }
    }
  }

  onExpiration(handler: ExpirationHandler): void {
    this.on('expiration', handler as (...args: any[]) => void);
  }

  startPolling(): void {
    if (this.pollingTimer) return;

    this.pollingTimer = setInterval(async () => {
      try {
        await this.checkAndEmit();
      } catch {
      }
    }, this.pollingIntervalMs);
  }

  stopPolling(): void {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }

  setPollingInterval(intervalMs: number): void {
    this.pollingIntervalMs = intervalMs;
    if (this.pollingTimer) {
      this.stopPolling();
      this.startPolling();
    }
  }

  async checkExpiringCredentials(windowInDays: number): Promise<VerifiableCredential[]> {
    const cacheKey = `expiring_${windowInDays}`;
    const cached = this.cache.get<VerifiableCredential[]>(DataType.CREDENTIAL_STATUS, cacheKey);
    if (cached) return cached;

    const now = Date.now();
    const windowMs = windowInDays * 24 * 60 * 60 * 1000;
    const threshold = now + windowMs;

    const allCredentials = await this.fetchAllCredentials();
    const expiring = allCredentials.filter(cred => {
      if (!cred.expirationDate) return false;
      return cred.expirationDate <= threshold;
    });

    this.cache.set(DataType.CREDENTIAL_STATUS, cacheKey, expiring);
    return expiring;
  }

  async getExpiredCredentials(address: string): Promise<VerifiableCredential[]> {
    const cacheKey = `expired_${address}`;
    const cached = this.cache.get<VerifiableCredential[]>(DataType.CREDENTIAL_STATUS, cacheKey);
    if (cached) return cached;

    const now = Date.now();
    const credentialIds = await this.credentialClient.getSubjectCredentials(address);
    const credentials = await Promise.all(
      credentialIds.map(id => this.credentialClient.getCredential(id).catch(() => null)),
    );

    const expired = credentials.filter((cred): cred is VerifiableCredential => {
      if (!cred) return false;
      if (!cred.expirationDate) return false;
      return cred.expirationDate <= now;
    });

    this.cache.set(DataType.CREDENTIAL_STATUS, cacheKey, expired);
    return expired;
  }

  private async checkAndEmit(): Promise<void> {
    const expiringCredentials = await this.checkExpiringCredentials(30);
    const now = Date.now();

    for (const cred of expiringCredentials) {
      if (!cred.expirationDate) continue;

      const daysUntilExpiry = Math.max(0, Math.floor(
        (cred.expirationDate - now) / (1000 * 60 * 60 * 24),
      ));

      const event: ExpirationEvent = {
        credentialId: cred.id,
        subject: cred.subject,
        issuer: cred.issuer,
        expirationDate: cred.expirationDate,
        daysUntilExpiry,
        expired: daysUntilExpiry <= 0,
        timestamp: now,
      };

      this.emit('expiration', event);
    }

    this.emit('checkComplete', { timestamp: now, checked: expiringCredentials.length });
  }

  private emit(event: string, ...args: any[]): void {
    const handlers = this.handlers.get(event);
    if (handlers) {
      for (const handler of handlers) {
        try {
          handler(...args);
        } catch {
        }
      }
    }
  }

  private async fetchAllCredentials(): Promise<VerifiableCredential[]> {
    return [];
  }
}
