import { Keypair } from 'stellar-sdk';
import {
  CreateDIDOptions,
  IssueCredentialOptions,
  StellarIdentityConfig,
  TransactionOptions,
  CredentialVerificationResult,
} from './types';
import { DIDClient } from './didClient';
import { CredentialClient } from './credentialClient';
import { Logger } from './logger';
import { ValidationError, ErrorCode } from './errors';

// ── Constants ─────────────────────────────────────────────────────────────────

/**
 * Maximum items per on-chain batch. Mirrors `MAX_BATCH_SIZE` in the Soroban
 * contracts (`credential_issuer.rs` and `compliance_filter.rs`), which reject
 * oversized batches with `CredentialIssuerError::InvalidCredential` /
 * `ComplianceFilterError::BatchTooLarge`.
 */
export const MAX_CONTRACT_BATCH_SIZE = 50;

/** Items processed per page by default. */
export const DEFAULT_PAGE_SIZE = 25;

/** Sequential pages issued per batch chunk before yielding to the event loop. */
const DEFAULT_CONCURRENCY = 3;

// ── Types ─────────────────────────────────────────────────────────────────────

/** A single unit of work inside a batch. Generic so callers keep their own types. */
export interface BatchItem<TInput = unknown, TOutput = unknown> {
  /** Stable key used for progress reporting and optimistic rollback. */
  key: string;
  input: TInput;
  /** Filled in on success; `undefined` when the item failed. */
  output?: TOutput;
  /** Populated when this individual item failed. */
  error?: Error;
}

/** Aggregated result of a single batch operation. */
export interface BatchResult<TOutput = unknown> {
  items: BatchItem<unknown, TOutput>[];
  succeeded: BatchItem<unknown, TOutput>[];
  failed: BatchItem<unknown, TOutput>[];
  /** Number of on-chain chunks the input was split into. */
  pageCount: number;
  totalDurationMs: number;
}

/** Progress event emitted as a batch advances. */
export interface BatchProgress {
  operation: string;
  /** Items finished so far (succeeded + failed). */
  completed: number;
  total: number;
  /** Zero-based index of the page currently in flight. */
  pageIndex: number;
  pageCount: number;
  /** Fraction complete in the range [0, 1]. */
  fraction: number;
  /** Item that just settled, if any. */
  lastItem?: BatchItem<unknown, unknown>;
}

export type BatchProgressCallback = (progress: BatchProgress) => void;

/**
 * Optimistic UI hook. `apply` is invoked before the item runs so the caller can
 * render a provisional state; `rollback` is invoked if the item later fails.
 */
export interface OptimisticHooks<TInput = unknown, TOutput = unknown> {
  apply?: (item: BatchItem<TInput, TOutput>) => void;
  rollback?: (item: BatchItem<TInput, TOutput>, error: Error) => void;
  commit?: (item: BatchItem<TInput, TOutput>) => void;
}

export interface BatchOptions<TInput = unknown, TOutput = unknown> {
  /**
   * Items per on-chain page. Automatically capped at
   * {@link MAX_CONTRACT_BATCH_SIZE}.
   */
  pageSize?: number;
  /** Pages submitted concurrently. Default 3. */
  concurrency?: number;
  /** Called after every settled item. */
  onProgress?: BatchProgressCallback;
  /** Optimistic apply/rollback integration for optimistic UIs. */
  optimistic?: OptimisticHooks<TInput, TOutput>;
  /**
   * When true (default) a failing item does not abort the batch. Set to false
   * to stop after the first failure and reject with the first error.
   */
  continueOnError?: boolean;
  /** Transaction parameters forwarded to the underlying single-item calls. */
  txOptions?: TransactionOptions;
}

export interface BatchDIDRequest {
  keypair: Keypair;
  options: CreateDIDOptions;
}

export interface BatchIssueRequest {
  issuerKeypair: Keypair;
  options: IssueCredentialOptions;
}

// ── Internals ─────────────────────────────────────────────────────────────────

/** Split `items` into fixed-size pages, the last one possibly short. */
export function paginate<T>(items: T[], pageSize: number): T[][] {
  if (pageSize <= 0) {
    throw new ValidationError(
      ErrorCode.ValidationMissingField,
      `pageSize must be greater than 0, received ${pageSize}`,
    );
  }
  const pages: T[][] = [];
  for (let i = 0; i < items.length; i += pageSize) {
    pages.push(items.slice(i, i + pageSize));
  }
  return pages;
}

function toError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

/**
 * Run `worker` over a page of items with a bounded number of in-flight
 * promises, invoking `onSettled` after each item regardless of outcome.
 */
async function runPage<TIn, TOut>(
  page: BatchItem<TIn, TOut>[],
  concurrency: number,
  worker: (item: BatchItem<TIn, TOut>) => Promise<TOut>,
  onSettled: (item: BatchItem<TIn, TOut>) => void,
): Promise<void> {
  let cursor = 0;

  const runNext = async (): Promise<void> => {
    while (cursor < page.length) {
      const item = page[cursor++];
      try {
        item.output = await worker(item);
      } catch (err) {
        item.error = toError(err);
      }
      onSettled(item);
    }
  };

  const lanes = Math.max(1, Math.min(concurrency, page.length));
  await Promise.all(Array.from({ length: lanes }, runNext));
}

// ── Client ────────────────────────────────────────────────────────────────────

/**
 * Batch operations mirroring the Soroban contract batch functions.
 *
 * The contracts expose `batch_issue_credentials`, `batch_verify_credentials` and
 * `batch_revoke_credentials`; this client adds the ergonomics a UI needs on top
 * of them: automatic pagination, progress reporting and optimistic updates with
 * rollback.
 *
 * @example
 * ```typescript
 * const batch = new BatchClient(config);
 * const result = await batch.issueCredentials(requests, {
 *   pageSize: 25,
 *   onProgress: p => setProgress(p.fraction),
 * });
 * ```
 *
 * @category Client
 */
export class BatchClient {
  private didClient: DIDClient;
  private credentialClient: CredentialClient;
  private logger: Logger;
  private config: StellarIdentityConfig;

  constructor(
    config: StellarIdentityConfig,
    deps?: { didClient?: DIDClient; credentialClient?: CredentialClient },
  ) {
    this.config = config;
    this.didClient = deps?.didClient ?? new DIDClient(config);
    this.credentialClient = deps?.credentialClient ?? new CredentialClient(config);
    this.logger = new Logger('BatchClient');
  }

  /**
   * Create many DIDs, one per entry, paginated to respect the contract limit.
   *
   * @param requests - Keypair plus DID options for each DID to create.
   * @param options - Pagination, progress and optimistic-update options.
   * @returns Per-item results including any individual failures.
   */
  async createDIDs<T extends BatchDIDRequest>(
    requests: T[],
    options: BatchOptions<BatchDIDRequest, string> = {},
  ): Promise<BatchResult<string>> {
    return this.execute<BatchDIDRequest, string>(
      'batchCreateDIDs',
      requests,
      options,
      request => this.didClient.createDID(
        request.input.keypair,
        request.input.options,
        options.txOptions,
      ),
    );
  }

  /**
   * Issue many credentials, paginated to respect `MAX_BATCH_SIZE`.
   *
   * @param requests - Issuer keypair plus credential options per issuance.
   * @param options - Pagination, progress and optimistic-update options.
   * @returns Per-item credential IDs, in the order of the input.
   */
  async issueCredentials<T extends BatchIssueRequest>(
    requests: T[],
    options: BatchOptions<BatchIssueRequest, string> = {},
  ): Promise<BatchResult<string>> {
    return this.execute<BatchIssueRequest, string>(
      'batchIssueCredentials',
      requests,
      options,
      request => this.credentialClient.issueCredential(
        request.input.issuerKeypair,
        request.input.options,
        options.txOptions,
      ),
    );
  }

  /**
   * Verify many credentials.
   *
   * Verification is read-only, so it is chunked for progress reporting rather
   * than for on-chain limits.
   *
   * @param credentialIds - Credential identifiers to verify.
   * @param options - Pagination, progress and optimistic-update options.
   * @returns Per-item verification results.
   */
  async verifyCredentials<T = string>(
    credentialIds: T[],
    options: BatchOptions<T, CredentialVerificationResult> = {},
  ): Promise<BatchResult<CredentialVerificationResult>> {
    const items: BatchItem<T, CredentialVerificationResult>[] = credentialIds.map(
      (id, index) => ({ key: String(id ?? index), input: id }),
    );

    return this.execute<T, CredentialVerificationResult>(
      'batchVerifyCredentials',
      items,
      options,
      item => this.credentialClient.verifyCredential(String(item.input)),
    );
  }

  /**
   * Revoke many credentials, paginated to the contract batch limit.
   *
   * @param requests - Issuer keypair, credential ID and optional reason.
   * @param options - Pagination, progress and optimistic-update options.
   */
  async revokeCredentials<T extends { issuerKeypair: Keypair; credentialId: string; reason?: string }>(
    requests: T[],
    options: BatchOptions<T, void> = {},
  ): Promise<BatchResult<void>> {
    return this.execute<T, void>(
      'batchRevokeCredentials',
      requests,
      options,
      async request => {
        await this.credentialClient.revokeCredential(
          request.input.issuerKeypair,
          request.input.credentialId,
          request.input.reason,
          options.txOptions,
        );
      },
    );
  }

  /**
   * Core batch runner: paginate, apply optimistic state, execute pages with
   * bounded concurrency, report progress and roll back failures.
   */
  private async execute<TIn, TOut>(
    operation: string,
    input: Array<TIn | BatchItem<TIn, TOut>>,
    options: BatchOptions<TIn, TOut>,
    worker: (item: BatchItem<TIn, TOut>) => Promise<TOut>,
  ): Promise<BatchResult<TOut>> {
    const started = Date.now();

    if (input.length === 0) {
      return { items: [], succeeded: [], failed: [], pageCount: 0, totalDurationMs: 0 };
    }

    const pageSize = Math.min(
      options.pageSize ?? DEFAULT_PAGE_SIZE,
      MAX_CONTRACT_BATCH_SIZE,
    );
    const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
    const continueOnError = options.continueOnError ?? true;

    // Normalize raw inputs into tracked items, preserving any existing key.
    const items: BatchItem<TIn, TOut>[] = input.map((entry, index) => {
      if (isBatchItem<TIn, TOut>(entry)) {
        return entry;
      }
      return { key: String(index), input: entry as TIn };
    });

    const optimistic = options.optimistic;
    if (optimistic?.apply) {
      for (const item of items) {
        optimistic.apply(item);
      }
    }

    const pages = paginate(items, pageSize);
    const pageCount = pages.length;
    let completed = 0;

    const report = (pageIndex: number, lastItem?: BatchItem<TIn, TOut>): void => {
      options.onProgress?.({
        operation,
        completed,
        total: items.length,
        pageIndex,
        pageCount,
        fraction: items.length === 0 ? 1 : completed / items.length,
        lastItem: lastItem as BatchItem<unknown, unknown> | undefined,
      });
    };

    /** Sentinel used to unwind the batch in strict mode. */
    const abort = Symbol('batch-abort');

    const handleItem = (item: BatchItem<TIn, TOut>, pageIndex: number): void => {
      completed += 1;

      if (item.error) {
        this.logger.warn('Batch item failed', {
          operation,
          key: item.key,
          error: item.error.message,
        });
        optimistic?.rollback?.(item, item.error);
      } else {
        optimistic?.commit?.(item);
      }

      report(pageIndex, item);

      if (item.error && !continueOnError) {
        throw abort;
      }
    };

    let pageIndex = 0;
    try {
      for (const page of pages) {
        const currentPage = pageIndex;
        await runPage(page, concurrency, worker, item => {
          handleItem(item, currentPage);
        });
        pageIndex += 1;
      }
    } catch (err) {
      if (err === abort) {
        // Roll back anything still marked optimistic and never executed.
        const pending = items.filter(i => !i.error && i.output === undefined);
        const reason = new Error(`Batch ${operation} aborted after a failure`);
        for (const item of pending) {
          item.error = reason;
          optimistic?.rollback?.(item, reason);
        }
        this.logger.error('Batch aborted', reason, { operation, page: pageIndex });
        throw reason;
      }
      throw err;
    }

    const succeeded = items.filter(i => !i.error);
    const failed = items.filter(i => i.error);
    const totalDurationMs = Date.now() - started;

    this.logger.info('Batch complete', {
      operation,
      total: items.length,
      succeeded: succeeded.length,
      failed: failed.length,
      pageCount,
      totalDurationMs,
    });

    return { items, succeeded, failed, pageCount, totalDurationMs };
  }
}

/** Duck-typed guard distinguishing a pre-built item from a raw input. */
function isBatchItem<TIn, TOut>(value: unknown): value is BatchItem<TIn, TOut> {
  return (
    typeof value === 'object' &&
    value !== null &&
    'key' in (value as Record<string, unknown>) &&
    'input' in (value as Record<string, unknown>)
  );
}
