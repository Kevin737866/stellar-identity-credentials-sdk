/**
 * Tests for the error monitoring and reporting hooks (issue #110).
 */

import {
  ErrorMonitor,
  ConsoleErrorReporter,
  NoOpErrorReporter,
  ErrorEvent,
} from '../errorMonitor';
import {
  DIDError,
  NetworkError,
  ValidationError,
  RateLimitError,
  ComplianceError,
  ErrorCode,
} from '../errors';

function makeDIDError()        { return new DIDError(ErrorCode.DIDNotFound); }
function makeNetworkError()    { return new NetworkError(ErrorCode.NetworkTimeout); }
function makeValidationError() { return new ValidationError(ErrorCode.ValidationInvalidAddress); }
function makeRateLimitError()  { return new RateLimitError(ErrorCode.RateLimitExceeded); }
function makeComplianceError() { return new ComplianceError(ErrorCode.ComplianceAddressBlocked); }

// ─── Global singleton ─────────────────────────────────────────────────────────

describe('ErrorMonitor.global()', () => {
  beforeEach(() => ErrorMonitor.resetGlobal());

  it('creates a new instance on first access', () => {
    const m = ErrorMonitor.global();
    expect(m).toBeInstanceOf(ErrorMonitor);
  });

  it('returns the same instance on subsequent calls', () => {
    const a = ErrorMonitor.global();
    const b = ErrorMonitor.global();
    expect(a).toBe(b);
  });

  it('setGlobal() replaces the instance', () => {
    const custom = new ErrorMonitor();
    ErrorMonitor.setGlobal(custom);
    expect(ErrorMonitor.global()).toBe(custom);
  });
});

// ─── capture() ────────────────────────────────────────────────────────────────

describe('ErrorMonitor#capture', () => {
  let monitor: ErrorMonitor;
  beforeEach(() => { monitor = new ErrorMonitor(); });

  it('returns an ErrorEvent with all required fields', () => {
    const err = makeDIDError();
    const event = monitor.capture(err, 'didClient', 'resolveDID');

    expect(event.code).toBe(ErrorCode.DIDNotFound);
    expect(event.errorClass).toBe('contract');
    expect(event.name).toBe('DIDError');
    expect(event.retryable).toBe(false);
    expect(event.recovery).toBeTruthy();
    expect(event.domain).toBe('didClient');
    expect(event.operation).toBe('resolveDID');
    expect(event.id).toBeGreaterThan(0);
    expect(event.timestamp).toBeGreaterThan(0);
  });

  it('assigns monotonically increasing IDs', () => {
    const a = monitor.capture(makeDIDError());
    const b = monitor.capture(makeNetworkError());
    expect(b.id).toBe(a.id + 1);
  });

  it('applies defaultDomain when none supplied', () => {
    const m = new ErrorMonitor({ defaultDomain: 'myApp' });
    const event = m.capture(makeDIDError());
    expect(event.domain).toBe('myApp');
  });

  it('keeps events in history ring buffer', () => {
    for (let i = 0; i < 5; i++) monitor.capture(makeDIDError());
    expect(monitor.getHistory()).toHaveLength(5);
  });

  it('trims history when historySize is exceeded', () => {
    const m = new ErrorMonitor({ historySize: 3 });
    for (let i = 0; i < 5; i++) m.capture(makeDIDError());
    expect(m.getHistory()).toHaveLength(3);
  });

  it('updates stats counters', () => {
    monitor.capture(makeDIDError(),     'did',        'createDID');
    monitor.capture(makeNetworkError(), 'network',    'rpc');
    monitor.capture(makeDIDError(),     'did',        'resolveDID');

    const stats = monitor.getStats();
    expect(stats.total).toBe(3);
    expect(stats.byCode[ErrorCode.DIDNotFound]).toBe(2);
    expect(stats.byClass['contract']).toBe(2);
    expect(stats.byClass['network']).toBe(1);
    expect(stats.byDomain['did']).toBe(2);
  });
});

// ─── Hook registration ────────────────────────────────────────────────────────

describe('ErrorMonitor hooks', () => {
  let monitor: ErrorMonitor;
  beforeEach(() => { monitor = new ErrorMonitor(); });

  it('onError fires for every captured error', () => {
    const hook = jest.fn();
    monitor.onError(hook);
    monitor.capture(makeDIDError());
    monitor.capture(makeNetworkError());
    expect(hook).toHaveBeenCalledTimes(2);
  });

  it('onError unsubscribe function removes the hook', () => {
    const hook = jest.fn();
    const unsub = monitor.onError(hook);
    unsub();
    monitor.capture(makeDIDError());
    expect(hook).not.toHaveBeenCalled();
  });

  it('onErrorClass fires only for matching class', () => {
    const hook = jest.fn();
    monitor.onErrorClass('network', hook);
    monitor.capture(makeNetworkError());
    monitor.capture(makeDIDError());         // contract — should not fire
    monitor.capture(makeValidationError());  // validation — should not fire
    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook.mock.calls[0][0].errorClass).toBe('network');
  });

  it('onErrorCode fires only for the specific code', () => {
    const hook = jest.fn();
    monitor.onErrorCode(ErrorCode.DIDNotFound, hook);
    monitor.capture(makeDIDError());                             // DIDNotFound — fires
    monitor.capture(new DIDError(ErrorCode.DIDAlreadyExists));  // different code — no
    monitor.capture(makeNetworkError());                         // network — no
    expect(hook).toHaveBeenCalledTimes(1);
  });

  it('onDomain fires only for the specified domain', () => {
    const hook = jest.fn();
    monitor.onDomain('credentialClient', hook);
    monitor.capture(makeDIDError(), 'didClient');
    monitor.capture(makeNetworkError(), 'credentialClient');
    expect(hook).toHaveBeenCalledTimes(1);
    expect(hook.mock.calls[0][0].domain).toBe('credentialClient');
  });

  it('multiple hooks on the same event all fire', () => {
    const h1 = jest.fn(), h2 = jest.fn();
    monitor.onError(h1);
    monitor.onError(h2);
    monitor.capture(makeDIDError());
    expect(h1).toHaveBeenCalledTimes(1);
    expect(h2).toHaveBeenCalledTimes(1);
  });

  it('a throwing hook does not crash capture()', () => {
    monitor.onError(() => { throw new Error('hook exploded'); });
    expect(() => monitor.capture(makeDIDError())).not.toThrow();
  });

  it('clearHooks() removes all registered hooks', () => {
    const hook = jest.fn();
    monitor.onError(hook);
    monitor.onErrorClass('network', hook);
    monitor.clearHooks();
    monitor.capture(makeDIDError());
    monitor.capture(makeNetworkError());
    expect(hook).not.toHaveBeenCalled();
  });
});

// ─── Reporters ────────────────────────────────────────────────────────────────

describe('ErrorMonitor reporters', () => {
  it('NoOpErrorReporter captures all events', () => {
    const reporter = new NoOpErrorReporter();
    const monitor = new ErrorMonitor({ reporters: [reporter] });
    monitor.capture(makeDIDError());
    monitor.capture(makeNetworkError());
    expect(reporter.captured).toHaveLength(2);
    expect(reporter.captured[0].code).toBe(ErrorCode.DIDNotFound);
  });

  it('addReporter attaches a reporter at runtime', () => {
    const monitor = new ErrorMonitor();
    const reporter = new NoOpErrorReporter();
    monitor.addReporter(reporter);
    monitor.capture(makeRateLimitError());
    expect(reporter.captured).toHaveLength(1);
  });

  it('removeReporter detaches a reporter', () => {
    const reporter = new NoOpErrorReporter();
    const monitor = new ErrorMonitor({ reporters: [reporter] });
    monitor.removeReporter(reporter);
    monitor.capture(makeDIDError());
    expect(reporter.captured).toHaveLength(0);
  });

  it('a throwing reporter does not crash capture()', () => {
    const badReporter = { report: () => { throw new Error('reporter exploded'); } };
    const monitor = new ErrorMonitor({ reporters: [badReporter] });
    expect(() => monitor.capture(makeDIDError())).not.toThrow();
  });

  it('ConsoleErrorReporter writes to console.error', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const reporter = new ConsoleErrorReporter('network');
    const event: ErrorEvent = {
      id: 1, timestamp: Date.now(), code: ErrorCode.NetworkTimeout,
      errorClass: 'network', name: 'NetworkError', message: 'timeout',
      recovery: 'retry', retryable: true, details: {}, domain: 'sdk',
    };
    reporter.report(event);
    expect(spy).toHaveBeenCalledTimes(1);
    spy.mockRestore();
  });

  it('ConsoleErrorReporter skips events below minClass', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const reporter = new ConsoleErrorReporter('network'); // skip validation
    const event: ErrorEvent = {
      id: 1, timestamp: Date.now(), code: ErrorCode.ValidationInvalidAddress,
      errorClass: 'validation', name: 'ValidationError', message: 'bad addr',
      recovery: 'fix it', retryable: false, details: {},
    };
    reporter.report(event);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ─── Queries ──────────────────────────────────────────────────────────────────

describe('ErrorMonitor queries', () => {
  let monitor: ErrorMonitor;

  beforeEach(() => {
    monitor = new ErrorMonitor();
    monitor.capture(makeDIDError(),        'did',        'createDID');
    monitor.capture(makeNetworkError(),    'rpc',        'sendTx');
    monitor.capture(makeComplianceError(), 'compliance', 'screen');
    monitor.capture(makeRateLimitError(),  'rpc',        'submit');
    monitor.capture(makeDIDError(),        'did',        'deactivate');
  });

  it('getHistory() returns all events in order', () => {
    const history = monitor.getHistory();
    expect(history).toHaveLength(5);
    expect(history[0].code).toBe(ErrorCode.DIDNotFound);
  });

  it('getRecentErrors(n) returns last n events', () => {
    const recent = monitor.getRecentErrors(2);
    expect(recent).toHaveLength(2);
    expect(recent[1].operation).toBe('deactivate');
  });

  it('getByClass() filters by errorClass', () => {
    const networkEvents = monitor.getByClass('network');
    expect(networkEvents).toHaveLength(2); // NetworkTimeout + RateLimitError → ratelimit
    networkEvents.forEach(e => expect(e.errorClass).toBe('network'));
  });

  it('getByCode() filters by exact code', () => {
    const didEvents = monitor.getByCode(ErrorCode.DIDNotFound);
    expect(didEvents).toHaveLength(2);
  });

  it('getByDomain() filters by domain', () => {
    const rpcEvents = monitor.getByDomain('rpc');
    expect(rpcEvents).toHaveLength(2);
  });

  it('reset() clears history and stats', () => {
    monitor.reset();
    expect(monitor.getHistory()).toHaveLength(0);
    expect(monitor.getStats().total).toBe(0);
  });

  it('getStats() returns a frozen snapshot (not live reference)', () => {
    const stats = monitor.getStats();
    monitor.capture(makeDIDError());
    expect(stats.total).toBe(5); // snapshot was taken before extra capture
  });
});
