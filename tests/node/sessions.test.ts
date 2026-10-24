import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { SessionStore } from '../../server/sessions.ts';

function storeWithClock(options: { ttlMs?: number; maxSessions?: number } = {}) {
  const clock = { now: 0 };
  const store = new SessionStore<string>({
    ttlMs: options.ttlMs ?? 1_000,
    maxSessions: options.maxSessions ?? 10,
    now: () => clock.now,
  });
  return { store, clock };
}

describe('SessionStore', () => {
  test('stores and returns sessions', () => {
    const { store } = storeWithClock();
    store.set('a', 'alpha');
    assert.equal(store.get('a'), 'alpha');
    assert.equal(store.get('missing'), undefined);
    assert.equal(store.size, 1);
  });

  test('expires idle sessions but slides the expiry on access', () => {
    const { store, clock } = storeWithClock({ ttlMs: 1_000 });
    store.set('a', 'alpha');
    clock.now = 900;
    assert.equal(store.get('a'), 'alpha');
    clock.now = 1_800;
    assert.equal(store.get('a'), 'alpha');
    clock.now = 2_801;
    assert.equal(store.get('a'), undefined);
    assert.equal(store.size, 0);
  });

  test('evicts the least recently used session at capacity', () => {
    const { store } = storeWithClock({ maxSessions: 2 });
    store.set('a', 'alpha');
    store.set('b', 'beta');
    store.get('a');
    store.set('c', 'gamma');
    assert.equal(store.get('b'), undefined);
    assert.equal(store.get('a'), 'alpha');
    assert.equal(store.get('c'), 'gamma');
  });

  test('prunes expired sessions before evicting live ones', () => {
    const { store, clock } = storeWithClock({ ttlMs: 100, maxSessions: 2 });
    store.set('old', 'x');
    clock.now = 50;
    store.set('live', 'y');
    clock.now = 120;
    store.set('new', 'z');
    assert.equal(store.get('live'), 'y');
    assert.equal(store.get('new'), 'z');
  });

  test('runExclusive serializes tasks per session, even after a failure', async () => {
    const { store } = storeWithClock();
    store.set('a', 'alpha');
    const order: string[] = [];
    const slow = store.runExclusive('a', async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
      order.push('first');
      throw new Error('boom');
    });
    const fast = store.runExclusive('a', async () => {
      order.push('second');
      return 'done';
    });
    await assert.rejects(slow, /boom/);
    assert.equal(await fast, 'done');
    assert.deepEqual(order, ['first', 'second']);
  });

  test('runExclusive rejects for unknown sessions', async () => {
    const { store } = storeWithClock();
    await assert.rejects(
      store.runExclusive('nope', async () => 1),
      /Unknown session/,
    );
  });
});
