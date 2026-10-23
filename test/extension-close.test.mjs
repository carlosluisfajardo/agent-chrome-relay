import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extensionFixture } from './helpers/extension.mjs';

test('pre-auth duplicate-profile refusal backs off finitely without discarding tab custody', async () => {
  const f = await extensionFixture({ authenticate: false, refuseCode: 4009, tabs: [7, 8], saved: { agentTabs: [7] } });
  assert.equal(f.messages.length, 0, 'server sequence starts with no authenticated command');
  for (let n = 0; n < 20; n++) await f.debuggerEvent(7, 'Network.loadingFinished', { requestId: `r${n}` });
  assert.equal(f.sockets.length, 1, 'pre-auth refusal caused a handshake storm');
  assert.ok(f.live.has(7) && f.agentTabs.has(7), 'untrusted refusal discarded owned tab custody');
  assert.ok(f.live.has(8), 'unrelated tab changed');
  assert.deepEqual(f.persisted.agentTabs, [7]);
  f.advance(5 * 60 * 1000 - 1);
  await f.connect();
  assert.equal(f.sockets.length, 1, 'refusal backoff ended early');
  f.advance(2);
  await f.connect();
  assert.equal(f.sockets.length, 2, 'refusal backoff did not expire');
});

test('transient disconnect keeps tabs and an authenticated new relay can clean up owned tabs', async () => {
  const f = await extensionFixture({ authenticate: false, tabs: [7, 8], saved: { agentTabs: [7], relayInstance: 'old' } });
  f.sockets[0].close(1006);
  await f.connect();
  assert.equal(f.sockets.length, 2, 'ordinary disconnect was incorrectly backed off');
  assert.ok(f.live.has(7) && f.live.has(8));
  await f.receive(f.envelope({ op: 'config', id: 1, instance: 'new' }));
  assert.ok(!f.live.has(7));
  assert.ok(f.live.has(8));
  assert.deepEqual(f.persisted.agentTabs, []);
});

test('a failed tab removal reports an error and remains retryable', async () => {
  let fail = true;
  const f = await extensionFixture({ saved: { agentTabs: [7] }, remove: async () => { if (fail) throw new Error('Chrome removal temporarily failed'); } });
  await f.handle({ op: 'close', id: 1, tabId: 7 });
  assert.match(f.messages.at(-1).error, /removal temporarily failed/);
  assert.ok(f.agentTabs.has(7));
  assert.deepEqual(f.persisted.agentTabs, [7]);
  assert.ok(f.live.has(7));
  fail = false;
  await f.handle({ op: 'close', id: 2, tabId: 7 });
  assert.deepEqual(f.messages.at(-1), { id: 2, result: {} });
  assert.ok(!f.agentTabs.has(7));
  assert.deepEqual(f.persisted.agentTabs, []);
});

test('restart cleanup retains failed tabs and retries before recording the new instance', async () => {
  let fail = true;
  const f = await extensionFixture({ saved: { agentTabs: [7], relayInstance: 'old' }, remove: async () => { if (fail) throw new Error('Chrome removal temporarily failed'); } });
  await f.handle({ op: 'config', id: 1, instance: 'new' });
  assert.match(f.messages.at(-1).error, /removal temporarily failed/);
  assert.equal(f.persisted.relayInstance, 'old');
  assert.deepEqual(f.persisted.agentTabs, [7]);
  fail = false;
  await f.handle({ op: 'config', id: 2, instance: 'new' });
  assert.equal(f.persisted.relayInstance, 'new');
  assert.deepEqual(f.persisted.agentTabs, []);
});

test('already removed tracked tabs are safely forgotten', async () => {
  const f = await extensionFixture({ saved: { agentTabs: [7] }, tabs: [] });
  await f.handle({ op: 'close', id: 1, tabId: 7 });
  assert.match(f.messages.at(-1).error, /not owned/);
  assert.deepEqual(f.persisted.agentTabs, []);
});

test('an unknown lookup failure is not evidence that a tab disappeared', async () => {
  let fail = false;
  const f = await extensionFixture({ saved: { agentTabs: [7] },
    get: async () => { if (fail) throw new Error('Lookup unavailable'); },
    remove: async () => { throw new Error('Removal unavailable'); } });
  fail = true;
  await f.handle({ op: 'close', id: 1, tabId: 7 });
  assert.match(f.messages.at(-1).error, /Removal unavailable/);
  assert.ok(f.agentTabs.has(7));
  assert.deepEqual(f.persisted.agentTabs, [7]);
});

test('refused-connection cleanup failures are handled and retried before reconnect', async () => {
  let fail = true;
  const f = await extensionFixture({ saved: { agentTabs: [7] },
    remove: async () => { if (fail) throw new Error('Removal unavailable'); } });
  f.sockets[0].onclose({ code: 4009 });
  await new Promise((r) => setImmediate(r));
  assert.ok(f.agentTabs.has(7));
  assert.deepEqual(f.persisted.agentTabs, [7]);
  fail = false;
  f.advance(5 * 60 * 1000 + 1);
  await f.connect();
  assert.ok(!f.agentTabs.has(7));
  assert.deepEqual(f.persisted.agentTabs, []);
  assert.equal(f.sockets.length, 2);
});
