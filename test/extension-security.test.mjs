import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extensionFixture } from './helpers/extension.mjs';

test('an absent public-key pin never opens a relay socket', async () => {
  const f = await extensionFixture({ authenticate:false, relayJSON:{port:9333} });
  assert.equal(f.sockets.length,0,'missing pin connected to a relay');
});

test('replacement relay cannot issue unsigned commands or use its close code for cleanup', async () => {
  const f = await extensionFixture({ authenticate: false, saved: { agentTabs: [7] } });
  await f.receive({ op: 'create', id: 1 });
  assert.equal(f.live.size, 1, 'unsigned replacement server created a tab');
  f.sockets[0].onclose({ code: 4009 });
  await new Promise(r => setImmediate(r));
  assert.ok(f.live.has(7), 'unauthenticated refusal closed tracked tabs');
});

test('only signed current-connection messages execute, in order, without replay', async () => {
  const f = await extensionFixture({ authenticate: false });
  const signed = f.envelope({ op: 'create', id: 1 });
  await f.receive(signed);
  assert.equal(f.live.size, 2, 'authenticated command did not execute');
  await f.receive(signed);
  assert.equal(f.live.size, 2, 'replayed command executed');
});

test('valid signature with another connection nonce is refused', async () => {
  const f = await extensionFixture({ authenticate: false });
  await f.receive(f.envelope({ op: 'create', id: 1 }, f.sockets[0], 'another-connection'));
  assert.equal(f.live.size, 1);
});

test('tampering a signed command cannot create a tab', async () => {
  const f = await extensionFixture({ authenticate: false });
  const signed = f.envelope({ op: 'version', id: 1 });
  signed.payload = signed.payload.replace('"version"', '"create"');
  await f.receive(signed);
  assert.equal(f.live.size, 1, 'tampered command executed');
});

test('unowned tab close is refused independently of CDP checks', async () => {
  const f = await extensionFixture({ tabs: [7, 8], saved: { agentTabs: [7] } });
  await f.handle({ op: 'close', tabId: 8, id: 1 });
  assert.ok(f.live.has(8), 'unowned tab was removed');
  assert.match(f.messages.at(-1).error, /not owned/);
});

test('unauthenticated relay close codes cannot discard owned tabs', async () => {
  const f = await extensionFixture({ authenticate: false, saved: { agentTabs: [7] } });
  f.sockets[0].onclose({ code: 4009 });
  await new Promise(r => setImmediate(r));
  assert.ok(f.live.has(7), 'untrusted close code removed tracked tab');
});

test('authenticated close and CDP refuse unowned tabs', async () => {
  const f = await extensionFixture({ tabs: [7, 8], saved: { agentTabs: [7] } });
  await f.handle({ op: 'cdp', tabId: 8, id: 1, method: 'Runtime.evaluate' });
  assert.equal(f.commands.length, 0, 'unowned CDP reached Chrome');
  await f.handle({ op: 'close', tabId: 8, id: 2 });
  assert.ok(f.live.has(8), 'unowned tab was removed');
  await f.handle({ op: 'cdp', tabId: 7, id: 3, method: 'Runtime.evaluate' });
  assert.equal(f.commands.length, 1);
});

for (const label of ['Continue', 'Allow']) test(`Google ${label} requires the person despite an account mapping`, async () => {
  const f = await extensionFixture(); let clicks = 0;
  const button = { offsetParent: {}, innerText: label, click() { clicks++; } };
  const result = f.google({ body: { innerText: `A third party wants access. ${label}` }, querySelectorAll: (q) => q === 'button, [role="button"]' ? [button] : [] });
  assert.equal(clicks, 0, 'consent was clicked automatically');
  assert.equal(result.state, 'needs_user');
});

// Synthetic DOM ancestry with aggregate descendant text: a consent button's
// innerText includes the account row it contains, as a real DOM element would.
function accountPage({ consent = '', heading = 'Choose an account', link = true } = {}) {
  let clicks = 0;
  const row = { offsetParent: {}, innerText: 'Fixture\nfixture@example.test', getAttribute: name => name === 'data-email' ? 'fixture@example.test' : null, click() { clicks++; } };
  const choice = { get innerText() { return row.innerText; }, click() { if (consent) button.click(); else clicks++; } };
  const button = { offsetParent: {}, get innerText() { return `${consent}\n${row.innerText}`; }, click() { clicks++; } };
  row.closest = selector => {
    if (selector === '[role="link"]') return link ? choice : null;
    if (selector === 'button, [role="button"], input[type="submit"]') return consent ? button : null;
    if (selector === '[role="link"], li, button') return link ? choice : consent ? button : null;
    throw new Error(`unmodeled ancestor selector: ${selector}`);
  };
  const document = { body: { innerText: `${heading}\n${consent}\n${row.innerText}` }, querySelectorAll: selector => {
    if (selector === '[data-identifier], [data-email]') return [row];
    if (selector === 'button, [role="button"]') return consent ? [button] : [];
    if (selector === 'h1, h2, [role="heading"]') return heading ? [{ offsetParent: {}, innerText: heading }] : [];
    return [];
  } };
  return { document, get clicks() { return clicks; } };
}

test('Google signed-in account selection still works', async () => {
  const f = await extensionFixture(), page = accountPage();
  const result = f.google(page.document);
  assert.equal(page.clicks, 1); assert.equal(result.state, 'clicked');
});

for (const consent of ['Continue', 'Allow']) for (const link of [false, true]) test(`aggregate ${consent} account wrapper requires the person (${link ? 'nested link' : 'plain row'})`, async () => {
  const f = await extensionFixture(), page = accountPage({ consent, link });
  const result = f.google(page.document);
  assert.equal(page.clicks, 0, 'mapped account wrapper clicked consent with aggregate descendant text');
  assert.equal(result.state, 'needs_user');
});

test('mapped account metadata outside an account chooser requires the person', async () => {
  const f = await extensionFixture(), page = accountPage({ heading: 'Authorize this application' });
  const result = f.google(page.document);
  assert.equal(page.clicks, 0, 'account metadata outside a chooser was clicked');
  assert.equal(result.state, 'needs_user');
});

test('mapped account metadata without an account-choice link requires the person', async () => {
  const f = await extensionFixture(), page = accountPage({ link: false });
  const result = f.google(page.document);
  assert.equal(page.clicks, 0, 'ambiguous account metadata was clicked');
  assert.equal(result.state, 'needs_user');
});

test('a mapped account element cannot bypass a visible consent button', async () => {
  const f = await extensionFixture(); let clicks=0;
  const button={offsetParent:{},innerText:'Allow',click(){clicks++;}};
  const row={offsetParent:{},innerText:'fixture@example.test',getAttribute:()=> 'fixture@example.test',closest:()=>button,click(){clicks++;}};
  const result=f.google({body:{innerText:'Allow this app access'},querySelectorAll:q=>q==='[data-identifier], [data-email]'?[row]:q==='button, [role="button"]'?[button]:[]});
  assert.equal(clicks,0,'mapped account wrapper clicked consent');
  assert.equal(result.state,'needs_user');
});
