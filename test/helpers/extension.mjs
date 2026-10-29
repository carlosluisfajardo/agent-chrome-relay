import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto, generateKeyPairSync, sign } from 'node:crypto';

export async function extensionFixture({ remove, get, group, relayJSON, refuseCode, authenticate = true, windowIds = [1], saved = {}, tabs = [7] } = {}) {
  const messages = [], persisted = { ...saved };
  const live = new Set(tabs);
  const groups = new Map(), groupCalls = [], commands = [];
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'jwk' }).x;
  let nextTab = 100, nextGroup = 10, windowIndex = 0;
  const event = () => ({ listeners: [], addListener(listener) { this.listeners.push(listener); } });
  const storage = { get: async () => ({ ...persisted }), set: async (data) => Object.assign(persisted, structuredClone(data)) };
  const chrome = {
    storage: { session: storage, local: storage },
    identity: { getProfileUserInfo: async () => ({ email: 'fixture@example.test' }) },
    alarms: { create() {}, onAlarm: event() },
    runtime: { getURL: (s) => s, onStartup: event(), onInstalled: event(), reload() {}, getManifest: () => ({ version: 'test' }) },
    debugger: { onEvent: event(), onDetach: event(), detach: async () => {}, attach: async () => {}, sendCommand: async (...args) => { commands.push(args); return {}; } },
    windows: { getLastFocused: async () => ({ id: windowIds[windowIndex++ % windowIds.length] }) },
    tabGroups: { get: async (id) => { if (!groups.has(id)) throw new Error('No group'); return groups.get(id); },
      update: async (id, data) => Object.assign(groups.get(id), structuredClone(data)) },
    tabs: { get: async (id) => { if (get) await get(id); if (!live.has(id)) throw new Error(`No tab with id: ${id}.`); return { id, windowId: 1 }; },
      create: async (options) => { const id = nextTab++; live.add(id); return { id, windowId: options.windowId ?? 1 }; },
      group: async (options) => {
        groupCalls.push(structuredClone(options));
        if (group) await group(options);
        const id = options.groupId ?? nextGroup++;
        if (!groups.has(id)) groups.set(id, { id, windowId: options.createProperties.windowId });
        return id;
      },
      remove: async (id) => { if (remove) await remove(id); if (!live.has(id)) throw new Error(`No tab with id: ${id}.`); live.delete(id); },
      onUpdated: event(), onActivated: event(), onCreated: event(), onRemoved: event() },
  };
  const sockets = [];
  class Socket { readyState = 1; constructor(url) { this.url = url; this.sequence = 0; sockets.push(this); if (refuseCode) queueMicrotask(() => this.close(refuseCode)); } send(data) { messages.push(JSON.parse(data)); } close(code) { this.readyState = 3; this.onclose?.({ code }); } }
  const startedAt = Date.now();
  let timeOffset = 0;
  class Clock extends Date { static now() { return startedAt + timeOffset; } }
  const context = vm.createContext({ chrome, WebSocket: Socket, crypto: webcrypto, console,
    fetch: async () => ({ json: async () => relayJSON ?? ({ port: 9333, publicKey }) }),
    TextEncoder, atob, setTimeout, clearTimeout, Date: Clock, URL });
  const source = fs.readFileSync(new URL('../../extension/sw.js', import.meta.url), 'utf8');
  vm.runInContext(source + '\n globalThis.fixture = { handle, connect, closeAgentTabs, agentTabs, googleAuthStep, hostOfAuth };', context);
  await context.fixture.connect();
  const envelope = (command, socket = sockets.at(-1), nonce = new URL(socket.url).searchParams.get('nonce')) => {
    const payload = JSON.stringify({ nonce, sequence: ++socket.sequence, command });
    return { payload, signature: sign(null, Buffer.from(payload), keys.privateKey).toString('base64url') };
  };
  const receive = async (message, socket = sockets.at(-1)) => { await socket.onmessage({ data: JSON.stringify(message) }); await new Promise(r => setImmediate(r)); };
  if (authenticate) await receive(envelope({ op: 'version', id: 0 }));
  return { ...context.fixture, messages, persisted, live, sockets, groups, groupCalls, commands, envelope, receive,
    debuggerEvent: async (tabId, method, params) => { for (const listener of chrome.debugger.onEvent.listeners) listener({ tabId }, method, params); await new Promise(r => setImmediate(r)); },
    google: (document) => { context.document = document; return context.fixture.googleAuthStep('fixture@example.test'); },
    created: async (tab) => { live.add(tab.id); await Promise.all(chrome.tabs.onCreated.listeners.map((listener) => listener(tab))); },
    advance: (ms) => { timeOffset += ms; } };
}
