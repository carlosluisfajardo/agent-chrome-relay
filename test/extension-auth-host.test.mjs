import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extensionFixture } from './helpers/extension.mjs';

test('a Google hop returns the hostname without a callback port', async () => {
  const f = await extensionFixture();
  assert.equal(
    f.hostOfAuth('https://accounts.google.com/o/oauth2/auth?redirect_uri=https%3A%2F%2Fapp.example.com%3A8443%2Fcb'),
    'app.example.com',
  );
});

test('a relative redirect does not hide a later absolute continue target', async () => {
  const f = await extensionFixture();
  assert.equal(
    f.hostOfAuth('https://accounts.google.com/AccountChooser?redirect_uri=%2Fcallback&continue=https%3A%2F%2Fshop.example.com%2Fhome'),
    'shop.example.com',
  );
});

test('a malformed absolute redirect does not hide a later service target', async () => {
  const f = await extensionFixture();
  assert.equal(
    f.hostOfAuth('https://accounts.google.com/ServiceLogin?redirect_uri=https%3A%2F%2F%5B&service_url=https%3A%2F%2Fservice.example.com%2Fhome'),
    'service.example.com',
  );
});

test('Google hop host lookup preserves valid target order and empty results', async () => {
  const f = await extensionFixture();
  for (const [address, expected] of [
    ['https://accounts.google.com/ServiceLogin?redirect_uri=https%3A%2F%2Ffirst.example.com%2Fcb&continue=https%3A%2F%2Fsecond.example.com', 'first.example.com'],
    ['https://accounts.google.com/ServiceLogin?origin=https%3A%2F%2Forigin.example.com', 'origin.example.com'],
    ['https://accounts.google.com/ServiceLogin', ''],
    ['https://accounts.google.com/ServiceLogin?redirect_uri=%2Fcallback', ''],
    ['not an address', ''],
  ]) assert.equal(f.hostOfAuth(address), expected, address);
});
