'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { DEFAULTS, origins, validateConfig, validUsername } = require('../src/lib/config');

test('valid configuration normalizes explicit origins', () => {
  const config = validateConfig({ ...DEFAULTS, allowedOrigins: ['https://chat.example.com:443'] });
  assert.deepEqual(config.allowedOrigins, ['https://chat.example.com']);
});

test('invalid ports fail fast with clear configuration errors', () => {
  for (const port of ['abc', 0, 70000, 3.14]) {
    assert.throws(() => validateConfig({ ...DEFAULTS, port }), /port must be an integer between 1 and 65535/i);
  }
});

test('invalid file limits and origins are rejected', () => {
  assert.throws(() => validateConfig({ ...DEFAULTS, maxFileSizeMB: 0 }), /maxFileSizeMB/);
  assert.throws(() => origins('*'), /cannot be/);
  assert.throws(() => origins('https://example.com/path'), /scheme \+ host/);
  assert.throws(() => origins('javascript:alert(1)'), /Origin must|Invalid origin/);
});

test('reserved or ambiguous usernames are rejected', () => {
  assert.equal(validUsername('alice'), true);
  assert.equal(validUsername('a_pv_b'), false);
  assert.equal(validUsername('__saved__alice'), false);
  assert.equal(validUsername('ab'), false);
});

test('bind host and access mode are validated', () => {
  assert.throws(() => validateConfig({ ...DEFAULTS, bindHost: 'example.com' }), /bindHost/);
  assert.throws(() => validateConfig({ ...DEFAULTS, accessMode: 'anything' }), /accessMode/);
});
