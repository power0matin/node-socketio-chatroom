'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const braces = require('braces');
const bracesPackage = require('braces/package.json');

test('the braces dependency resolves to the reviewed depth-guard backport', () => {
  assert.equal(bracesPackage.name, '@dieub/braces-depth-guard');
  assert.equal(bracesPackage.version, '3.0.3-pn.2');
});

test('ordinary brace expansion remains compatible', () => {
  assert.deepEqual(braces.expand('{a,b}'), ['a', 'b']);
  assert.deepEqual(braces.expand('file-{a,b}.js'), ['file-a.js', 'file-b.js']);
});

test('deeply nested brace input is rejected before unbounded recursion', () => {
  const nested = `${'{'.repeat(101)}x${'}'.repeat(101)}`;
  assert.throws(() => braces.expand(nested), /exceeds max depth/i);
});
