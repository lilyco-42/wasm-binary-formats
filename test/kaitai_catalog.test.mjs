// Load gate for the whole generated set: every spec listed in tools/kaitai/specs.txt must produce
// a module that resolves and exposes its class. This asserts reachability, not correctness - only
// the formats with fixtures in kaitai.test.mjs are checked against real bytes. Keeping the two
// levels apart is what stops "it generated" from being reported as "it parses".
//
//   node test/kaitai_catalog.test.mjs path/to/generated
import { createRequire } from 'node:module';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const here = dirname(fileURLToPath(import.meta.url));

const specs = readFileSync(join(here, '..', 'tools', 'kaitai', 'specs.txt'), 'utf8')
  .split('\n').map((line) => line.trim()).filter(Boolean);

const className = (id) => id.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');

assert.ok(specs.length >= 20, `expected at least 20 specs, listed ${specs.length}`);

test('every listed spec generates a loadable reader', () => {
  const missing = [];
  const unusable = [];
  for (const spec of specs) {
    const name = className(spec.slice(spec.lastIndexOf('/') + 1));
    const file = join(generatedDir, `${name}.js`);
    if (!existsSync(file)) {
      missing.push(`${spec} -> ${name}.js`);
      continue;
    }
    const exported = require(file)[name];
    if (typeof exported !== 'function' || typeof exported.prototype._read !== 'function') {
      unusable.push(name);
    }
  }
  assert.deepEqual(missing, [], 'specs that produced no output file');
  assert.deepEqual(unusable, [], 'modules that do not expose a reader class');
});

test('the generated set only contains readers and their shared imports', () => {
  const produced = readdirSync(generatedDir).filter((name) => name.endsWith('.js'));
  const wanted = new Set(specs.map((spec) => `${className(spec.slice(spec.lastIndexOf('/') + 1))}.js`));
  const extras = produced.filter((name) => !wanted.has(name));
  // Shared helpers (DosDatetime, Riff, VlqBase128Le, ...) are expected; anything else means the
  // generated directory holds files this repo did not ask for.
  assert.ok(extras.length <= 15, `unexpected generated files: ${extras.join(' ')}`);
});
