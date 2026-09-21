// Parse the demo page's inline script, because nothing else in CI does.
//
// The panels are one `<script>` block, so a single duplicated `const` - which is what happened when the
// Resources panel reused the Functions panel's `bodies` - is a SyntaxError that takes the *whole* page
// down, wasm tests included, since they never load the page. `node --check` on the extracted body is the
// same parse the browser does, and it is the cheapest gate that would have caught it.
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const html = readFileSync('demo/index.html', 'utf8');
const blocks = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)];
if (blocks.length === 0) {
  console.error('demo/index.html has no inline script, so this gate is checking nothing');
  process.exit(1);
}
for (const [index, match] of blocks.entries()) {
  const file = join(tmpdir(), `demo-panel-${index}.mjs`);
  writeFileSync(file, match[1]);
  const checked = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (checked.status !== 0) {
    console.error(`script block ${index} does not parse:\n${checked.stderr.slice(0, 800)}`);
    process.exit(1);
  }
}
console.log(`${blocks.length} inline script block(s) in demo/index.html parse`);
