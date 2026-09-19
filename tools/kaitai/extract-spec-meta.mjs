// Distils what each .ksy declares about itself - id, title, file extensions, mime types - into
// catalog/kaitai-meta.json. The specs are the authority on the extensions they claim, so matching
// them against magika's labels beats a synonym table maintained by hand.
//
//   node tools/kaitai/extract-spec-meta.mjs <formats-dir> [out.json]
import { readFileSync, writeFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const NL = String.fromCharCode(10);
const ANY_ITEM = /^(\s+)-\s+(.*)$/;

const walk = (dir, base = dir) => readdirSync(dir).flatMap((name) => {
  const full = join(dir, name);
  if (statSync(full).isDirectory()) return walk(full, base);
  return full.endsWith('.ksy') ? [relative(base, full).replace(/\\/g, '/')] : [];
});

// The meta block is the indented region that follows a "meta:" line at column 0.
const metaBlock = (text) => {
  const lines = text.split(NL);
  const from = lines.findIndex((line) => line.startsWith('meta:'));
  if (from < 0) return [];
  const block = [];
  for (let i = from + 1; i < lines.length; i += 1) {
    if (lines[i].trim() !== '' && !lines[i].startsWith(' ')) break;
    block.push(lines[i]);
  }
  return block;
};

// Dash items under `key:`, e.g. "file-extension:" followed by "  - png". Stops at the next key.
const listAfter = (block, key) => {
  const at = block.findIndex((line) => line.trim() === `${key}:`);
  if (at < 0) return [];
  const items = [];
  for (let i = at + 1; i < block.length; i += 1) {
    if (block[i].trim() === '') continue;
    const match = block[i].match(ANY_ITEM);
    if (!match) break;
    items.push(match[2].trim().replace(/^["']|["']$/g, ''));
  }
  return items;
};

const scalarAfter = (block, key) => {
  const line = block.find((entry) => entry.trim().startsWith(`${key}:`));
  if (!line) return '';
  return line.slice(line.indexOf(':') + 1).trim().replace(/^["']|["']$/g, '');
};

const root = process.argv[2];
const out = process.argv[3] ?? 'catalog/kaitai-meta.json';

const specs = walk(root).map((path) => {
  const block = metaBlock(readFileSync(join(root, path), 'utf8'));
  return {
    path,
    id: path.slice(path.lastIndexOf('/') + 1, -4),
    category: path.slice(0, path.lastIndexOf('/')),
    title: scalarAfter(block, 'title'),
    extensions: [...new Set(listAfter(block, 'file-extension').map((v) => v.toLowerCase()))].sort(),
    mimes: [...new Set(listAfter(block, 'mime').map((v) => v.toLowerCase()))].sort(),
  };
}).sort((a, b) => a.path.localeCompare(b.path));

writeFileSync(out, JSON.stringify({ source: 'kaitai spec meta as declared by each .ksy', specs }, null, 2) + NL);

console.log(`${specs.length} specs · ${specs.filter((s) => s.extensions.length).length} declare file-extension · ${specs.filter((s) => s.mimes.length).length} declare mime`);
for (const probe of ['png', 'microsoft_pe', 'zip', 'sqlite3', 'iso9660', 'wav']) {
  const found = specs.find((s) => s.id === probe);
  console.log(`  ${probe.padEnd(14)} ${JSON.stringify(found?.extensions ?? []).slice(0, 46)} ${JSON.stringify(found?.mimes ?? []).slice(0, 40)}`);
}
