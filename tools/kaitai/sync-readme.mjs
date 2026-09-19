// Rewrites the README tables that are derived from CI-measured artefacts, so no number in the docs
// is ever transcribed by hand again.
//
//   node tools/kaitai/sync-readme.mjs
import { readFileSync, writeFileSync } from 'node:fs';

const sizes = JSON.parse(readFileSync('catalog/kaitai-sizes.json', 'utf8'));
const { summary: cov } = JSON.parse(readFileSync('catalog/coverage.json', 'utf8'));
const num = (v) => v.toLocaleString('en-US');

const families = Object.entries(sizes.byCategory)
  .filter(([, v]) => v.formats > 0)
  .sort((a, b) => b[1].bytes - a[1].bytes)
  .map(([category, v]) => {
    const heaviest = sizes.rows
      .filter((r) => r.category === category && r.size > 0)
      .sort((a, b) => b.size - a.size)[0];
    return `| ${category} | ${v.formats} | ${num(v.bytes)} B | ${num(heaviest.gzSize)} B | ${heaviest.className} ${num(heaviest.size)} B |`;
  });

const familyTable = [
  '| family | formats | raw JS | gzipped | heaviest |',
  '|---|---|---|---|---|',
  ...families,
  `| **total** | **${sizes.specsGenerated}** | **${num(sizes.bytesForRequestedFormats)} B** | ${num(sizes.tiers.light.gzBytes + sizes.tiers.medium.gzBytes + sizes.tiers.heavy.gzBytes)} B | + ${sizes.sharedImportFiles} shared files, ${num(sizes.bytesForSharedImports)} B raw |`,
].join('\n');

const t = sizes.tiers;
const tierTable = [
  '| tier | formats | raw JS | gzipped |',
  '|---|---|---|---|',
  `| light (<15 KB each) | ${t.light.formats} | ${num(t.light.bytes)} B | ${num(t.light.gzBytes)} B |`,
  `| medium (15-60 KB) | ${t.medium.formats} | ${num(t.medium.bytes)} B | ${num(t.medium.gzBytes)} B |`,
  `| heavy (>=60 KB) | ${t.heavy.formats} | ${num(t.heavy.bytes)} B | ${num(t.heavy.gzBytes)} B |`,
  `| shared imports | ${sizes.sharedImportFiles} | ${num(sizes.bytesForSharedImports)} B | ${num(t.sharedGzBytes)} B |`,
  `| **all ${sizes.specsGenerated} + shared** | **${sizes.specsGenerated}** | **${num(sizes.bytesForRequestedFormats + sizes.bytesForSharedImports)} B** | **${num(t.totalGzBytes)} B** |`,
].join('\n');

const share = (n) => `${((100 * n) / cov.binaryLabels).toFixed(1)}%`;
const coverageTable = [
  '| state | binary labels | share |',
  '|---|---|---|',
  `| parseable via a reader this repo generates and load-gates | **${cov.binaryGenerated}** | ${share(cov.binaryGenerated)}% |`,
  `| an upstream spec exists but the pinned compiler does not ship it | ${cov.binarySpecAvailable} | ${share(cov.binarySpecAvailable)}% |`,
  `| **no spec matched - real gap** | **${cov.gaps}** | ${share(cov.gaps)} |`,
].join('\n');

let doc = readFileSync('README.md', 'utf8');
const replace = (startMark, endMark, body) => {
  const from = doc.indexOf(startMark);
  const to = doc.indexOf(endMark, from);
  if (from < 0 || to < 0) throw new Error(`anchor not found: ${startMark}`);
  doc = `${doc.slice(0, from)}${body}\n\n${doc.slice(to === -1 ? doc.length : to)}`;
};

// A table is the contiguous run of lines starting with '|' that begins at the header row. Replacing
// the whole run keeps this idempotent without needing marker comments in the file.
function replaceTable(doc, headerPrefix, body) {
  const lines = doc.split('\n');
  const from = lines.findIndex((line) => line.startsWith(headerPrefix));
  if (from < 0) throw new Error(`table not found: ${headerPrefix}`);
  let to = from;
  while (to + 1 < lines.length && lines[to + 1].startsWith('|')) to += 1;
  lines.splice(from, to - from + 1, ...body.split('\n'));
  return lines.join('\n');
}

doc = replaceTable(doc, '| family | formats |', familyTable);
doc = replaceTable(doc, '| tier | formats |', tierTable);
doc = replaceTable(doc, '| state | binary labels |', coverageTable);

writeFileSync('README.md', doc);
console.log(`README synced: ${sizes.specsGenerated} formats, ${(t.totalGzBytes / 1024).toFixed(0)} KiB gz, coverage ${cov.binaryGenerated}/${cov.binaryLabels} binary labels`);
