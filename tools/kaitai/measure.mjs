// Measures what a Kaitai .ksy costs once it becomes a JavaScript reader, grouped by format
// family. Run after the compiler: node tools/kaitai/measure.mjs <generated-dir> [out.json]
import { gzipSync } from 'node:zlib';
import { readFileSync, writeFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const outFile = process.argv[3] ?? '';

const specs = readFileSync(join(here, 'specs.txt'), 'utf8')
  .split('\n').map((line) => line.trim()).filter(Boolean)
  .map((path) => ({ category: path.slice(0, path.lastIndexOf('/')), id: path.slice(path.lastIndexOf('/') + 1) }));

// The compiler names each output after the spec's type id, one PascalCase word per underscore.
const className = (id) => id.split('_').map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join('');

const present = new Set(readdirSync(generatedDir).filter((name) => name.endsWith('.js')));

const rows = specs.map((spec) => {
  const file = `${className(spec.id)}.js`;
  const size = present.has(file) ? statSync(join(generatedDir, file)).size : -1;
  const gzSize = size >= 0 ? gzipSync(readFileSync(join(generatedDir, file))).length : -1;
  return { ...spec, className: className(spec.id), file, size, gzSize };
});

const missing = rows.filter((row) => row.size < 0).map((row) => row.className);
const generated = new Set(rows.map((row) => row.file));
const sharedImports = [...present].filter((name) => !generated.has(name)).map((name) => ({
  file: name, size: statSync(join(generatedDir, name)).size,
}));

const byCategory = {};
for (const row of rows) {
  if (row.size < 0) continue
  const bucket = (byCategory[row.category] ??= { formats: 0, bytes: 0, files: [] });
  bucket.formats += 1;
  bucket.bytes += row.size;
  bucket.files.push(`${row.className}=${row.size}`);
}
const importBytes = sharedImports.reduce((sum, item) => sum + item.size, 0);

const tiers = { light: [], medium: [], heavy: [] };
for (const row of rows) {
  if (row.size < 0) continue;
  tiers[row.size < 15000 ? 'light' : row.size < 60000 ? 'medium' : 'heavy'].push(row);
}
const tierSummary = Object.fromEntries(Object.entries(tiers).map(([name, group]) => [name, {
  formats: group.length,
  bytes: group.reduce((sum, row) => sum + row.size, 0),
  gzBytes: group.reduce((sum, row) => sum + row.gzSize, 0),
}]));
tierSummary.sharedGzBytes = sharedImports.reduce((sum, item) => sum + gzipSync(readFileSync(join(generatedDir, item.file))).length, 0);
tierSummary.totalGzBytes = Object.values(tierSummary).reduce((sum, v) => sum + (typeof v === 'object' ? v.gzBytes : 0), 0);
const formatBytes = rows.reduce((sum, row) => sum + Math.max(row.size, 0), 0);

const summary = {
  compiler: 'kaitai-struct-compiler 0.11',
  target: 'javascript',
  specsRequested: specs.length,
  specsGenerated: rows.length - missing.length,
  missing,
  sharedImportFiles: sharedImports.length,
  bytesForRequestedFormats: formatBytes,
  bytesForSharedImports: importBytes,
  tiers: tierSummary,
  meanBytesPerFormat: rows.length - missing.length ? Math.round(formatBytes / (rows.length - missing.length)) : 0,
  largest: rows.filter((r) => r.size > 0).sort((a, b) => b.size - a.size).slice(0, 5).map((r) => `${r.className}=${r.size}`),
  smallest: rows.filter((r) => r.size > 0).sort((a, b) => a.size - b.size).slice(0, 5).map((r) => `${r.className}=${r.size}`),
  byCategory: Object.fromEntries(Object.entries(byCategory).map(([k, v]) => [k, { formats: v.formats, bytes: v.bytes }])),
};

for (const [category, bucket] of Object.entries(byCategory).sort((a, b) => b[1].bytes - a[1].bytes)) {
  console.log(`${category.padEnd(15)} ${String(bucket.formats).padStart(2)} formats  ${String(bucket.bytes).padStart(7)} B   ${bucket.files.slice(0, 4).join(' ')}${bucket.files.length > 4 ? ' …' : ''}`);
}
console.log(`total ${summary.specsGenerated}/${summary.specsRequested} generated · ${formatBytes} B formats + ${importBytes} B shared (${sharedImports.length} files) · mean ${summary.meanBytesPerFormat} B`);
if (missing.length) console.log(`MISSING: ${missing.join(' ')}`);
if (outFile) writeFileSync(outFile, JSON.stringify({ ...summary, rows }, null, 2) + '\n');
process.exitCode = missing.length ? 1 : 0;
