// Fetches the upstream enumerations the catalog is derived from, so the counts can be
// re-verified instead of trusted.
//
//   node scripts/fetch-sources.mjs
import { writeFileSync } from 'node:fs';

const SOURCES = {
  'catalog/tika.xml': 'https://raw.githubusercontent.com/apache/tika/main/tika-core/src/main/resources/org/apache/tika/mime/tika-mimetypes.xml',
  'catalog/arch.h': 'https://raw.githubusercontent.com/libarchive/libarchive/master/libarchive/archive.h',
  'catalog/LIEF-README.md': 'https://raw.githubusercontent.com/lief-project/LIEF/main/README.md',
  'catalog/Apktool-README.md': 'https://raw.githubusercontent.com/iBotPeaches/Apktool/master/README.md',
  // Resolved through the API because the readme's filename and default branch differ
  // per repository, and guessing them produced a 404.
  'catalog/magika-kb.json': 'https://raw.githubusercontent.com/google/magika/main/python/src/magika/config/content_types_kb.min.json',
  // The full upstream spec list, so "no spec exists" is a checked fact rather than an assumption.
  'catalog/kaitai-specs.json': 'https://api.github.com/repos/kaitai-io/kaitai_struct_formats/git/trees/master?recursive=1',
  'catalog/v86-README.md': 'https://api.github.com/repos/copy/v86/readme',
};

// Handler modules are enumerated from the source trees themselves rather than from prose, so
// every row in the catalogue traces back to a file that exists upstream today.
const LISTINGS = {
  'catalog/dfvfs-vfs.json': 'https://api.github.com/repos/log2timeline/dfvfs/contents/dfvfs/vfs',
  'catalog/dfvfs-volume.json': 'https://api.github.com/repos/log2timeline/dfvfs/contents/dfvfs/volume',
  'catalog/dfvfs-compression.json': 'https://api.github.com/repos/log2timeline/dfvfs/contents/dfvfs/compression',
  'catalog/dfvfs-encryption.json': 'https://api.github.com/repos/log2timeline/dfvfs/contents/dfvfs/encryption',
  'catalog/tika-standard-modules.json': 'https://api.github.com/repos/apache/tika/contents/tika-parsers/tika-parsers-standard/tika-parsers-standard-modules',
  'catalog/tika-extended-modules.json': 'https://api.github.com/repos/apache/tika/contents/tika-parsers/tika-parsers-extended',
  'catalog/tika-ml-modules.json': 'https://api.github.com/repos/apache/tika/contents/tika-parsers/tika-parsers-ml',
};

for (const [path, url] of Object.entries(LISTINGS)) {
  const headers = { 'user-agent': 'wasm-binary-formats source fetch', accept: 'application/vnd.github+json' };
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token) headers.authorization = `bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    console.error(`${path}: HTTP ${res.status} from ${url}`);
    process.exitCode = 1;
    continue;
  }
  const body = await res.text();
  writeFileSync(path, body);
  console.log(`${path}: ${JSON.parse(body).length} entries`);
}

for (const [path, url] of Object.entries(SOURCES)) {
  const headers = { 'user-agent': 'wasm-binary-formats source fetch', accept: 'application/vnd.github.raw+json' };
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (token && url.startsWith('https://api.github.com/')) headers.authorization = `bearer ${token}`;
  const res = await fetch(url, { headers });
  if (!res.ok) {
    console.error(`${path}: HTTP ${res.status} from ${url}`);
    process.exitCode = 1;
    continue;
  }
  const body = await res.text();
  writeFileSync(path, body);
  console.log(`${path}: ${body.length} bytes`);
}
