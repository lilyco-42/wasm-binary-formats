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
  'catalog/v86-README.md': 'https://api.github.com/repos/copy/v86/readme',
};

for (const [path, url] of Object.entries(SOURCES)) {
  const headers = { 'user-agent': 'wasm-binary-formats source fetch', accept: 'application/vnd.github.raw+json' };
  if (process.env.GITHUB_TOKEN && url.startsWith('https://api.github.com/')) headers.authorization = `bearer ${process.env.GITHUB_TOKEN}`;
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
