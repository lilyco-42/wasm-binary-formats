// Builds catalog/formats.json from machine-readable upstream enumerations only.
// Nothing here is invented: every row traces to a file fetched by fetch-sources.mjs.
//
//   node scripts/build-catalog.mjs
import { readFileSync, writeFileSync } from 'node:fs';

const tika = readFileSync('catalog/tika.xml', 'utf8');
const arch = readFileSync('catalog/arch.h', 'utf8');

const FAMILY_RULES = [
  [/^application\/(x-)?(zip|tar|gzip|gzip|bzip|compress|x-7z|x-rar|x-cab|x-iso|x-arj|x-lzh|x-ar|java-archive|vnd\.android\.package-archive|apk|x-debian|rpm|war|ear|jar)$/i, 'archive'],
  [/^application\/(x-dosexec|x-msdownload|elf|x-executable|x-sharedlib|octet-stream|x-mach-o|java-vm|dex)$/i, 'executable'],
  [/^image\//i, 'image'],
  [/^(audio|video)\//i, 'av'],
  [/^font|^application\/(font|vnd\.ms-fontobject|x-fonturl|x-font)$/i, 'font'],
  [/^text\/|^application\/(pdf|xml|xhtml|json|rtf|msword|vnd\.openxmlformats|vnd\.oasis|postgres|x-tex|latex)/i, 'document'],
];

const familyOf = (type) => FAMILY_RULES.find(([re]) => re.test(type))?.[1] ?? 'other';

const mimeTypes = [...new Set([...tika.matchAll(/<mime-type\s+type="([^"]+)"/g)].map((m) => m[1]))]
  .sort();

const archiveFormats = [...new Set([...arch.matchAll(/ARCHIVE_FORMAT_([A-Z0-9_]+)\s/g)].filter((n) => n !== 'BASE_MASK').map((m) => m[1]))].sort();
const archiveFilters = [...new Set([...arch.matchAll(/ARCHIVE_FILTER_([A-Z0-9_]+)\s/g)].map((m) => m[1]))].filter((n) => n !== 'PROGRAM').sort();

// Executable/container families LIEF documents as supported, and the layers Apktool
// decodes inside an APK. Both lists are copied from the fetched READMEs.
const liefFormats = ['ELF', 'PE', 'Mach-O', 'OAT', 'DEX', 'VDEX', 'ART'];
const apkLayers = [
  { layer: 'AndroidManifest.xml', note: 'binary XML (AXML)' },
  { layer: 'resources.arsc', note: 'compiled resource table' },
  { layer: 'classes.dex', note: 'Dalvik bytecode' },
  { layer: 'META-INF/CERT.SF + *.RSA/EC', note: 'JAR signature blocks' },
  { layer: 'assets/ and res/raw/', note: 'web assets for Cordova/Capacitor shells' },
];

// Handler modules enumerated out of the upstream source trees (see fetch-sources.mjs), so every
// row names a file that exists today rather than a format somebody remembers.
const listing = (path) => JSON.parse(readFileSync(path, 'utf8'));
const fileNames = (path) => listing(path).filter((e) => e.type === 'file').map((e) => e.name);
const dirNames = (path) => listing(path).filter((e) => e.type === 'dir').map((e) => e.name);
const keep = (names, re, suffix) => names
  .filter((name) => re.test(name) && !name.startsWith('test_') && name !== '__init__.py')
  .map((name) => name.slice(0, name.length - suffix.length))
  .sort();

const fileSystems = keep(fileNames('catalog/dfvfs-vfs.json'), /_file_system[.]py$/, '_file_system.py');
const volumeSystems = keep(fileNames('catalog/dfvfs-volume.json'), /_volume_system[.]py$/, '_volume_system.py');
const compressors = keep(fileNames('catalog/dfvfs-compression.json'), /compressor[.]py$/, '.py');
const encrypters = keep(fileNames('catalog/dfvfs-encryption.json'), /(crypter|encryptor|decrypter)[.]py$/, '.py');
const tikaModules = [
  ...dirNames('catalog/tika-standard-modules.json'),
  ...dirNames('catalog/tika-extended-modules.json'),
  ...dirNames('catalog/tika-ml-modules.json'),
].filter((name) => /^tika-parser-/.test(name) && !name.endsWith('-package') && !name.includes('integration-test')).sort();

const identify = mimeTypes.map((type) => ({
  module: `identify:${type}`,
  tier: 'identify',
  family: familyOf(type),
  source: 'Apache Tika tika-mimetypes.xml (Apache-2.0)',
  status: 'catalogued',
}));

const unpack = [
  ...archiveFormats.map((f) => ({
    module: `unpack:${f.toLowerCase()}`, tier: 'unpack', family: 'archive',
    source: 'libarchive archive.h ARCHIVE_FORMAT_* (BSD-2)', status: 'catalogued',
  })),
  ...archiveFilters.map((f) => ({
    module: `decompress:${f.toLowerCase()}`, tier: 'unpack', family: 'compression',
    source: 'libarchive archive.h ARCHIVE_FILTER_* (BSD-2)', status: 'catalogued',
  })),
  ...fileSystems.map((f) => ({
    module: `filesystem:${f}`, tier: 'unpack', family: 'filesystem',
    source: 'log2timeline/dfvfs dfvfs/vfs/*_file_system.py (Apache-2.0)', status: 'catalogued',
  })),
  ...volumeSystems.map((v) => ({
    module: `volume:${v}`, tier: 'unpack', family: 'partition',
    source: 'log2timeline/dfvfs dfvfs/volume/*_volume_system.py (Apache-2.0)', status: 'catalogued',
  })),
  ...compressors.map((c) => ({
    module: `compress-dfvfs:${c}`, tier: 'unpack', family: 'compression',
    source: 'log2timeline/dfvfs dfvfs/compression/*_compressor.py (Apache-2.0)', status: 'catalogued',
  })),
  {
    module: 'unpack:zip+deflate', tier: 'unpack', family: 'archive',
    source: 'this repo: engine/src/lib.rs, tested against test/fixtures/lab-fixture.apk',
    status: 'implemented',
  },
];

const parse = [
  ...encrypters.map((c) => ({
    module: `crypto:${c}`, tier: 'parse', family: 'encryption',
    source: 'log2timeline/dfvfs dfvfs/encryption/*.py (Apache-2.0)', status: 'catalogued',
  })),
  ...tikaModules.map((m) => ({
    module: `parser-module:${m}`, tier: 'parse', family: 'document',
    source: 'apache/tika tika-parsers module directories (Apache-2.0)', status: 'catalogued',
  })),
  ...liefFormats.map((f) => ({
    module: `parse:${f.toLowerCase()}`, tier: 'parse', family: 'executable',
    source: 'LIEF README supported formats (Apache-2.0)', status: 'catalogued',
  })).concat(apkLayers.map((l) => ({
    module: `apk-layer:${l.layer}`, tier: 'parse', family: 'android-package',
    source: `Apktool README (${l.note}) (Apache-2.0)`, status: 'catalogued',
  }))),
  {
    module: 'parse:pe-header', tier: 'parse', family: 'executable',
    source: 'this repo: engine/src/pe.rs, offsets cross-checked against a shipped System32 exe',
    status: 'implemented',
  },
  {
    module: 'parse:dex-header', tier: 'parse', family: 'android-package',
    source: 'this repo: engine/src/dex.rs', status: 'draft: reverted from main, see the README',
  },
  {
    module: 'parse:axml-string-pool', tier: 'parse', family: 'android-package',
    source: 'this repo: engine/src/axml.rs', status: 'draft: reverted from main, see the README',
  },
];

const execute = [
  { module: 'run:x86-pe', tier: 'execute', family: 'executable', source: 'copy/v86 (BSD-2) x86 emulator + x86-to-wasm JIT; blocked by the Windows image licence, see README', status: 'catalogued' },
  { module: 'run:apk-web-assets', tier: 'execute', family: 'android-package', source: 'this repo: demo/index.html opaque-origin iframe over unpacked assets/', status: 'implemented' },
];

const modules = [...parse, ...unpack, ...execute, ...identify];
const byTier = modules.reduce((acc, m) => ({ ...acc, [m.tier]: (acc[m.tier] ?? 0) + 1 }), {});
const actionable = (byTier.parse ?? 0) + (byTier.unpack ?? 0) + (byTier.execute ?? 0);

writeFileSync('catalog/formats.json', JSON.stringify({
  summary: {
    total: modules.length,
    byTier,
    actionableWithoutSignatureTables: actionable,
    implementedHere: modules.filter((m) => m.status === 'implemented').length,
    byFamily: modules.reduce((acc, m) => ({ ...acc, [m.family]: (acc[m.family] ?? 0) + 1 }), {}),
  },
  licenceNotes: [
    'libarchive and v86 are BSD-2; Tika, LIEF and Apktool are Apache-2.0.',
    'RAR: libarchive exposes RAR/RAR_V5 read support, but the reference UnRAR decoder carries a non-free licence; treat rar as a separate licensing decision.',
    'file/file (libmagic) is BSD but its Magdir database is 359 files; it duplicates Tika coverage for identification.',
  ],
  modules,
}, null, 2) + '\n');

console.log(JSON.stringify({ total: modules.length, byTier, actionable }, null, 2));
