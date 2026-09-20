// Builds catalog/coverage.json: what share of magika's content-type taxonomy this repo can actually
// parse, with no credit given for anything not backed by a file that exists. magika's KB is used as
// the definition of "common formats" because it is a maintained, citable enumeration rather than a
// list we invent.
//
//   node tools/coverage.mjs
import { readFileSync, writeFileSync } from 'node:fs';

const kb = JSON.parse(readFileSync('catalog/magika-kb.json', 'utf8'));
// The GitHub tree API payload is committed as fetched, so unwrap it here rather than trusting a
// hand-edited copy of the spec list.
const specPaths = JSON.parse(readFileSync('catalog/kaitai-specs.json', 'utf8')).tree.map((e) => e.path);
const specs = specPaths
  .filter((path) => path.endsWith('.ksy'))
  .map((path) => path.slice(0, -4))
  .map((path) => ({ category: path.slice(0, path.lastIndexOf('/')), id: path.slice(path.lastIndexOf('/') + 1) }));

const generated = new Set(JSON.parse(readFileSync('catalog/kaitai-sizes.json', 'utf8')).rows
  .filter((r) => r.size > 0).map((r) => r.file.replace(/[.]js$/, '')));

const implemented = JSON.parse(readFileSync('catalog/formats.json', 'utf8')).modules
  .filter((m) => m.status === 'implemented')
  .map((m) => m.module);

// Only unambiguous equivalences. A label with no entry here is reported as a gap, never as covered,
// so the list can be audited instead of trusted.
// What this repo's own Rust engine reads, and at what level. "container" means the framing is
// parsed (member names, sizes, chunk or tag lists) without claiming the document's semantics: a zip
// reader does not parse a .docx. "fields" means named header fields are decoded.
const SELF = {
  tar: ['container'], ar: ['container'], deb: ['container'], riff: ['container'],
  webp: ['container'], tiff: ['fields'], pebin: ['fields'], exe: ['fields'], dll: ['fields'], sys: ['fields'],
  ocx: ['fields'], cpl: ['fields'], scr: ['fields'], dex: ['fields'], elf: ['fields'], swf: ['fields'],
  zip: ['container'], jar: ['container'], apk: ['container'], gzip: ['fields'], sqlite: ['fields'],
  xz: ['fields'], bzip: ['fields'], lz4: ['fields'], zst: ['container'],
  mp4: ['fields'], mkv: ['fields'], webm: ['fields'], avi: ['container'], avif: ['container'],
  '3gp': ['fields'], asf: ['container'], wma: ['container'], wmv: ['container'],
  flv: ['container'], cab: ['container'], mpegts: ['fields'],
  flac: ['fields'], mp3: ['fields'], mp2: ['fields'], ogg: ['fields'], wav: ['fields'],
  pdf: ['fields'], pbm: ['fields'], wasm: ['fields'], ttf: ['fields'], woff: ['fields'], icns: ['fields'],
  applebplist: ['fields'], qoi: ['fields'], jp2: ['fields'], woff2: ['fields'],
  docx: ['container'], xlsx: ['container'], pptx: ['container'],
  odt: ['container'], ods: ['container'], odp: ['container'], epub: ['container'],
};

const ALIAS = {
  pebin: ['microsoft_pe'], exe: ['microsoft_pe'], dll: ['microsoft_pe'], sys: ['microsoft_pe'], ocx: ['microsoft_pe'], cpl: ['microsoft_pe'], scr: ['microsoft_pe'],
  elf: ['elf'], so: ['elf'], ko: ['elf'], rlib: ['elf'], object: ['elf'],
  macho: ['mach_o'], dylib: ['mach_o'],
  dex: ['dex'], javabytecode: ['java_class'], pythonbytecode: ['python_pyc_27'],
  zip: ['zip'], jar: ['zip'], apk: ['zip'], crx: ['zip'], xpi: ['zip'], nupkg: ['zip'], docx: ['zip'], xlsx: ['zip'], pptx: ['zip'], odt: ['zip'], odp: ['zip'], ods: ['zip'], epub: ['zip'], npz: ['zip'], msix: ['zip'], ooxml: ['zip'],
  gzip: ['gzip'], zlibstream: ['gzip'], tar: ['tar'], ar: ['ar'], cpio: ['cpio_old_le'], rar: ['rar'], sevenzip: ['seven_z'], xar: ['xar'], rpm: ['rpm'], deb: ['deb'],
  png: ['png'], jpeg: ['jpeg'], gif: ['gif'], bmp: ['bmp'], tiff: ['tiff'], ico: ['ico'], icns: ['icns'], tga: ['tga'], pcx: ['pcx'], wmf: ['wmf'], dicom: ['dicom'], xcf: ['xcf'], psd: ['psd'], qoi: ['qoi'],
  wav: ['wav'], riff: ['riff'], au: ['au'], avi: ['avi'], mp4: ['quicktime_mov'], qt: ['quicktime_mov'], mkv: ['matroska'], webm: ['matroska'], ebml: ['ebml'], ogg: ['ogg'], flac: ['flac'], mp3: ['id3v2_3'], midi: ['standard_midi_file'], aac: ['adts'], asf: ['asf'], flv: ['flv'], wma: ['asf'], wmv: ['asf'], webp: ['webp'], heif: ['heif'], avif: ['avif'],
  sqlite: ['sqlite3'], dbf: ['dbf'], jsonl: ['json'], protobuf: ['google_protobuf'], bson: ['bson'], msgpack: ['msgpack'], pickle: ['python_pickle'], marshal: ['ruby_marshal'], php: ['php_serialized_value'], ole: ['microsoft_cfb'], msi: ['microsoft_cfb'], cdf: ['microsoft_cfb'], visio: ['microsoft_cfb'],
  iso: ['iso9660'], udf: ['udf'], img: ['raw'], hfs: ['hfsplus'], ext2: ['ext2'], fat: ['vfat'], ntfs: ['ntfs'], squashfs: ['squashfs'], erofs: ['erofs'], vhd: ['vhd'], dmg: ['dmg'], wim: ['wim'], vmdk: ['vmware_vmdk'], mbr: ['dos_mbr'], gpt: ['gpt_partition_table'], lnk: ['windows_lnk_file'], winregistry: ['regf'], dsstore: ['ds_store'], thumbsdb: ['thumbs_db'], chm: ['chm'], pcap: ['pcap'],
  bzip: ['bz2'], bzip3: ['bz3'], xz: ['xz'], lz4: ['lz4'], zstd: ['zst'], compress: ['unix_compress'], lha: ['lzh'], arc: ['arc'], arj: ['arj'], cab: ['cab'], lz: ['lzma'], lzx: ['lzx'], mscompress: ['xxx'], rzip: ['rzip'], zisofs: ['zisofs'],
  android_sparse: ['android_sparse'], odex: ['dex'], ocx2: ['dex'], smali: ['smali'], wasm: ['wasm'], swf: ['swf'], pdf: ['pdf'], rtf: ['rtf'], postscript: ['postscript'], ps: ['postscript'], onnx: ['onnx'], parquet: ['parquet'], avro: ['avro'], h5: ['hdf5'], arrow: ['arrow'], npy: ['npy'],
};

const specIds = new Set(specs.map((s) => s.id));
const rows = Object.entries(kb).map(([label, meta]) => {
  const wanted = ALIAS[label] ?? [];
  const matched = wanted.filter((id) => specIds.has(id));
  const isGenerated = matched.some((id) => generated.has(id.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('')));
  return {
    label,
    group: meta.group ?? 'unknown',
    mime: meta.mime_type ?? '',
    isText: Boolean(meta.is_text),
    extensions: meta.extensions ?? [],
    kaitaiSpecs: matched,
    generatedHere: isGenerated,
    selfLevel: (SELF[label] ?? [''])[0],
    status: (SELF[label] ?? [''])[0] ? `self-${(SELF[label] ?? [''])[0]}`
      : isGenerated ? 'spec-generated'
      : matched.length ? 'spec-available'
      : meta.is_text ? 'text' : 'gap',
  };
});

const by = (status) => rows.filter((r) => r.status === status);
const byBinary = (status) => binary.filter((r) => r.status === status);
const binary = rows.filter((r) => !r.isText);
const summary = {
  source: 'google/magika content_types_kb.min.json (Apache-2.0)',
  labels: rows.length,
  binaryLabels: binary.length,
  textLabels: rows.length - binary.length,
  specGenerated: by('spec-generated').length,
  specAvailable: by('spec-available').length,
  binaryGenerated: byBinary('spec-generated').length,
  selfFields: binary.filter((r) => r.status === 'self-fields').length,
  selfContainer: binary.filter((r) => r.status === 'self-container').length,
  binarySpecAvailable: byBinary('spec-available').length,
  gaps: byBinary('gap').length,
  implementedHere: implemented,
  gapByGroup: binary.filter((r) => r.status === 'gap').reduce((acc, r) => ({ ...acc, [r.group]: (acc[r.group] ?? 0) + 1 }), {}),
};

writeFileSync('catalog/coverage.json', JSON.stringify({ summary, rows }, null, 2) + '\n');
console.log(JSON.stringify({ ...summary, gapByGroup: undefined, implementedHere: undefined }, null, 2));
console.log('gaps (sample):', by('gap').slice(0, 40).map((r) => r.label).join(' '));
