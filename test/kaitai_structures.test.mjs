// Real-byte assertions for the generated readers of six serialised / structured formats.
//
// Two of these fixtures come from a tool this repo does not control: `tiny.class` is the output of
// the installed javac (OpenJDK 17, hence major version 61) and `tiny-id3v23.mp3` is muxed by ffmpeg
// with `-id3v2_version 3 -metadata title=...`, so reading "Lab fixture" back out of `TIT2` is a
// round trip through two independent implementations. The other four are written by
// `scripts/make-structure-fixtures.py` straight from the published layouts - the same tier as the
// hand-built image fixtures, and clearly weaker, so they assert structure (counts, ids, terminator
// bytes) rather than semantic claims.
//
// Every assertion compares a scalar. Node inspects both operands of a failing `assert.equal` with no
// depth limit, and a parsed reader is a cyclic graph of `_parent` / `_root` / `_io` - one object
// comparison once cost 37 s and looked like a hung CI step.
//
//   node test/kaitai_structures.test.mjs path/to/generated   (default: generated/kaitai)
import { createRequire } from 'node:module';
import { readFileSync, statSync } from 'node:fs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const generatedDir = resolve(process.argv[2] ?? 'generated/kaitai');
const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const KaitaiStream = require('kaitai-struct/KaitaiStream');

function load(name) {
  const file = join(generatedDir, `${name}.js`);
  assert.ok(statSync(file).size > 0, `${file} is empty`);
  const mod = require(file);
  return mod[name] ?? mod.default
    ?? Object.values(mod).find((value) => typeof value === 'function')
    ?? mod;
}

const read = (name) => new Uint8Array(readFileSync(join(fixtures, name)));

const model = (name, fixture) => new (load(name))(new KaitaiStream(read(fixture)), null, null);

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const text = (bytes) => Buffer.from(bytes).toString('latin1');

test('JavaClass: the constant pool and counts javac 17 wrote', () => {
  const klass = model('JavaClass', 'tiny.class');
  assert.equal(hex(klass.magic), 'cafebabe', 'class files start with 0xCAFEBABE');
  assert.equal(klass.versionMinor, 0);
  assert.equal(klass.versionMajor, 61, 'major 61 is Java 17, the JDK installed here');
  assert.equal(klass.constantPoolCount, 27);
  assert.equal(
    klass.constantPool.length,
    klass.constantPoolCount - 1,
    'long/double entries consume two indices, which is why the count is one more than the array'
  );
  assert.equal(klass.accessFlags, 33, 'ACC_PUBLIC | ACC_SUPER');
  assert.equal(klass.thisClass, 19, 'the this-class pointer indexes into the pool above');
  assert.equal(klass.superClass, 2, 'java/lang/Object');
  assert.equal(klass.interfacesCount, 0);
  assert.equal(klass.fieldsCount, 0);
  assert.equal(klass.methodsCount, 2, '<init> and main');
  assert.equal(klass.attributesCount, 1, 'SourceFile');
});

test('Id3v23: the title ffmpeg was asked to write comes back through the frame table', () => {
  const id3 = model('Id3v23', 'tiny-id3v23.mp3');
  const header = id3.tag.header;
  assert.equal(hex(header.magic), '494433', "'ID3'");
  assert.equal(header.versionMajor, 3, '-id3v2_version 3, not the 2.4 the mp3 muxer uses by default');
  assert.equal(header.versionRevision, 0);
  assert.equal(header.flags.flagUnsynchronization, false);
  const frames = id3.tag.frames;
  assert.equal(frames.length, 2, 'one TIT2 plus one TSSE');
  assert.equal(frames[0].id, 'TIT2');
  assert.equal(frames[0].size, 13, 'encoding byte + "Lab fixture" + terminator');
  assert.equal(text(frames[0].data), '\x00Lab fixture\x00', 'the title we passed on the command line');
  assert.equal(frames[1].id, 'TSSE');
  assert.match(text(frames[1].data), /Lavf/, 'the encoder tag the muxer adds itself');
});

test('Pcap: the global header and one raw packet record', () => {
  const pcap = model('Pcap', 'tiny.pcap');
  assert.equal(hex(pcap.hdr.magicNumber), 'd4c3b2a1', 'read little-endian, the swapped form of 0xA1B2C3D4');
  assert.equal(pcap.hdr.versionMajor, 2);
  assert.equal(pcap.hdr.versionMinor, 4);
  assert.equal(pcap.hdr.snaplen, 65535);
  assert.equal(pcap.hdr.network, 101, 'DLT_RAW, so the payload stays opaque to this reader');
  assert.equal(pcap.packets.length, 1);
  const packet = pcap.packets[0];
  assert.equal(packet.tsSec, 1700000000);
  assert.equal(packet.tsUsec, 123456);
  assert.equal(packet.inclLen, 8);
  assert.equal(packet.origLen, 8, 'nothing was truncated, so both lengths agree');
  assert.equal(hex(packet.body), '4500001811223344');
});

test('StandardMidiFile: header, one track and the note-on event inside it', () => {
  const midi = model('StandardMidiFile', 'tiny.mid');
  assert.equal(hex(midi.hdr.magic), '4d546864', "'MThd'");
  assert.equal(midi.hdr.lenHeader, 6, 'the header chunk is always six bytes of body');
  assert.equal(midi.hdr.format, 1, 'format 1: one concurrent track plus accompaniment');
  assert.equal(midi.hdr.numTracks, 1);
  assert.equal(midi.hdr.division, 480, 'ticks per quarter note');
  assert.equal(midi.tracks.length, 1);
  const track = midi.tracks[0];
  assert.equal(hex(track.magic), '4d54726b', "'MTrk'");
  assert.equal(track.lenEvents, 12, 'the declared track length is the byte count of its events');
  assert.equal(track.events.event.length, 3, 'note on, note off, end of track');
  const [first] = track.events.event;
  assert.equal(first.eventHeader, 0x90, 'note on, channel 0');
  assert.equal(first.eventBody.note, 60, 'middle C');
  assert.equal(first.eventBody.velocity, 100);
  assert.equal(first.vTime.groups[0].hasNext, false, 'a delta time of zero is one byte');
});

test('Msgpack: a fixmap of three pairs', () => {
  const pack = model('Msgpack', 'tiny.msgpack');
  assert.equal(pack.b1, 0x83, 'high bits 1000 mean fixmap, low nibble is the pair count');
  assert.equal(pack.isFixMap, true);
  assert.equal(pack.isMap, true);
  assert.equal(pack.numMapElements, 3);
  assert.equal(pack.mapElements.length, 3);
  assert.equal(pack.mapElements[0].key.strValue, 'n', 'a1 6e is a fixstr of one byte');
  assert.equal(pack.mapElements[0].value.b1, 127, '0x7f is the positive fixint 127');
});

test('Bson: three elements and the terminator the document length counts', () => {
  const bson = model('Bson', 'tiny.bson');
  assert.equal(bson.len, 35, 'the int32 length counts itself, the elements and the terminator');
  const elements = bson.fields.elements;
  assert.equal(elements.length, 3);
  assert.equal(elements[0].typeByte, 0x10, 'int32');
  assert.equal(elements[0].name.str, 'n');
  assert.equal(elements[0].content, 7);
  assert.equal(elements[1].typeByte, 0x02, 'utf8 string, whose own length includes its NUL');
  assert.equal(elements[2].typeByte, 0x12, 'int64');
  assert.equal(Number(elements[2].content), 2 ** 40);
  assert.equal(hex(bson.terminator), '00');
});
