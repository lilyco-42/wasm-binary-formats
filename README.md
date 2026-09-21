# wasm-binary-formats

Requirement this repo exists to answer: **unpack an APK, run the web assets inside it, and support
exe and other binary formats — as wasm modules, ≥200 of them.**

This repo is preflight output, not an implementation. Its job is to make the "≥200" number
auditable before any code is written, and to say plainly which parts of it are cheap and which
are not.

## What "support" splits into (the cost differs by two orders of magnitude)

| Tier | Meaning | Count today | Where the count comes from |
|---|---|---|---|
| `identify` | read magic bytes / declare a type | 1688 | Apache Tika `tika-mimetypes.xml` (Apache-2.0) |
| `unpack` | list entries, extract files, walk filesystems and volumes | 87 | libarchive `archive.h` (BSD-2) + dfVFS `dfvfs/vfs`, `dfvfs/volume`, `dfvfs/compression` (Apache-2.0) |
| `parse` | structured parsing of executables, package layers and parser modules | 49 | LIEF formats + Apktool layers + Tika `tika-parser-*` module directories + dfVFS encryption handlers |
| `execute` | actually run the thing | 2 | v86 x86 emulator (BSD-2) for `.exe`; this repo's opaque-origin sandbox for APK `assets/` |

**Actionable today: 138. Implemented and tested in wasm here: 5** (`unpack:zip+deflate`,
`parse:pe-header`, `parse:dex-header`, `parse:axml-string-pool`, `run:apk-web-assets`) - the
`implementedHere` field in `catalog/formats.json` carries that number and CI refuses to let it drop.

The 1688 identification rows are a signature table, not 1688 modules — counting them to reach "200"
would be padding, so this file states 138 instead. The sibling
[wasm-pixel-kernels](https://github.com/lilyco-42/wasm-pixel-kernels) repo adds 65 more wasm modules
that are each numerically tested against an independent reference, which is the honest way to read
a module count: 70 shipped and tested, not 1826 catalogued.

## Path from 138 to 200 actionable, still all from citable enumerations

1. Media containers and metadata (mp4, mkv, avi, webm, flac, ogg, mp3, id3, exif, xmp, icc):
   enumerate from MediaInfo's format list — the only source that would add ~50 real handlers at once.
2. Documents beyond the Tika module names (pdf object level, docx/xlsx/pptx parts, odt, rtf, epub):
   Tika's *parser* modules are counted, their per-format handlers are not.
3. Package wrappers (deb, rpm, xapk, apks, crx, snap, flatpak, vsix): each is an archive plus one
   metadata file, cheap once `unpack:zip+deflate` and `unpack:tar` exist.
4. Filesystems dfVFS reaches through TSK rather than implementing itself — those should be counted
   as libyal/tsk modules, not as work here.

Each is a fetch-and-enumerate step like the five sources already wired into
`scripts/fetch-sources.mjs`; nothing on that list is invented later from memory.

## What is implemented, not just counted

* `engine/` (`apk-lens`, MIT) — zip/APK reader exposed through a plain C ABI so the JS side needs
  no glue: `open / count / entry / extract / parse_pe / pe_sections / last_error`. Handles stored
  *and* deflated entries; nothing touches disk, no path is resolved.
* PE header inspection (`engine/src/pe.rs`) — machine, PE32 vs PE32+, entry RVA, image base,
  subsystem, `IMAGE_FILE_DLL`, section table, and the COM descriptor that marks a .NET image.
  Every offset is bounds-checked against the file. **This reads, it does not run.**

  The declared `SizeOfOptionalHeader` is used but validated: an implausible value falls back to
  the canonical 224/240 for the magic, while a legal-but-smaller 216 (96 standard bytes plus 15
  directories, which real PE32 images use) is honoured — forcing the canonical size would shift
  the section table by eight bytes.
* `engine/src/dex.rs` and `engine/src/axml.rs` — the two formats that live *inside* the unpacked
  APK: the `classes.dex` header (version, checksum, `file_size`, endian tag, the id-table counts)
  and the `AndroidManifest.xml` string pool in both its UTF-16 and UTF-8 forms. Attribute-level
  manifest decoding is deliberately not attempted: it needs the resource ID table from
  `resources.arsc`, and guessing at it would print a package name that is wrong some of the time.
* `demo/index.html` — unpacks an APK client-side and runs `assets/**.html` in an opaque-origin
  sandbox with relative references rewritten to `data:` URLs; `classes.dex` and a binary
  `AndroidManifest.xml` render as a DEX header table and a string-pool dump, `.exe`/`.dll` as the PE
  panel, and anything else the engine recognises as the rows its reader returns — package, container,
  audio or stream, each named by the reader that accepted the bytes rather than by a code table in
  the page. All dispatched on magic bytes rather than filename (verified in the deployed page: DEX 035
  with checksum `0xdeadbeef`, and the pool's three strings, alongside `GUEST_RAN@null` from the
  sandboxed web asset; and against `gnu.tar`, `media.mkv`, `media.flac`, `tiny.pdf` and `tiny.docx`
  opened in a real browser).
  Live at <https://lilyco-42.github.io/wasm-binary-formats/>.
* `test/fixtures/lab-fixture.apk` — a hand-written, deterministic APK-shaped archive (8 entries,
  mixed stored/deflated, `AndroidManifest.xml` starting with the real res chunk type 0x0003).
  Because it is written from the spec rather than by the same Rust crate that reads it, it checks
  the reader against something other than itself. Regenerate with `node scripts/make-fixture.mjs`.


## Path from 61 to 200 actionable, all from citable enumerations

1. Filesystems (ext2/4, fat, ntfs, hfs+, apfs, f2fs, erofs, squashfs, iso9660, vmdk/qcow2/vhdx):
   enumerate from `dfVFS`/libyal and `erofs-utils` rather than inventing names.
2. Media containers and metadata (mp4, mkv, avi, webm, flac, ogg, mp3, id3, exif, xmp, icc):
   enumerate from MediaInfo's format list.
3. Documents (pdf, docx, xlsx, pptx, odt, rtf, epub): Tika *parser* modules, not its mime table.
4. Package formats (deb, rpm, apk, xapk, apks, crx, snap, flatpak, vsix): each is a thin wrapper
   over an archive plus a metadata file — cheap once `unpack:zip` exists.

Each of those is a fetch-and-enumerate step like the three sources already wired up.

## Licence landmines found during preflight

* **rar**: libarchive exposes `RAR`/`RAR_V5` read slots, but the reference UnRAR decoder carries a
  non-free licence. Decide before shipping rar support.
* `file`/libmagic is BSD and its `magic/Magdir` holds 359 definition files, but it duplicates Tika
  for identification — picking both buys nothing.
* Apktool is Java, so it is a *behavioural reference* here, not a dependency to compile.

## The APK "run the web version" part is not a parsing problem

Unpacking is tier 2 and easy. Running the extracted `assets/` web app means serving attacker-
controlled JS. The demo uses `<iframe sandbox="allow-scripts">` **without** `allow-same-origin`,
which per the HTML spec gives the document a special origin that always fails the same-origin
test ([iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe),
[sandboxed feature](https://html.spec.whatwg.org/multipage/iframe-embed-object.html#attr-iframe-sandbox)),
so it provably cannot read this site's cookies, `localStorage`, IndexedDB or parent DOM. The
documented self-escape of `sandbox` needs `allow-scripts` **and** `allow-same-origin` together,
which is exactly the combination not used here.

What that shape cannot do, and why:

| Guest feature | Works? | Reason |
|---|---|---|
| classic `<script>` / `<link>` / `<img>` | yes, via `data:` URLs | **`blob:` does not work**: measured in Chromium, a `sandbox="allow-scripts"` frame without `allow-same-origin` never executes a `blob:` script minted by the host, while the identical URL loads fine in an unsandboxed frame and an inline script runs fine in the sandboxed one. The isolation boundary and the storage key are the same thing here ([FileAPI §8.3](https://w3c.github.io/FileAPI/#blob-url)) |
| `fetch()`/XHR to a relative path, history routing, path-based routers | no | a `data:`/`blob:` document has no path space to resolve against, and the frame policy sets `connect-src 'none'` |
| `<script type="module">` | no | module scripts require the CORS protocol ([host-environment-resolution](https://html.spec.whatwg.org/multipage/webappapis.html#host-environment-resolution)) |
| Web Worker, `localStorage`, `document.cookie` | no | opaque origin + no storage; measured `localStorage.getItem` throws inside the guest ([Worker](https://developer.mozilla.org/en-US/docs/Web/API/Worker/Worker)) |
| its own Service Worker | no | SW needs same-origin + secure context ([Using SW](https://developer.mozilla.org/en-US/docs/Web/API/Service_Worker_API/Using_Service_Workers)) |

Every one of those rows was measured in the deployed page rather than read off the spec: inline
guest script arrives at the host as a `postMessage` with `origin: "null"`, `data:` script /
stylesheet / image all load, `localStorage` throws, and `blob:` silently does nothing.

Un-rewritten references in a `srcdoc` document resolve against **this page's** URL, so they hit
GitHub Pages rather than the archive; outbound network calls by guest script are not stopped by
`sandbox` alone. Two layers that do apply: a Chrome-only `csp` attribute on the frame
([HTMLIFrameElement.csp](https://developer.mozilla.org/en-US/docs/Web/API/HTMLIFrameElement/csp),
not usable via `<meta>`) and `referrerpolicy="no-referrer"`. Host-side previews still use `blob:`
and revoke them on every render, because a leaked `blob:https://lilyco-42.github.io/…` HTML
document opened in a new tab runs as first-party on the origin shared by every Pages site.

Getting the missing features means a real guest origin, and COOP/COEP is not the lever — those
only produce `crossOriginIsolated` for `SharedArrayBuffer` and finer timers
([why-coop-coep](https://web.dev/articles/why-coop-coep),
[StackBlitz](https://blog.stackblitz.com/posts/cross-browser-with-coop-coep/)). A second hostname
with its own Service Worker is the lever, which GitHub Pages cannot provide (no header control,
[discussion #13309](https://github.com/orgs/community/discussions/13309)); CodeSandbox/Sandpack
make the same choice for the same reason ([issue #686](https://github.com/codesandbox/sandpack/issues/686)).
So: self-host the demo on its own subdomain before promising routers, modules or workers.

## Can a browser run an `.exe`? Yes, and that is not the question

Verified against the projects themselves on 2026-09-19:

* [copy/v86](https://github.com/copy/v86) — BSD-2-Clause, 23,502 ★, pushed 2026-09-14. Full x86
  PC emulation, 32-bit only, with an x86→wasm JIT (`disable_jit` appears in the shipped
  `libv86.js`; `SharedArrayBuffer`, `Atomics` and `crossOriginIsolated` appear **0** times, so
  the hosted build needs no COOP/COEP). Its own [docs](https://github.com/copy/v86/blob/master/docs/windows-nt.md)
  list which Windows versions boot, and every Windows profile on copy.sh is marked proprietary —
  so running Windows there still requires a Windows disk image.
* [danoon2/Boxedwine](https://github.com/danoon2/Boxedwine) — **GPL-2.0**, 1,084 ★, active. Runs
  16/32-bit `.exe` through Wine over its own x86 emulator with a Linux rootfs, i.e. no Windows
  image, but GPL reaches into anything linked into the shipped bundle. The original
  `inexorabletash/BoxedWine` is now a 404.
* [caiiiycuk/js-dos](https://github.com/caiiiycuk/js-dos) — 1,336 ★ with **no licence file at all**
  (its backends are GPL-2.0); unusable for a commercial product on that basis alone.

Cost either way: `v86.wasm` alone is 2,101,621 B, and a BoxedWine web build ships ~2.5 MB of wasm
plus a ~10 MB overlay and a ~50 MB Wine rootfs — against this repo's entire engine, which is around
200 KB (`engine/target/wasm32-unknown-unknown/release/apk_lens.wasm`, reported by CI). Modern Win32
(64-bit, current .NET) is out of reach regardless.

**Decision: do not ship execution.** Ship inspection (`engine/src/pe.rs`) plus an honest "use the
native build to run it". If execution is ever wanted, the licence-clean combination is v86 (BSD-2)
with a freely redistributable guest such as ReactOS, sold as "legacy 16/32-bit", not as "run your
.exe".


## Breadth: the Kaitai route, measured rather than assumed

The ">=200 modules" requirement is not answered by hand-writing 200 readers. It is answered by
[kaitai-io/kaitai_struct_formats](https://github.com/kaitai-io/kaitai_struct_formats): **189
`.ksy` specs** (counted from the git tree, star 795, pushed 2026-09-18), from whose descriptions
the compiler emits parsers for 13 languages including JavaScript and Rust.
`.github/workflows/kaitai.yml` proves the pipe end to end: it downloads compiler 0.11 by checksum,
generates readers for **50 specs across 13 families** (`tools/kaitai/specs.txt`), and parses
fixtures against them. Two levels are asserted separately on purpose - a load gate for
all 50 (`test/kaitai_catalog.test.mjs`, 2 tests) and byte-level correctness for the 22 formats that
have a fixture: PNG, GIF, BMP, ICO, gzip, TGA and SQLite (`test/kaitai.test.mjs`, 8
tests, mean reader 13.7 KB), JPEG and ZIP (`test/kaitai_formats.test.mjs`, 2 tests), and WAVE, the
generic RIFF, Ogg, MOV/MP4, AU and PCX (`test/kaitai_media.test.mjs`, 7 tests) read from files
ffmpeg muxed and Pillow wrote, plus the class file `javac` 17 wrote, an ID3v2.3 tag ffmpeg muxed on
request, and hand-built MIDI / pcap / BSON / MessagePack
(`test/kaitai_structures.test.mjs`, 6 tests) plus a real ELF read off the runner itself (`test/kaitai_exec.test.mjs`, 1 test, skipped where no system binary exists). The strongest of those is the ID3 one: the reader has
to return the exact title that was passed to the muxer two implementations earlier. The media assertions are a three-way check: the same bytes are also
read by this repo's Rust
engine and by `ffprobe`, so a shared wrong assumption has to be wrong in three places to pass.
The one media spec that fails on a real file is asserted as a gap instead of dropped - see
`test/kaitai_media.test.mjs` and the AVI note below.
"It generated" is never reported as "it parses".


* Licences: **compiler GPLv3+** (so it runs in CI and is never shipped), **JS runtime
  `kaitai-struct@0.11.0` Apache-2.0**, Python and Rust runtimes MIT. What kaitai.io does **not**
  state is the licence of generated code - that has to be settled in writing before a generated
  reader is linked into a paid product.
* Measured runtime trap: `new Png(uint8)` left `_io` without `readBytes` on Node 22, while
  `new Png(new KaitaiStream(bytes), null, null)` parsed the same file completely and returned the
  full three-chunk list. Drive generated readers with an explicit stream.
* Not every generated reader is drop-in drivable, measured on two of them: `Wav` (built on
  `common/riff`) exposes only a `chunk` root, so the interesting fields sit one object-tree walk
  away, and `Ipv4Packet` threw `requested 4 bytes, but only 0 bytes available` on a spec-correct
  24-byte packet (IHL 5, `totalLength` 24, protocol 6) even with 8 and 16 bytes of slack appended.
  Both stay in the load gate, not the assertion set, until that is understood - which is the reason
  the two levels exist.
* [ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns) holds 314 `.hexpat` format
  descriptions but is **GPL-2.0**: something to read, not to vendor. For identification,
  [google/magika](https://github.com/google/magika) (star 18622, Apache-2.0) is the permissive pick.


### What that costs, by family

Re-generated on CI from compiler 0.11 (the numbers below are the CI numbers, not a local run):

| family | formats | raw JS | gzipped | heaviest |
|---|---|---|---|---|
| image | 9 | 455,301 B | 77,230 B | Dicom 347,766 B |
| executable | 8 | 306,134 B | 12,242 B | MachO 92,584 B |
| media | 7 | 94,956 B | 8,308 B | Wav 33,543 B |
| archive | 7 | 90,431 B | 8,589 B | Rpm 38,514 B |
| serialization | 6 | 88,220 B | 4,303 B | PythonPickle 24,181 B |
| font | 1 | 52,968 B | 9,686 B | Ttf 52,968 B |
| filesystem | 4 | 46,764 B | 3,782 B | Vfat 16,072 B |
| windows | 2 | 29,625 B | 3,242 B | Regf 15,847 B |
| network | 2 | 18,193 B | 4,689 B | Pcap 14,028 B |
| macos | 1 | 15,646 B | 2,980 B | DsStore 15,646 B |
| database | 1 | 13,475 B | 3,026 B | Sqlite3 13,475 B |
| common | 1 | 11,858 B | 2,254 B | Riff 11,858 B |
| log | 1 | 9,437 B | 2,201 B | SystemdJournal 9,437 B |
| **total** | **50** | **1,233,008 B** | 258,654 B | + 13 shared files, 108,293 B raw |

**Three tiers, because the mean hides the tail.** 22 formats stay under 15 KB apiece (189 KB
together) and can ship in one bundle; 12 land between 15 and 60 KB (353 KB); 3 are heavy enough
to load on demand - `Dicom` alone is 347,766 B, a third of the whole 37-format set, with
`MachO` 92,584 B and `Elf` 85,025 B behind it. The practical grouping is therefore: always-load
core (images, archives, containers), lazy-load binaries, and consider dropping DICOM unless a
medical use case is real.

Scaling: at the measured mean of 28,854 B, all 189 upstream specs would be
about 5.2 MB of unminified JavaScript - still not hundreds of wasm modules, and the heavy tail
above is what makes the number shrink once tiered.

### Bundle budget, measured with gzip

| tier | formats | raw JS | gzipped |
|---|---|---|---|
| light (<15 KB each) | 30 | 267,526 B | 66,543 B |
| medium (15-60 KB) | 17 | 440,107 B | 88,804 B |
| heavy (>=60 KB) | 3 | 525,375 B | 103,307 B |
| shared imports | 13 | 108,293 B | 31,102 B |
| **all 50 + shared** | **50** | **1,341,301 B** | **258,654 B** |

So the entire 37-format breadth is about 242 KiB gzipped, and the heavy three (Dicom, Elf, MachO)
are 42 % of that on their own: shipping the light and medium tiers plus lazy-loading binaries costs
~117 KiB gzipped. Scaling to all 189 upstream specs is arithmetic, not measurement - at the observed
mean it is ~5.2 MB raw, so the tiering decision matters more than the spec count.

## Coverage against a cited definition of "common"

"所有常见格式都能解析" needs someone else's enumeration, not ours. `tools/coverage.mjs` compares
what this repo can do against **google/magika `content_types_kb.min.json`** (Apache-2.0, 353 labels:
353 total, 219 binary, 134 text) and Kaitai's live spec tree, and writes
`catalog/coverage.json`. `.github/workflows/coverage.yml` rebuilds it on push and weekly, fails if
the committed matrix disagrees with upstream, and asserts the buckets add up.

| state | binary labels | share |
|---|---|---|
| own Rust reader, named header fields decoded | 54 | 24.7% |
| own Rust reader, container framing only | 29 | 13.2% |
| generated Kaitai reader, load-gated in CI | 41 | 18.7% |
| an upstream spec exists but the pinned compiler lacks it | 0 | 0.0% |
| **no parser at all - real gap** | **95** | 43.4% |
| **covered, any level** | **124** | 56.6% |

Top binary gap groups by count: unknown 50, archive 10, image 8, application 7, document 6,
code 5, executable 4, inode 3, text 1, undefined 1.
Named gaps that an end user would call common: `ppt` - the last compound-file Office type, and
re-probed here rather than repeated: LibreOffice accepts `ppt:impress8_export` for a PNG (opened as a
Draw document) and then refuses the store with `SfxBaseModel::impl_store ... 0x81a`, and nothing on
this host opens as an Impress document, so no ppt can be produced to read at all - an older note here
blamed a 640 KB padding size, which this round could not reproduce because nothing was written.
Then `chm`, `bzip3`, `arc`/`arj`,
`dmg`/`wim`/`vhd`/`squashfs`/`hfs`/`udf`, and the bare `ebml` label. `woff2`, `coff`, `crt`,
`sevenzip` and `otf` were on that list as the row before: the first for a reason that turned out to be
about the interpreter on PATH rather than
about the machine, the second because no Kaitai spec covers it, the third because the earlier sweep for
"cheap specs to generate" keyed on label names and so never matched `crt` to the `asn1_der` spec that
does exist upstream, and `sevenzip` because `py7zr` turned out to be installed as both a writer and a
reader for it here - see below. `otf` is the same story a fourth time: the blocker on record was "no CFF
charstring writer runs here", and the writer has been installed in this repo's own venv the whole time.

So the honest answer to the objective is **no, not yet**: 124 of 219 binary labels have a parser
that runs here (54 field-level and 29 container-level from our own Rust engine, 41 generated from
Kaitai specs and load-gated in CI), 95 have none. The buckets are deliberately separate from "identified" - the Tika
signature table covers 353 types for naming a file, which is not the same as parsing it.

## Analysis modules, fetched only when a visitor asks

The engine above is one small module that every visitor downloads: the structural readers share it,
and it costs about 200 KB. A binary *analyser* is a different weight class, and most visitors came to
unpack an APK - so the analysers are separate crates that build to separate `.wasm` files, listed on
the page behind a button, with nothing fetched, instantiated or held in memory until that button is
pressed. The row says so before the click and reports the byte count, export count and instantiation
time after it.

| module | built from | in the base download | what it answers |
|---|---|---|---|
| `apk-lens.wasm` | `engine/` | yes | container and header structure for 124 binary labels |
| `apk-lens-analysis.wasm` | `analysis/` | **no** | object-file layout: sections with their file offsets, both symbol tables, the machine, an address-to-name index over those tables, the byte-region map below, the printable strings that map loads, the CodeView type records a `.debug$T` section carries, and the export and import tables a PE image keeps |
| `apk-lens-disasm.wasm` | `disasm/shim.c` + Capstone 5.0.5 (BSD-3), via emscripten | **no** | instruction text, cross-references, basic blocks / function boundaries, the control-flow edges between blocks, and the names the symbol table gives each function entry, for x86-64, AArch64 and Thumb bytes |

**The region map** (`region_count` / `region_at`, painted by the page under the analyser's rows) answers a
different question from the section list: not *what is where* but *what names these bytes*. Every range
comes from a table the file itself points at - ELF's program-header and section-header tables, PE's
`SizeOfHeaders`, its section table and its certificate directory - and what falls between them is
classified as what it is: padding inside a segment the loader does map, or bytes no table and no segment
reaches at all. The colours say the difference, and the page says the limit out loud: green means nothing
in the file's own structure points there, which is not a promise that editing it is safe: a checksum, a
signature, or a program that reads its own file by offset are three things this map cannot see.

**The string list** (`string_count` / `string_at`) is the map's direct answer: a printable run counts only
when it lies inside a range the file's own load tables name - `data` or `rodata`, never `meta`, never a
`gap`. That is why it is not simply `strings -a`: the linker's `"Linker: LLD 22.1.8"` banner is the first
byte of `.comment`, `!This program cannot be run in DOS mode.` sits in the MS-DOS stub, both are printable,
binutils prints both, and no part of the running program ever reads them. Each row carries the address on
the same basis as the disassembly (`0x140002000`, image base included), the file offset, the run's exact
length and its section, so the page can say which strings an instruction actually points at and print that
as `引用` without guessing.

**The type list** (`type_count` / `type_at`) reads the CodeView records of a `.debug$T` section or of a
PDB's TPI stream - the same leaves either way, which is what IDA calls the type list: structures with
their field names, types and byte offsets, unions and enums, pointer, modifier, argument-list and
procedure types. A record's length counts its kind and its data but not the length field itself, so the
walk steps `length + 2`; in an object the stream opens with a four-byte header that is reported rather
than interpreted, and in a PDB the header size, the first index and the record bytes are read from the
TPI header, which is why the same reader answers both and the `header` column says which was skipped.
A member record inside a field list carries no length at all, so when the walk meets a member kind it
does not know - `LF_NESTTYPE`, which clang writes for the anonymous union inside `struct box` - the row
says where it stopped instead of guessing where the next name begins. Leaves the reader does not decode
are listed as `aux leaf 0x1605 not decoded`, so the count of what was skipped is on screen too. DWARF
is a different format and is not read; a file with no type stream gets no rows rather than names
invented from its section titles.

**The export list** (`export_count` / `export_at`) is IDA's Exports window: one row per slot of a PE's
export address table, in the table's own order, so an address that three names share appears three times
and the `hint` column says which entry of the name table reached it. The three kinds of slot are told
apart the way the format does it - a zero is an empty slot, an RVA inside the directory's own span is a
forwarder whose payload is another module's name in text, and anything else is the address of a body,
resolved through the section table into a file offset and named with the section that holds it. Two
readers had to be reconciled to write this: `llvm-readobj --coff-exports` lists the empty slot as ordinal
8 with no address, `objdump -x` leaves it out of its table altogether, and `lld-link` was made to produce
both by pinning two ordinals (`@7`, and `@9,noname` - a bare `,noname` is rejected, the ordinal has to
come first). `scripts/make-export-fixtures.py` walks the bytes a third time and refuses to write its
probe unless all three agree, so the eight rows the tests assert are the linkers' and the readers', and
never a transcription of this one's. An ELF, a Mach-O or a COFF object answers with no rows: their names
are already in the symbol list, and inventing an export directory for them is not this reader's job.

**The import list** (`import_count` / `import_at`) is the other half of that window, and it needed a
different producer: `lld-link` cannot write an import table on this host at all, because there is no
Windows import library, no mingw sysroot and no SDK anywhere on it, so a call into `kernel32` has nothing
to resolve against. `csc.exe` does write one - a .NET assembly always imports its runtime host - which
also handed the reader a PE32 to go with the export fixture's PE32+, so the two directory bases
(`opt+96` and `opt+112`) and the two thunk widths are both covered by committed files. Two shapes a
compiler would not produce were made by changing one `u32` each and asking both readers what they now
said: setting the high bit of a lookup-table entry (the low sixteen bits are the ordinal, and there is no
name to read at all - `12` is this patch's number, not a real `mscoree` ordinal), and zeroing a
descriptor's lookup-table pointer, which leaves the address table as the only copy of the names and is
what the `names	iat` column reports. Both readers agreed with the walk on all three files before the
probe was written. What the rows do not do: no name is resolved, no bound-import table is read (entry 11
is empty in every file here), and delay-loaded imports - a different directory, a different structure -
are not looked at, so a file whose only imports are delay imports reads as importing nothing.

`scripts/make-image-fixtures.py` links the two fixtures with `clang` driving `ld.lld`
(`-nostdlib -ffreestanding`, one for `x86_64-unknown-linux-gnu`, one for `x86_64-w64-windows-gnu`), which
is also the answer to "no ELF or PE image can be produced on this host": 1 152 bytes of ELF64 and 3 072 of
PE32+, each with alignment gaps the map has to find. The script refuses to write its probe unless its own
reading of the headers agrees with `readelf -h -l -S` and `objdump -h` field for field, which is how two
wrong offsets in the first draft - ELF64's `e_phentsize`, and the COFF `TimeDateStamp` sitting before the
symbol pointer - died before the Rust port did. The same gate runs over the strings: every row the scan
predicts has to be one `strings -t x -a -n 4` prints at that offset with that length, which is the check
that pins `.buildid` down to `RSDS,` and `ovsLLD PDB.` - the two runs binutils finds there, cut apart by
the CodeView GUID's non-printable bytes, rather than one word guessed at.

The third module is the reason the second one reports a `machine` and a section's file offset at all:
the page hands the analyser's answer - which instruction set, and where the code lies in the file -
to the disassembler, the same way `objdump -d` gets both from the binary. It is 1.86 MB, 601 KB
gzipped, which is exactly why it is not in the module every visitor loads.
One file does not need to wait for the middle step, and the reason is worth stating exactly because an
earlier draft of this paragraph had it wrong: a `clang -c` object **is** something the analyser reads -
`object`'s `read` feature includes COFF, and its file-kind dispatch keys on the machine field at byte
zero, so a relocatable object comes back with `kind relocatable` and section-relative symbol addresses.
The base module simply carries the same two facts in its COFF rows already, so for `.o` the page takes
them from there and an object disassembles after one fetch instead of two. An i386 object says so
rather than being decoded as something else, because the module carries x86-64, AArch64 and Thumb only.

The disassembler's C can be checked on any host that has a C compiler, without emsdk and without
linking anything: `git clone --filter=blob:none --no-checkout --depth 1 --branch 5.0.5` the Capstone
tree, `git sparse-checkout set include/capstone`, then
`clang -fsyntax-only -Wall -Wextra -I <that include dir> disasm/shim.c`. That is how a wrong operand
spelling - Capstone's types are `cs_x86_op`, `cs_arm64_op`, `cs_arm_op`, not the shorter names one
expects - is caught in a second instead of a CI cycle.

The analysis module rides on [`object`](https://crates.io/crates/object) (Apache-2.0 or MIT, pinned to
`=0.32.2` because the row text is that crate's own naming), with `default-features = false` and only
`read` + `std` so `flate2`/`ruzstd` stay out of a file the browser downloads on request. It reads two
symbol tables rather than one, which the CI runner taught the hard way: `/bin/ls` there is stripped,
so `.symtab` is empty and every import lives in `.dynsym` - a reader that looked only at the first
would call a real program symbol-less. `test/module.test.mjs` asserts the other half of the deal too:
the base module must **not** export `analyse_run`, `analyse_count`, `analyse_at` or `self_test`.

**What this lane can and cannot grow into, measured by `.github/workflows/toolchain.yml` rather than
assumed:** the runner has rustc 1.98 and clang 18.1.3 (plus 16 and 17), and a minimal wasm crate
builds in ~8 s; it has **no `emcc` and no emsdk**, though `apt` offers `emscripten 3.1.6` - so a C
engine such as Capstone is reachable behind an install step, at the cost of pinning an old toolchain.
Two things named in the requirement are not viable and are not going to be quietly swapped for
something smaller: **BinCAT** needs Z3, Boost and a host C++ build, and has no wasm port; and
**LLVM itself** (the `cling` line of the user's own `clings`/`cling`/`cling-win` repos) is a
multi-hour build whose useful subset still runs to tens of megabytes - an order of magnitude beyond a
200 KB demo. Instruction decoding, by contrast, turned out to be reachable the same day the question
was measured, so it ships: what is left on this lane is the rest of the pipeline those tools are known
for - types over the blocks, edges and names that now exist - one
opt-in module at a time. A decompiler is not on the list: the well-known one is proprietary, and
"we ported it" would not be true.

The cross-reference pass is `disasm_xrefs`, and it is deliberately narrower than the window in IDA it
is modelled on. An edge exists when a decoded instruction is a call or a jump and carries an immediate
target (Capstone resolves the PC-relative offset for both), or when an x86-64 instruction reaches
memory through `rip` - which is how the same code names a global it reads. An immediate in
`sub eax, 0x10` is a constant and stays out of the list, because a reference graph full of constants
hides the edges that matter. Every edge carries a `where`, saying whether the target falls inside the
window that was disassembled or outside it, which is the difference between a call into the same
section and a pointer into something the loader has not shown you; and the summary row gives the counts
against the number of instructions scanned. `self_test` exercises this second path too, on a five-byte
`call rel32 + 10`, so a build that decodes text but not edges returns a negative number and the page
says so. What it does **not** claim: that an address it prints is a function entry, which is what the
third and fourth passes are for.

The third pass is `disasm_funcs`, and it is the reason the edges above are kept rather than thrown
away: a **block** ends at a call, a jump or a return, or just before any address one of this window's
transfers points at, and a **function** starts at the entry address plus every address a *call* in the
window points at, running to the next such start. The rows state both rules instead of leaving a graph
the caller cannot see - `func` carries its extent, instruction count, block count and how many of each
terminator kind it holds, and `block` carries its own extent, its function and its terminator, which is
`none` when a leader, not a terminator, ended it. Only Capstone's groups decide this, so `call`, `jump`
and `ret` mean the same thing for all three instruction sets, and `self_test` refuses a build whose
six-byte `call` + `ret` does not come back as one function and two blocks.

The fourth pass is `disasm_cfg`, and it turns the blocks into a graph by naming their successors. An
edge is drawn per way out of a block: `taken` for a branch whose target is inside the window, `fall` for
the block that begins at the byte after the terminator, and `call` for a call whose target is inside the
window - labelled separately, because a call leaves the function and drawing it as flow inside one would
be wrong even though the bytes really do name a target. A conditional branch therefore has two successors
and an unconditional jump or a `ret` has one or none, which is the difference between a list of blocks
and a graph: `self_test` checks exactly that on four bytes (`jne +2`, a `nop`, a `ret`), where the taken
edge and the fallthrough leave the same block and no linear walk can produce both. Two derived facts ride
on top of the edges, because they are what people look a graph for: `back yes` marks an edge whose
destination sits at or below its source - the loop - and a block with no predecessor that is not the
entry is counted `unreached`, which in compiler output is alignment padding and in a truncated window is
a block whose other half the caller did not hand over.

The fixture for the graph is `scripts/make-cfg-fixture.py`: `clang -c` writes a function with a guard, a
loop and a three-way branch, and `objdump -d` reads it back, so every address and every branch target in
the expected rows is another program's answer. The block boundaries themselves are this lab's rule applied
to objdump's listing - objdump has no notion of a basic block - so what the test proves is that the module
computes the graph the listing implies, not that two implementations agree on a graph. The rows say which
facts they rest on: the guard's block has two successors, fifteen edges come back over eleven blocks, and
the `nopl` padding at `0x3d` is the one block nothing reaches.

Two limits are stated rather than smoothed over. The split is a linear scan, not reachability: a
function is an address range, so bytes the control flow never touches still fall inside one - the graph
rows now say which blocks nothing reaches, but they do not remove them. And a call's target is what the raw bytes say, which for a `clang -c`
object - where the linker has not filled the displacement in yet - means the instruction *after* the
call; `objdump -d` splits those same bytes at its symbol table instead, which a window of instructions
does not have. The page therefore says how many functions it found, and shows the rows.

Names are the fourth thing an analyser does, and they are what closes that last gap: the symbol table a
window of instructions does not carry is exactly what the analysis module reads, so a name is looked up
in the file rather than guessed from the bytes. It lives there rather than in the disassembler because
a name is a fact about the file and not about an instruction. `name_at(address)` answers out of an index
built while the symbol tables were being listed - every symbol the file says lives in a section, minus
the two kinds that do not own an address: a **section** symbol names a range (and an object file has one
per section, all of them at offset zero), and a **file** symbol names a compilation unit.
`test/fixtures/answer.obj` is the witness, and it is a strict one: eleven symbols are listed, four of
them report address 0 - `.text`, `@feat.00`, the file record and `answer` itself - and only `answer` is
allowed to win that address, so the lookup says `answer` at 0, `answer+0x5` five bytes in, `helper` at
0x10 and `helper+0x9` at `0x19`. objdump writes that call as `call 19 <helper+0x9>`, and since its
addresses are hex, reading the `19` as decimal is the one way to get the witness wrong - it cost a CI
cycle to learn it, so both the Rust test and the JS one assert `helper+0x3` at `0x13` beside
`helper+0x9` at `0x19`. The
offset form is objdump's hex spelling rather than IDA's decimal one so the row can be diffed against the
listing it was checked against. What the lookup does *not* do is bound a name to its size: a COFF symbol
carries no size unless the compiler wrote an aux record, so the nearest name below an address wins
however far below it is - which is objdump's rule too, and is why the page prints how many addresses are
named rather than implying every byte of a section belongs to something. For a function entry the file
does not name, the page synthesises IDA's `sub_<hex>` label and marks it `合成` in its own column: an
invented name and one read out of the file must never look alike.
The listing cap and the index are deliberately different sizes, and the CI runner showed why: every one
of the 64 dynamic-symbol rows it prints for `/bin/ls` is an undefined import, because the linker puts
those first, so a check written against the printed rows can see nothing while the index - built over
all 128 - still holds `_init`, `data_start` and the rest.

## Reproduce

```bash
node scripts/fetch-sources.mjs   # pulls Tika, libarchive, LIEF, Apktool, v86
node scripts/build-catalog.mjs   # writes catalog/formats.json and the counts above
node tools/coverage.mjs          # writes catalog/coverage.json, the 219-label matrix
node scripts/make-fixture.mjs    # rewrites test/fixtures/lab-fixture.apk
bash scripts/make-media-fixtures.sh    # ffmpeg/Pillow media, tiny.pcx, tiny.pdf
bash scripts/make-pdf-fixtures.sh      # Pillow + headless Chromium PDFs and their probes
python scripts/make-icon-fixtures.py   # Pillow writes tiny.icns, then decodes it back for the probe
python scripts/make-plist-fixtures.py  # plistlib writes the binary plists; tools/plist-sim.py decodes them back
python scripts/make-qoi-fixtures.py    # Pillow encodes the QOI fixtures and decodes them back
python scripts/make-jp2-fixtures.py    # Pillow/openjpeg writes the JP2 boxes; the probe walks them back
temp/venv/Scripts/python.exe scripts/make-woff2-fixture.py   # fontTools + brotli write tiny.woff2
temp/venv/Scripts/python.exe scripts/make-npy-fixtures.py      # numpy writes the .npy files and supplies the sizes
temp/venv/Scripts/python.exe scripts/make-h5-fixtures.py         # h5py writes HDF5 twice, old and new superblock
temp/venv/Scripts/python.exe scripts/make-avro-fixtures.py        # fastavro writes the containers and counts the records back
temp/venv/Scripts/python.exe scripts/make-arrow-fixtures.py      # pyarrow writes both IPC framings and reads every field back
temp/venv/Scripts/python.exe scripts/make-parquet-fixtures.py  # pyarrow writes parquet and answers every footer field back
temp/venv/Scripts/python.exe scripts/make-onnx-fixtures.py      # onnx writes the models and re-reads every field back
temp/venv/Scripts/python.exe scripts/make-heif-fixtures.py        # pillow-heif (libheif) writes HEIF and reports its own size and colour
temp/venv/Scripts/python.exe scripts/make-cfb-fixtures.py         # LibreOffice + xlwt write compound files that olefile then re-reads
temp/venv/Scripts/python.exe scripts/make-stl-fixtures.py       # meshio writes the meshes and counts the triangles back
temp/venv/Scripts/python.exe scripts/make-icc-fixtures.py     # littleCMS (via Pillow) writes the profiles and reads them back
temp/venv/Scripts/python.exe scripts/make-bmff-wide-fixture.py  # hand-built 64-bit box; mutagen and ffprobe read it back
temp/venv/Scripts/python.exe scripts/make-emf-fixtures.py       # LibreOffice and Windows GDI each write a metafile
temp/venv/Scripts/python.exe scripts/make-ps-fixtures.py         # LibreOffice and ImageMagick each write PostScript
temp/venv/Scripts/python.exe scripts/make-coff-fixtures.py        # clang -c writes the objects, objdump reads them back
temp/venv/Scripts/python.exe scripts/make-der-fixtures.py         # openssl signs the certificates and lists every object in them
temp/venv/Scripts/python.exe scripts/make-7z-fixtures.py          # py7zr writes both header shapes and checks the archive's two CRCs
temp/venv/Scripts/python.exe scripts/make-psd-fixtures.py           # psd-tools writes the documents, Pillow reads every one back
temp/venv/Scripts/python.exe scripts/make-cfg-fixture.py            # clang -c writes the branchy object, objdump lists it back
temp/venv/Scripts/python.exe scripts/make-dotx-fixture.py           # LibreOffice converts a real docx, both manifests are re-read
temp/venv/Scripts/python.exe scripts/make-otf-fixtures.py           # fontTools writes the CFF font, FreeType reads its numbers back
temp/venv/Scripts/python.exe scripts/make-vcard-fixtures.py         # vobject writes the cards and counts their properties back
temp/venv/Scripts/python.exe scripts/make-torrent-fixtures.py       # bencode.py writes the .torrent files and re-encodes them to themselves
temp/venv/Scripts/python.exe scripts/make-image-fixtures.py          # clang + lld link a real ELF64 and PE32+; readelf and objdump check every offset the map uses
temp/venv/Scripts/python.exe scripts/make-codeview-fixtures.py       # clang -gcodeview writes test/fixtures/cv.obj; the type-stream walk is checked both ways against llvm-pdbutil on the PDB lld links from it
temp/venv/Scripts/python.exe scripts/make-pdb-fixtures.py          # lld-link writes test/fixtures/lab.pdb; the MSF superblock, stream table, TPI header and its records are checked against llvm-pdbutil --summary --streams --type-stats --types
temp/venv/Scripts/python.exe scripts/make-export-fixtures.py     # lld-link writes test/fixtures/exp.dll with an aliased, a nameless, an empty and a forwarded export; llvm-readobj --coff-exports and objdump -x must both agree with the byte walk before the probe is written
temp/venv/Scripts/python.exe scripts/make-import-fixtures.py     # csc.exe writes test/fixtures/lab.dll (the only PE this host can make with a real import table); ordinal.dll and noilt.dll are its bytes with one u32 changed, and both readers have to read the patched shape the same way
temp/venv/Scripts/python.exe scripts/make-pgp-fixtures.py           # gpg writes six OpenPGP files and --list-packets reads every packet back
npm install jsonc-parser && temp/venv/Scripts/python.exe scripts/make-jsonc-fixtures.py   # jsonc-parser (MIT) supplies the tree, json.loads the refusal; both are needed for one probe
python tools/vcard-sim.py                          # a second reading of the fold rules, diffed against the rows
python tools/torrent-sim.py                        # the same walk in Python, for the bencode rows
python scripts/make-font-fixtures.py   # fontTools compiles tiny.ttf / tiny.woff from nothing
node --test test/wasm.test.mjs engine/target/wasm32-unknown-unknown/release/apk_lens.wasm
cargo test --manifest-path analysis/Cargo.toml   # host tests for the on-demand analysis module
node test/module.test.mjs analysis/target/wasm32-unknown-unknown/release/apk_lens_analysis.wasm engine/target/wasm32-unknown-unknown/release/apk_lens.wasm
cargo test --manifest-path engine/Cargo.toml   # host tests for zip and PE
```

Nothing here compiles on a phone or a weak laptop by necessity: `.github/workflows/engine.yml`
builds the wasm target and runs both test layers on CI.

### Corrections worth keeping in the record

* An early research pass claimed v86 has no JIT, citing [issue #547](https://github.com/copy/v86/issues/547).
  A second pass contradicted it. Checking the shipped artifact settles it: `disable_jit` is a real
  option in `https://copy.sh/v86/build/libv86.js`. The "no JIT" claim is dropped; the licence and
  payload findings stand independently of it.
* A version of this README asserted that `ScriptRunner.exe` declares `SizeOfOptionalHeader = 0`.
  It does not: the first implementation read that field and `Characteristics` one slot early (at
  `NumberOfSymbols`, per a mis-counted `IMAGE_FILE_HEADER`), and a real system binary was parsed
  into a shape that looked like a wild defect. The file actually declares 224 and `0x0022`, and
  the accidental canonical fallback was masking the off-by-one-field, which is also why the
  synthetic tests stayed green — they were built with the same wrong layout. Ground truth came
  from `struct.unpack_from('<HHIIIHH', …)` over the same bytes. Offsets fixed, validation added,
  and a legal 216-byte header is now a test case so the fallback cannot silently become the rule.
* The demo shipped rewriting the APK's relative references to `blob:` URLs, which reads as correct
  and does nothing: the frames are isolated, so Chromium refuses the host's blobs and the guest
  page rendered without its scripts or styles. The unit tests stayed green because they only check
  the bytes coming out of wasm, not what the browser does with them. Rewriting to `data:` URLs is
  what actually runs, and `test/fixtures/lab-fixture.apk` now carries a guest script that answers
  with a `postMessage`, so "it ran, and it ran as `origin: null`" is checkable from the host.
* Writing the media readers against ffmpeg's own output corrected two more recollections. An EBML
  size whose leading byte is all ones is the *unknown length* marker, and the value mask has to come
  from that byte's own width: `0xff >> len` shifts a `u8` by 8 and panics on exactly the encoding a
  streamed file uses, which is now a test rather than a crash. And FLAC's metadata blocks do not
  tile the file - the frame area follows the last block - so a reader that expected EOF after them
  was wrong about the format, not about the fixture: it reports where frames begin and the test
  checks the sync code sitting there.
* `ffprobe`'s `bit_rate` for an MP3 is the encoder's nominal average, and the first frame header of
  a LAME file advertises a bitrate index that no later frame uses. Both are reasons the reader
  reports the frame chain it walked, and the test asserts the *majority* index against the probe
  instead of trusting frame zero.
* A generated reader is not automatically better than a handwritten one: `media/avi.ksy` (CC0, in the
  pinned 0.11 bundle) steps from one RIFF block to the next by the declared size alone and never
  skips the padding byte that follows an odd-sized chunk. ffmpeg's AVI has five such chunks - the
  `ISFT` tag is 13 bytes, the `00dc` video frames 41, 23, 21 and 33 - so the generated reader
  desyncs inside the nested `LIST`s and throws at end of data, while this repo's own walk, which
  adds `size & 1`, tiles the file exactly. AVI is therefore credited to the Rust reader only, and
  the test asserts the generated one still fails so the gap is visible if upstream fixes it.
* A failing assertion on a *parsed reader object* is its own hazard: Node builds the failure diff by
  inspecting both operands without a depth limit, and a generated object hangs off `_parent`, `_root`
  and the stream. One `assert.equal(pcx.palette256, undefined)` cost 37 s to fail - long enough to
  stall the CI step and look like a hang. The whole media file now runs in 18 ms, because the
  assertions compare scalars and lengths instead of handing objects to the comparator.
* A remembered table is the thing this repo keeps getting caught by. Apple's icon types are usually
  described by a tag-to-size table, but Pillow writes `ic13` and `ic14` at 256 and 512 *image* pixels,
  not at the point sizes the names imply - so the ICNS reader takes its dimensions from each embedded
  PNG's own header, and `scripts/make-icon-fixtures.py` writes a probe that decodes the payload again
  with Pillow, which is what says the two agree. Same class as the section ids for WebAssembly (10 is
  `code`, not `data count`), which a first simulation got wrong before the real module corrected it.
* Blocked on privileges rather than tools: `wim`. `dism.exe` is on PATH and would be a genuine
  producer, but `/Capture-Image` refuses without elevation (error 740), and elevating is not
  something to do from a script.
* A generator that quietly writes the wrong document reads as a reader bug. The two-page A4 sample
  came out as one Letter page because `printf 'a' 'b' 'c'` treats everything after the first argument
  as a substitution rather than as more text, so the continued string that carried the `@page` rule
  and the `<body>` was dropped on the floor. The test for it would have failed against a correct
  reader. `scripts/make-pdf-fixtures.sh` now counts the page boxes in the file it wrote and exits non-zero
  when they disagree with what the tests assert. The same run also showed why a Windows GUI binary is
  a poor place to read provenance from: `chrome.exe --version` prints in the console codepage, and the
  mojibake landed in the probe JSON, so the recorded producer comes from the PDF's own `/Producer`
  string (`Skia/PDF m153`) instead.
* Opening the deployed page in a browser found two things no test could. The panel had taken its
  format name from the reader's first row, which for a tar is a *member* name, so it printed
  `tiny.tif` for `gnu.tar` — a wrong answer, delivered confidently; the name now comes from the
  reader that accepted the bytes, through `container_name` / `audio_name` / `stream_name` /
  `document_name`, with the tables kept beside the format constants. And the page had cached the
  previous build's `apk-lens.wasm` while serving fresh HTML over it, so a call into an export the old
  module does not have threw inside an async handler and left the status line stuck on "读取中…" with
  nothing in the console. The wasm is fetched with `no-cache`, the new calls are feature-detected, and
  the handler reports what it threw instead of going quiet.
* CAB was attempted and **partly** implemented, on purpose. `makecab.exe` here produces a cabinet whose
  file table decodes exactly as documented - 16-byte `CFFILE` records at `coffFiles`, names
  `payload.txt` and `second.txt`, sizes 50 and 50, matching `expand -D` - but its folder area is
  `coffFiles - 36 = 8` bytes for `cFolders = 1`, where `CFFOLDER` is specified as 16, and the two
  u16s in those 8 bytes read 1 and 1 rather than the 59 compressed / 100 uncompressed bytes the
  folder actually holds. The reader walks the file table and stops there; the folder area stays
  unwritten rather than guessed from one sample, so `cab` is a container-level credit. Revisit with a
  second cabinet (a larger one, and one from another writer) before coding against either
  interpretation.
* Two little-endian reads sat inside a big-endian format, and no file in the tree could say so.
  `box_extent` took the 64-bit length of a size-1 box from `Le`, and so did the version-1 `mvhd`
  duration - both wrong, since 14496-12 lays every integer in this family out big-endian. Nothing
  looked broken, because a 64-bit box means a file over 4 GB and a version-1 `mvhd` means a muxer that
  bothered to widen its timestamps, and the ffmpeg output that is our fixture has neither: the arms
  that handle them were written and never executed. `test/fixtures/wide.mov` carries both and is
  labelled as hand-built, because this lab cannot produce either form. Two other implementations are
  asked the same question about the same bytes before the fixture is committed, so it is not a
  self-assertion: `mutagen` - installed, with its own `struct.unpack(">Q", ...)` at box + 8 - reports
  the box as 48 bytes at 148, and byte-swapping those eight bytes makes it report
  3,458,764,513,820,540,928, which is the number this reader used to print; `ffprobe` reads the
  version-1 64-bit creation stamp back as the date written into it. The row now says which form it read
  (`box  mdat  48  148  wide`), because a bare number cannot tell a 64-bit length from a 32-bit one.
  Lesson, and it is the same one as every other untested arm: a format being *covered* is not the same
  as its branches being run - the way to find these is to ask which fields a real writer would rarely
  emit, then hand-build exactly those and get a third program to read them back.

### Where the breadth work stands, and what is deliberately not attempted

Coverage is scored against magika's 219 binary labels: **124 covered** (54 field-level and 29
container-level from this repo's own readers, 41 generated and mostly load-gated), **95 with no
parser**. Four things follow from measuring rather than assuming, and are recorded so the next pass
does not re-derive them:

* Labels that share framing are where the cheap breadth is, and the count moves only when a fixture
  proves it: `.wma` and `.wmv` are ASF files with different codec objects, so the walk that was written
  for `media.asf` covered both once ffmpeg produced one of each and `engine/tests/asf.rs` checked that
  the header object's five children end where its own declared length says and that the top-level
  objects tile the file. **88 → 90 covered, 131 → 129 gaps**, at container level, with no new reader
  code - which is exactly why the tier is not called "fields". The same economy carried `.mp2`: Layer
  II and Layer III share the `144 * bitrate / rate + padding` stride and the 1152 samples per frame,
  so the existing MPEG walk needed only its bitrate table and a layer test to gain a **field-level**
  label (91 covered, 128 gaps). Two encodings, 128k and 192k, because one file cannot tell a table it
  looked up from a stride it hardcoded - and a Layer III file walked with the Layer II table finds no
  frame at all, which is the assertion that says the two are really separated. `.ts` needed a reader of
  its own (a 188-byte grid, then PAT to PMT to elementary stream), and earns **field** level because
  the streams come out of those tables: one program, its PMT on PID 4096, PCR and the only video
  stream both PID 256 under stream type 0x02 - which is what ffprobe reads from the same file.
  `wasm` had stood as "no producer on this machine" for rounds; the producer was the CI build all
  along - `engine.yml` now compiles the wasm target before `cargo test`, and the section walk runs
  over that module (`code_matches_functions`, one code body per declared function, is the check that
  the boundaries are real; the JS test compares the export count with what the host engine reports for
  the same bytes). Same lesson as the PDF writer: look at what already exists before recording a
  format as unproducible. Fonts went the same way - `fontTools` is installed and MIT-licensed, and it
  compiles a two-glyph font out of nothing, so `tiny.ttf`/`tiny.woff` are an independent writer's
  bytes with no third-party outline to licence (+2 labels; `woff2` looked blocked because the one
  dependency it needs, `brotli`, would not install into the interpreter on PATH - which the next
  paragraph shows was a mistake of attribution).
  `applebplist` looked for its producer in the wrong place too: CPython's `plistlib` writes the binary
  format, so `scripts/make-plist-fixtures.py` dumps three files - a dictionary holding one value of
  every scalar type, a KeyedArchiver graph whose `$top` reaches its objects only through UIDs, and an
  empty dictionary - and `tools/plist-sim.py` decodes them with `struct` and compares that walk against
  `plistlib.loads` of the identical bytes before a single row is asserted (+1 label, at field level:
  97 covered, 122 gaps). The read is of the object *graph*, which is what earns the `edges`/`reach`
  rows rather than a listing of markers, and the trap is the two widths the trailer carries: byte 6 is
  the offset table's entry width, byte 7 the width of references *inside* an object, and `tiny.bplist`
  uses 2 and 1 - a reader that reuses one number for both walks off the end of every table. Sets and
  ordered sets stay unnamed: `plistlib` refuses a Python `set`, so markers 0xB and 0xC get a row quoting
  their byte and nothing else.
  The same hunt turned up two more writers in Pillow 12.3, and one near-miss worth recording. It
  *encodes* QOI (`scripts/make-qoi-fixtures.py`), so `tiny.qoi`/`srgb.qoi`/`all6.qoi` are an
  independent encoder's bytes, re-decoded by Pillow's own reader in the generator before the fixture
  was committed; and because the writer only emits colourspace 0 when the caller asks for sRGB, the
  two single-byte header fields are both covered by real files instead of by a remembered layout -
  which is the trap this one sprang first, since width and height are u32 and channels and colourspace
  are u8, and reading them as four u32s prints 67239434 where the file says 4 (+1 field-level label,
  98 covered, 121 gaps). QOI has no unknown tags - the six ranges cover every byte value - so the read
  is an accounting of pixels walked against `width * height`, and the hostile cases are the three ways
  a length can be wrong: an overrun, a chunk that would reach into the terminator, a terminator that is
  not there. `all6.qoi` exists because a flat image only exercises two of the six classes. The
  near-miss: Pillow also *writes* SGI (`\x01\xda`) and JPEG 2000 (`jP  ` boxes), and magika has no
  `sgi` label but does have `jp2` - so SGI earns nothing here while JP2 is now reachable, and `psd`,
  which Pillow reads but cannot write, stayed a gap named rather than quietly dropped - until a wheel for
  `psd-tools` turned out to install here, which made Pillow the second reader instead of the missing writer.
  JP2 took the reachable branch (+1 field-level label, 99 covered, 120 gaps) and caught two more
  remembered-table traps on the way: the `ihdr` box lists **height before width**, the opposite of the
  `Xsiz`/`Ysiz` order in the codestream beside it, and it stores sample depth minus one, so the byte
  reads 7 for the 8-bit images Pillow confirms by decoding them back. The third box, `colr`, is printed
  as its raw enumerated-colourspace number (16 and 17 across the three fixtures) because the code list
  beyond those two values is exactly the kind of table this repo has been wrong about before - and the
  `SIZ` segment's own geometry was dropped from the probe for the same reason: laid out from memory it
  did not add up to its declared length, so the reader keeps to the boxes and leaves the codestream at
  its SOC marker.
  **A recorded blocker is worth re-testing before it is repeated.** `woff2` had been listed as a gap
  "because writing it needs `brotli` and this Python refuses to install into its own environment" -
  true of the interpreter on PATH, irrelevant to the machine: `python -m venv --system-site-packages
  temp/venv` plus one `pip install fonttools brotli` worked immediately, and network access turned out
  to be available. That produced `tiny.woff2` (+1 field-level label, 100 covered, 119 gaps) and put
  `npy`/`h5`/`parquet` in reach too. The read itself is the table directory over one brotli block -
  decompression is *not* attempted, because a dependency-free wasm crate cannot do it, which is why the
  credit is header-and-directory fields and not a rendered glyph. Two witnesses keep the directory honest:
  every untransformed `origLength` equals the length that table has in `tiny.ttf`, the font the file was
  made from (the test reads both), and the 63-entry known-tag list is compared in order against
  fontTools' own copy inside `woff2.probe.json` rather than against a recollection - the failure mode
  this repo has hit in three formats now. `glyf` and `loca` at version 0 carry a second, transformed
  length; `DSIG`-style arbitrary tags name themselves in the entry.
  The same venv then produced nine `.npy` fixtures from numpy itself (+1 field-level label, 101
  covered, 118 gaps), which is also the reason the reader's arithmetic is trustworthy: a NumPy header
  spells a *type* (`'<f8'`, `'|S4'`, `'<U4'`, or a nested field list) and a shape, and the item size
  has to be derived from that spelling before `size × product(shape)` can be compared with the bytes
  after the header - so `make-npy-fixtures.py` records `dtype.itemsize` and `nbytes` from numpy and
  refuses any file where they disagree with the file's own length. `'<U4'` therefore reads as sixteen
  bytes because numpy says sixteen, not because four looked like a character width; a field list is
  left explicitly `unknown` (the v2 fixture's real item size is 13, which only alignment rules give)
  and earns no `walked end`. Version 1 stores the header length as a little-endian u16 and versions
  2 and 3 as a u32, and both forms are real files rather than hand-built ones.
  HDF5 (+1 **container**-level label, 102 covered, 117 gaps) is where the remembered-table trap was
  refused outright rather than worked around. h5py will write it twice over - `libver="earliest"` gives
  the old v0 superblock with its B-tree and local heap, `libver="latest"` gives v3 with an `OHDR`
  object header - so both generations are the same library's output and h5py reopens each one before
  it is committed. What the reader then does is *not* walk a field table: it reads the version byte and
  the two width bytes (v0 keeps them at 13/14, v2/v3 at 9/10, and since both files say 8/8 the only
  proof the positions differ is that reading them swapped yields 0, which no longer parses - pinned by
  a test that zeroes each pair in turn), then scans the superblock's 64-bit slots and reports each one
  only for what the bytes demonstrate: that it equals the file's own length, or that the address it
  holds points at four ASCII letters, which is how HDF5 signs every structure (`TREE` and `HEAP` at
  136 and 680 in the old file, `OHDR` at 48 in the new). No message-kind table and no traversal below
  the root group is claimed, because these two files cannot verify either; `h5` is therefore
  container-level, and the deeper read is queued behind `parquet`/`onnx` rather than faked.
  Avro (+1 field-level label, 103 covered, 116 gaps) is the same discipline applied to a container of
  variable-length integers: fastavro writes `rows.avro`/`deflate.avro`/`many.avro`, reads each one
  back, and the generator refuses to commit a file whose block counts do not sum to the record count
  the library returns - so the arithmetic the Rust reader repeats has already been checked against a
  second implementation. `many.avro` is deliberately written with `sync_interval=1000` to be five
  blocks, because with one block a loop and a block that merely ends where the file does are the same
  observable thing. Payload bytes are counted, never deserialised, and a deflate-coded block is
  reported by name rather than inflated. Writing the mirror first caught two arithmetic slips in the
  hand-built tests (a varint `0x14` for an 11-byte key, and a patched byte that was not the block's
  size field), which is the point of the mirror: after the npy port silently dropped a trim step the
  mirror had, the Rust and the python are now compared line by line as well as row by row.
  Arrow IPC (+1 field-level label, 104 covered, 115 gaps) is where that discipline paid for itself
  twice in one file. `scripts/make-arrow-fixtures.py` writes seven fixtures with pyarrow, walks each
  one with its own flatbuffer reader, reads it back through `pyarrow.ipc.read_message`, and refuses
  to write `arrow.probe.json` unless the two agree on every metadata length, body length, version,
  header kind, row count, column name and block offset. Two traps fell out of that comparison and
  neither is visible in a spec summary: a message's body length lives *inside* its metadata
  flatbuffer, so a walk that skips only the metadata desynchronises at the first record batch
  (`batches.arrow`, three batches, cannot be walked that way); and a file's footer `Block` gives the
  envelope position plus a `metaDataLength` that already includes the 8-byte encapsulation prefix, so
  the naive `offset + meta` reading of "both are metadata sizes" lands eight bytes into every body.
  The codec ordinal is a third, quieter case - `lz4_frame` is the enum's zero, so pyarrow omits the
  field entirely and only `zstd` has to appear: two files written with two option strings are what
  order those two values, which is why the reader names nothing it has not seen and reports column
  type discriminators as numbers.
  Parquet (+1 field-level label, 105 covered, 114 gaps) is the same file family read a second way: the
  interesting half of a .parquet is at the *end*, and it is Thrift compact protocol rather than a
  bespoke layout, so field ids exist only as deltas and a field that equals its default is simply
  absent - which is why unknown fields must be skipped by type, the behaviour a hand-written test
  exercises by appending a field the reader has never seen and asserting the report does not move. The
  generator names nothing from memory either: it collects codec and physical-type ordinals from files
  pyarrow was told to write with those options, and refuses a value that maps to two names. That check
  caught a recalled table being wrong before it reached the reader - `ZSTD` is ordinal 6, not 5 - and it
  is also why encoding ordinals stay unnamed: the only thing two fixtures that differ in exactly the
  `use_dictionary` option prove is *which* ordinal belongs to a dictionary page.
  ONNX (+1 field-level label, 106 covered, 113 gaps) is a third encoding class again: the whole file is
  one protobuf message with no magic, and a length-delimited region is a string or a sub-message only
  because the schema says so - so no generic walker is available and the reader descends one named
  level at a time. The generator justifies every field number twice: against the descriptor `onnx`
  ships, and by byte-for-byte equality between each region and what `onnx` serializes for that node,
  tensor, input or output. Both were needed, because several numbers a recollection supplies are wrong
  - `producer_name` is 2 not 3 and `graph` is 7 not 8, and inside a tensor `float_data` is 4,
  `int32_data` 5 and `string_data` 6, so the remembered 5/6/12 would have called an int32 tensor a
  float one and a doc string a payload. `ModelProto.ByteSize()` equals the file length, which is what
  lets the reader require that its walk account for every byte and refuse a truncated model.
  HEIF (+1 field-level label, 107 covered, 112 gaps) is the same ISO base-media container MP4 uses, and
  the reason it needed its own reader is a size that is not the picture: libheif codes in whole blocks,
  so a 23x17 image declares `ispe` 64x64 and carries the real 23x17 in `clap`, as signed numerators over
  unsigned denominators. `scripts/make-heif-fixtures.py` writes it with pillow-heif (which bundles
  libheif) and asserts the crop's numerators equal the size pillow-heif reports when it reads the file
  back, the `pixi` depths' maximum equal its bit depth, and the `nclx` primaries/transfer/matrix/range
  equal its colour profile; `block.heic`, written at an exact block size, is the control - same coded
  64x64, no `clap` box at all, so the two files together show that reporting `ispe` alone would print a
  size one of the two pictures does not have.
  Compound File Binary (+2 container-level labels, 109 covered, 110 gaps) is the container Word and
  Excel 97 are stored in, and walking it is three linked tables rather than one header: a sector FAT
  whose own sector list is the DIFAT, a directory of 128-byte entries, and - for streams under
  0x1000 bytes - a second FAT and a second stream carried inside the root entry's own data. Two
  things only the cross-check settled: the header word at `0x38` is `Mini Stream Size`, always
  0x1000, and not the sector count an older reading of the layout suggested, and the DIFAT starts at
  `0x4C`, which is the only offset that leaves all 109 slots inside the 512-byte header.
  `scripts/make-cfb-fixtures.py` writes `word97.doc` with LibreOffice from a document python-docx
  generated and the two `.xls` files with xlwt (which owns its own compound-file writer), then walks
  each output itself and refuses to commit unless olefile, reading the same bytes, agrees on every
  stream name and size. The invariant the reader actually claims is the one a document does not need:
  chains are linked lists, so sector numbers interleave freely, but no sector may belong to two
  owners - `collisions` counts the ones that do, and it is 0 in all three real files.
  Binary STL (+1 field-level label, 110 covered, 109 gaps) is the opposite case: a format with no
  magic at all, where the only thing a file asserts about itself is `84 + 50 * triangles == size`.
  That identity is necessary and not sufficient, and CI proved how much: an HDF5 superblock that the
  HDF5 reader correctly refuses was picked up as a mesh because one byte at offset 80 of a real file
  divided evenly by 50. So the gate is the exact identity - a file whose count does not close is
  refused, not annotated - plus finite coordinates and a stored normal that is either zero or a unit
  vector, checked against *every* triangle. Normals are then listed as written *and* counted against
  the normal the three points imply, because writers disagree: meshio computes them, plenty of
  exporters leave them at zero, and `normals.stl` carries both cases on purpose.
  `scripts/make-stl-fixtures.py` writes the meshes with meshio and asserts that meshio's own reader
  returns the same triangle count the header declares.
  ICC profile (+1 field-level label, 111 covered, 108 gaps) has a magic, but not where a reader
  normally looks for one: the constant `acsp` sits at byte 36, behind the fields it identifies, and
  the whole format is big-endian in a tree of formats that are little-endian. The header states its own
  total length, so the two self-assertions are checked against each other, and the line the round
  actually drew is between the two ways they can disagree. A length that does not match the buffer is
  *reported* - `broken 1` beside the real and stated sizes - because the table is still there to read.
  A tag count whose table would run past the bytes is *refused*, because past the end of a real table
  sits tag payload, and walking it as a directory prints pointers no profile wrote. Two details only
  the written file settled: signatures are space-padded, so `RGB ` and `RGB` are the same colour space,
  and three of sRGB's eleven tags - `rTRC`, `gTRC`, `bTRC` - share one offset, so a reader that
  deduplicates pointers would report a shorter table than the profile carries.
  `scripts/make-icc-fixtures.py` builds both profiles with littleCMS through Pillow (`createProfile`
  assembles them from the library's own tables; neither is a copy of a file), walks the bytes with a
  private mirror, and refuses to write the probe unless `ImageCms` reading the same bytes agrees on the
  name and copyright it itself wrote.
  Enhanced Metafile (+1 field-level label, 112 covered, 107 gaps) is a record list in which the header
  is just another record - `u32 type, u32 size` - so the file's own length lives at byte 48 and the walk
  has to land on it, while the signature (`' EMF'`, at 40) sits behind the fields it signs. Two
  producers are committed on purpose, because one file cannot tell a rule from a habit: `gdi.emf` comes
  from Windows' own `CreateEnhMetaFileW`, and `page.emf` from LibreOffice's Draw export. They disagree
  about the header's record count - GDI's 5 matches the walk's 5, LibreOffice's 22 is one short of its
  23, because the header record is or is not counted - so the reader prints `records` and `walked`
  side by side and corrects neither. Record *types* are reported as numbers for the same reason: type 14
  closes both files, which is a fact about position, and no citable name table runs here (`cab`'s folder
  area is the earlier instance of the same refusal). What the reader does name is geometry: `bounds` in
  device units, `frame` in hundredths of a millimetre, and a pixels/mm pair that states the resolution
  relating them - 120.05 dpi for LibreOffice's page, 162.56 for GDI's screen, and the two rectangles
  agree to within the pixel the extents round apart. That pair is not a third copy of the same
  rectangle: on a file whose device is a monitor, it describes the monitor. The bounds themselves are
  checked outside this repo, against what Pillow's GDI-backed EMF opener reports as the image size.
  PostScript (+1 field-level label, 113 covered, 106 gaps) claims a line rather than a magic: `%!` at
  byte 0 - or not at byte 0 at all. LibreOffice's EPS export puts a binary preview in front, and the only
  way to name it honestly is its own arithmetic: the two little-endian words at 20 and 24 are the header's
  size (30) and the preview's length (11878), and their sum is exactly where `%!PS-Adobe-3.0` begins. That
  sum is the gate; the sixteen bytes between the magic and those words are printed as hex and named
  nothing, because one sample spells them `TK` and another puts a length there. ImageMagick supplies the
  second producer, writing a plain `%!PS-Adobe-3.0` at offset 0, and the two disagree in the way worth
  reporting: LibreOffice states `%%Pages: 0` for a file carrying one `%%Page: 1 1` while ImageMagick
  states 1 for one page - so `pages` prints the claim and the count side by side, the third instance of
  that shape after a PDF's `/Count` and an EMF's record count. Line endings are counted rather than
  assumed (the DSC allows CR, LF or CRLF: the two fixtures hold 9 CRLF and 0 respectively), and
  `broken` is the number of failed checks - a missing `%%EOF`, or a `%%BoundingBox` that is not four
  numbers - reported beside, not instead of, a walk that still finished.
  Lesson from the same round, and it undoes an old assumption: `magick` (ImageMagick 7.1.2) and a MiKTeX
  install have been on this host the whole time. The formats recorded as "no producer here" were checked
  against the package indexes and the obvious binaries, not against everything on PATH - so re-probe
  before believing any blocked-by-producer claim, as with the PDF/Chromium and venv cases above.
* COFF (+1 field-level label, 114 covered, 105 gaps) is the file the analysis lane is asked to open -
  what `clang -c` leaves behind before a linker sees it - and magika's `coff` label has no Kaitai spec
  at all, so the choice was a reader written here or a permanent gap. LLVM 22.1.8 supplied both fixtures
  (`x86_64-w64-windows-gnu` and the i686 triple, the second included precisely because a 32-bit object
  must read with the same code), and GNU objdump read them back: `-h` for every section name, size and
  file offset, `-t` for every symbol's value, section, type and storage class, and
  `scripts/make-coff-fixtures.py` writes no probe unless its own walk matches those two on all of it.
  Two format facts are what the reader had to get right. A name longer than eight bytes is not in the
  record: a section writes `/4` and a symbol leaves four zero bytes plus an offset, and both mean the
  string table that follows the last symbol record - which is why `.llvm_addrsig` appears nowhere in the
  record that names it. And the header's symbol count counts *records*, auxiliary entries included, so
  the section symbols come out at 0, 2, 4 and a cut row can only mean the walk left the file.
  Two traps this round turned up, neither of them a compiler error. A relocation count is two bytes wide
  while the pointer beside it is four, so a 32-bit read of `lines` returns the pointer's neighbour
  shifted together - 2097152 where the file says 0 - and the objdump-checked probe is what caught it.
  And a section's raw size is a 32-bit field on a wasm32 host where `usize` is 32 bits too, so an extent
  like `300 + 4294967295` overflows the machine word rather than exceeding the file: every bound here is
  computed in 64-bit integers, and `test/wasm.test.mjs` patches that field on the deployed module to
  prove the printed claim and the `broken` count come back the same from wasm32 as from a desktop build.
  The Characteristics word is the deliberate non-claim: `objdump -f` lists HAS_RELOC, HAS_LINENO,
  HAS_DEBUG, HAS_SYMS and HAS_LOCALS for these objects while clang writes zero into the header, so those
  words are bfd's conclusion from the contents and the reader prints the raw word the file holds.
  Relocation records came next in the same reader - **depth, not a label, so the counts above do not
  move** - because they are the only place an object uses a symbol index as an index: ten bytes of
  offset, record number and type, and the number counts auxiliary entries, which is why the `answer`
  call site is `sym 15(answer)` rather than the sixteenth entry of the table. The type names are the
  part nobody may recall: `objdump -r` prints 4 as `IMAGE_REL_AMD64_REL32`, 3 as `..._ADDR32NB` and
  0x14 as bare `DISP32` for the i386 object, and the fixture script compares its walk with that listing
  record by record - section grouping, offset, type and resolved symbol - and writes no probe unless all
  four agree. Two facts fell out of that comparison.
  `objdump -t` names a storage-class-103 symbol by the path in its auxiliary record (`answer.c`) while
  the entry itself carries `.file`; the row prints the entry and the script asserts the aux bytes spell
  what bfd prints, rather than waiving the mismatch. And the earlier check had been reading `ty` as
  decimal digits while bfd prints them as hex, which agrees by accident for every type whose digits are
  all below 10 - a witness that is subtly wrong looks exactly like a witness that passed. A third fact
  came from a hand-built case rather than from a witness: patch the symbol count to zero and there is no
  string table to resolve with, so the section keeps the literal `/4` its record holds - the alternative
  is reading four bytes past the header and calling the result a name.
* X.509 in DER (+1 field-level label, 115 covered, 104 gaps) is the second format the coverage sweep
  mis-filed as unreachable: it looked like a gap needing a self-written reader with no producer, while
  OpenSSL 3.5.7 has been on PATH the whole time and both writes **and** lists these files. The producer
  is `genpkey` + `req -new -x509` with the serial and both validity dates fixed - run through
  `subprocess`, because Git Bash rewrites `-subj /C=CN/...` into a Windows path before openssl sees it -
  and the witnesses are `asn1parse -inform DER -i`, whose list of offset, depth, header length, content
  length and type name the walk has to match **item for item in order**, and `x509 -text`, which states
  the version, serial, both algorithm names, the two times, the issuer and subject strings and the RSA
  key size. So the tree rows are somebody else's listing, and so are the names: `sha256WithRSAEncryption`
  for `1.2.840.113549.1.1.11` is what asn1parse printed beside those bytes, and the script checks its
  table in both directions, so a name that is wrong fails as loudly as one that is missing.
  A DER file makes exactly one claim about its own size - the top SEQUENCE's length - and the reader
  states whether it accounts for the file (`end yes` / `end no`) instead of deciding that a mismatch
  means there is no file; a certificate with one byte past the end is still read and reports
  `broken 2`, while one truncated by a byte cannot be walked at all and is not claimed. Two absences are
  deliberate: an EC key's `256 bit` comes from the *name* of its curve, so the row prints `bits -`
  rather than a size borrowed from a curve table, and the validity strings are printed as DER holds
  them (`260101000000Z`) because parsing a `UTCTime` needs a two-digit-year rule that nobody here has
  vouched for. Two fixtures, RSA and EC, because one sample of a shape is one shape.
* 7z (+1 container-level label, 116 covered, 103 gaps) is the third label the sweep mis-filed as
  unreachable: `py7zr 1.1.3` is installed here as both producer and witness, and it writes the two shapes
  the format has - `encoded.7z` with its header compressed, and `plain.7z` from
  `set_encoded_header_mode(False)` with the property tree in the open. A third archive comes from a
  different program altogether: the `bsdtar` 3.8.4 that Windows ships writes 7z with `--format=7zip`, at
  version 0.3 with its own packing, so the envelope rows stop describing one library's habits. The script
  keeps that archive only if `py7zr` - which did not write it - and bsdtar agree on its member list.
  What the reader reports is the
  envelope: version, where the header block is, how long it is, which of the two shapes it starts out to
  be, and the two CRCs the archive states about itself recomputed over the bytes they cover. That last
  pair is the useful part, because it works on every 7z whoever wrote it - it is the check that says a
  download finished and a file was not edited - and it depends on one offset nobody should guess at:
  `next_header_offset` counts from the end of the 32-byte start header, not from byte zero, which is how
  py7zr's own `SignatureHeader._read` treats it. The CRC itself is the reflected `0xEDB88320` form, and
  the implementation was shadowed in Python against `zlib.crc32` over a thousand random lengths before a
  single CI cycle was spent on it.
  What is *not* claimed is the file list, and the report says which of the two cases a file is rather
  than quietly producing nothing. In the plain shape the names are readable in principle but sit behind a
  `MainStreamsInfo` whose contents are raw numbers rather than property ids, so skipping it needs the
  folder-and-coder grammar; in the encoded shape they are behind a compressed stream this module has no
  decoder for - and the note does not name the codec, because the codec id lives inside the stream the
  note is about. So this one is credited exactly where `cab` is, and a truncation that removes the header
  block reads as `kind unreadable` plus a CRC row that says `unreachable` instead of printing a checksum
  over bytes that are gone.
* Photoshop document (+1 field-level label, 117 covered, 102 gaps) had been named as unreachable for the
  simplest reason - Pillow reads PSD and cannot write one - and the blocker was a package index away:
  `psd-tools` installs from a wheel and writes them. Pillow then does the job it can still do, which is
  being a second parser that shares no code with the writer, and the fixture script refuses to commit a
  file unless both agree on the header, the resource ids **and** the resource sizes. That matters more here
  than in most rounds, because a PSD has no total-length field at all: the only self-check the format
  offers is the image data's own arithmetic, either the sum of RLE's per-row byte counts equalling the
  payload that follows the table, or - uncompressed - the header predicting `channels x rows x columns x
  depth/8` exactly. Four fixtures rather than one because that is one file per branch the header can take:
  three channels, one, four under the same colour mode, and raw instead of RLE. Section spans are reported
  and a length that falls outside the file prints as `128+?` with the walk stopping there; six non-zero
  reserved bytes are counted as one broken claim rather than a reason to refuse; and a version-2 header -
  hand-built, labelled as such, because no PSB writer exists here - stops after its own row, since its
  section lengths are 64-bit and every offset below would be read at the wrong width.
  The layer records are **not** decoded, and the report says so in a row of its own. psd-tools can add
  pixel layers, and both it and ImageMagick list them afterwards with correct geometry - but the file it
  saves declares a zero-length layer section while the layer payload sits later in it. A walker written
  against those bytes would be fitted to one library's bug, so the section is reported as a span and the
  claim is left off rather than made quietly. Indexed colour is out for a related reason: `frompil` derives
  the colour mode from the PIL mode name and refuses `P`, so there is no palette file to read.
* Word template (+1 container-level label, 118 covered, 101 gaps) added a label with **no new parsing
  code**: a `.dotx` is the same OOXML package as a `.docx` - same part names, same `word/document.xml`,
  and no extension stored inside - so the only thing in either file that says which one it is, is the
  content type the package's own manifest declares for its main part: `wordprocessingml.template.main+xml`
  against `wordprocessingml.document.main+xml`. The classifier already opened `[Content_Types].xml` to find
  the package, so it now reads that line and prints it beside the part name; the name `word/` used to
  collapse every Word package into one code, and a template was therefore not a gap of knowledge but a gap
  of bookkeeping. `python-docx` writes the source and LibreOffice's `Office Open XML Text Template` filter
  writes the template from it, so the file is not hand-assembled; the witness is the manifest of both files
  re-read with `zipfile`, and the script refuses to commit unless the two content types differ in that
  one word and nothing else - which is also why only `dotx` is credited: `xltx` and `potx` are not magika
  labels at all, so this is one label rather than a family.
* OpenType with PostScript outlines (+1 field-level label, 119 covered, 100 gaps) was on the blocker list
  as "no CFF charstring writer runs here", and the writer has been in this repo's own venv the whole time:
  fontTools' `FontBuilder(isTTF=False)` writes a real CFF font. The reader is the same sfnt walk that has
  read `tiny.ttf` for rounds - `OTTO` sits in the four-byte flavour slot and the table directory is
  identical - so what was missing was the bookkeeping and one cross-check: `otf` is credited only when a
  `CFF ` table is *listed* (tag and all, trailing space included, since those four bytes are the tag)
  **and** the flavour agrees, and the row says what was found either way. A `glyf` font retagged `OTTO` -
  hand-built, labelled as such, because writers do not ship contradictions - therefore keeps the `ttf`
  label with `agrees no` printed beside it: a flavour tag is a claim, the outline table is the evidence,
  and where they disagree the weaker name stands. `CFF2` is not credited as `otf` at all, because nothing
  here writes one to prove anything about it. The second implementation is FreeType through Pillow, which
  shares no code with fontTools: it reports the family, an advance of 24 px for a 600-unit width in a
  1000-em font at 40 px, and metrics (32, 8) for the 800/-200 `hhea` pair - so the fixture is refused
  unless a program from another project reads the numbers the bytes state.
* vCard (+1 field-level label, 120 covered, 99 gaps) is the first reader in this repo whose input is
  ordinary line text: `BEGIN:VCARD`, `NAME;PARAM=value:value`, values folded by a following line that
  starts with a space, `END:VCARD`. `vobject` writes the two fixtures and reads them back - so "eight
  properties" is another implementation's count, not a comment agreeing with itself - and the shape that
  makes the format worth a reader of its own is the fold: fourteen physical lines carry ten logical ones,
  so a line count and a property count are different numbers and only the second one is the file's claim
  about itself. Counting is where the care went, not decoding: `N:Fixture\, Jr.;Lab;;;` has five
  sub-values because the comma is escaped, `ADR:;;1 Main St;…` has seven, `X;P="a:b;c":one` is one
  property whose name ends at the colon *outside* the quotes, and a value is never unescaped, so no row
  here pretends to have read the address book. `vcard` is a `fields` label over that line structure.
  Two refusals carry weight: `BEGIN:VCALENDAR` shares the grammar but `ics` is `is_text: true` in
  magika's table and so outside the 219 labels scored here, and `vcs` is inside the 219 with an empty
  knowledge-base entry - no mime, no description, no extension - which is a label that cannot be pinned
  to anything, so it stays a gap rather than becoming a guess. `tools/vcard-sim.py` is the usual shadow:
  a second reading of the same rules in Python, diffed against the rows before a CI cycle is spent.
* .torrent (+1 field-level label, 121 covered, 98 gaps) is bencode, the third format here with no magic
  to match: every string and every integer states its own length, so either the values tile the file
  exactly or the file is not what it claims, which is the whole of the acceptance rule - a walk that
  lands on the last byte and finds an `info` dictionary on the way. `bencode.py` writes both fixtures
  (`lab.torrent` single-file, `lab-multi.torrent` with a `files` list) and re-encodes each one back to
  identical bytes, so the key counts, the `pieces` length and the file count in the probe are another
  implementation's. Two things are reported rather than demanded, because both are cases where a real
  file can be readable and still wrong: dictionary keys out of BEP-3's byte order come back as
  `sorted no` with a count of the dictionaries that did it, and `pieces` - a flat string of 20-byte
  SHA-1 hashes - states `pieces_x20 no` when its length does not divide, which is the one arithmetic
  check the format offers on a field rather than on the file. A `length` inside a `files` entry is one
  file's size and not the torrent's, so named values are read at the key they were reached under, and
  the shape row says `single` or `multi` from which of the two the file actually has.
* JSONC (+1 field-level label, 124 covered, 95 gaps) is JSON with the two things strict JSON forbids. It is
  the fifth format here with nothing to recognise it by - the claim is that the whole file parses and that a
  strict parser would refuse it - and the first whose witness is a *second parser* rather than a writer:
  `scripts/make-jsonc-fixtures.py` authors the settings file, then Microsoft's `jsonc-parser` - the parser
  VS Code uses for its own configuration - supplies the comment count, the member tree with its paths and
  depths, and the byte spans the trailing-comma count is taken from, while `json.loads` supplies the
  refusal that makes the file JSONC at all. The script will not write the probe unless both answers arrive,
  so a fixture that was only half-distinguished from plain JSON cannot be credited. The reader's own
  acceptance rule is the whole file parsing plus at least one comment or trailing comma, which is what
  keeps `json` out of this label; a document with an unclosed comment, a root that is not an object, text
  after the closing brace, an escaped key (a path nobody would recognise) or a number outside the JSON
  grammar - `01`, `+1`, `1e`, `1.` - is refused rather than completed by guesswork.
* MSF 7.00 (+1 container-level label, 123 covered, 96 gaps) is the `.pdb` a linker writes, and it is the
  file the types actually live in once a binary is linked. The page size, block count and free-page map come
  from the superblock; the stream table comes from the pages it names - two inline, the rest through the list
  page - and each stream's size and block list are reported as the directory gives them, with the four reserved
  indices (`old-msf-directory`, `pdb`, `tpi`, `dbi`, `ipi`) named by position because `llvm-pdbutil` labels
  them that way and the fixture script checks the labels agree. The PDB stream's version, signature and age and
  the TPI header's declared record bytes are checked against that witness too. Two refusals carry the weight:
  the feature word is printed as a word, because llvm's `Has Types / Has IDs / Has Debug Info` answers turned
  out to be about which streams the directory holds - which is what the `has` rows say - and not names for its
  bits, which the first draft assumed and the witness rejected; and the GUID is the sixteen bytes as they lie,
  because its first word repeats the signature and any reformatting would be an endianness claim.
* OpenPGP (+1 field-level label, 122 covered, 97 gaps) is the fourth format here with no magic: a
  transfer is a run of packets and each one states its own payload length, so the acceptance rule is
  again "the lengths tile the file". An unstated length is allowed only on the packet that carries a stream
  to the end of the file - compressed or literal data - and that limit is what a CI run caught: `0x93`, the
  first octet of a NumPy array, is an old-format header whose two low bits mean "no length follows", so
  without the rule *any* file of *any* size is a valid one-packet OpenPGP transfer. `gpg` 2.4.9 (Git for Windows) writes six fixtures and
  `gpg --list-packets` is the witness, which is an unusually direct one - it prints `off`, `ctb`, `tag`,
  `hlen` and `plen` for every packet - so the generator refuses to write the probe unless its own walk of
  the bytes agrees with gpg's numbers packet for packet, *and* with the names gpg spells (`public key`,
  `onepass_sig`, `literal data`). Two header formats had to be demonstrated rather than recalled: an
  old-format header puts the length octet count in the tag octet's two low bits, so the ed25519 export
  (every packet under 192 bytes) never shows the two-octet branch and the rsa2048 export exists to - and
  a witness can be quietly wrong about field *order*: gpg lists a session-key packet as "version, algo,
  keyID" while the packet itself spells version, keyID, algo, so reading them positionally prints `0xff`,
  the key ID's first octet, as an algorithm, which is the kind of number that would have shipped as a
  confident wrong field. Nothing is decompressed or decrypted: past a compressed or encrypted packet the
  report says `descend no deflate` / `descend no encrypted` and stops, and a one-pass signature prints no
  algorithm fields at all because the witness prints none either.
* A format only looked blocked because the producer was looked for in the wrong place. PDF has no
  Kaitai spec and no `qpdf`, `mutool`, `gs` or `pandoc` on this host, so the only writer available
  was Pillow - one habits, one object numbering. `scripts/make-pdf-fixtures.sh` finds that a headless
  Chromium is a second, independent PDF writer (`Skia/PDF m153` in the file's own `/Producer`), and
  the four committed fixtures now cross each other: Skia numbers objects in Pillow's opposite order,
  puts the catalog at 13 rather than 4, writes A4 as `594.95996` points where Pillow's pages are
  whole, and carries a `/Count` that a tree need not agree with. So the reader resolves the trailer's
  `/Root` through the cross-reference table, walks `/Kids` to the leaves, and reports the claimed
  `/Count` beside the leaves it found; the depth and node caps are exercised by a hand-written tree
  whose `/Kids` points back at itself. Lesson kept general: before coding around a "no producer"
  claim, search the installed binaries as well as the package indexes.
* The ASF/FLV/CAB group listed here as "ready to build" is built: all three walk their objects or
  records against ffmpeg's and `makecab`'s own bytes, and are credited at container level only.
  Two more were unbuilt for a reason that has since gone away: `doc` and `xls` were listed as needing a
  CFB writer that this host did not have, and `scripts/make-cfb-fixtures.py` found LibreOffice plus `xlwt`
  writing them and `olefile` reading both back, so they are credited at container level now. What is left
  of that list is `ppt`, which re-probed badly: the filter name is accepted, the store is refused
  (`impl_store ... 0x81a`), because a Draw document is not an Impress document - so the size figure that
  used to be given as its blocker belongs to a file this host cannot make. And `chm`, which has not been
  probed for a writer since the lesson above.
* Refused rather than guessed: **CAB's folder area** - the *file* table decodes exactly as documented
  and matches `expand -D`, but `makecab` gives it 8 bytes where `CFFOLDER` is specified as 16, so the
  reader stops at the file table and `cab` is credited as a container, not a field-level parser.
  **PAM (P7)** ends its header with the token `ENDHDR` instead of a fixed count of integers, so the
  Netpbm reader rejects it rather than reporting a geometry from the wrong offsets. **IPv4** is still
  unresolved: the generated reader over-reads the hand-built 24-byte packet by four bytes, and until
  that is explained the format is not claimed.
* Blocked on somebody else: 28 generated readers still have
  no fixture because nothing here writes rpm, xar, ext2, GPT, ISO 9660, registry hives or
  `.DS_Store`. And the licence question that gates shipping - what kaitai.io permits for *generated*
  code - has no written answer upstream, so the 41 generated readers stay feasibility evidence, not
  product capability.

## Prior art worth copying instead of rebuilding

| Project | Stars | Why it matters here |
|---|---|---|
| [copy/v86](https://github.com/copy/v86) | 23.5k | x86 emulation + x86→wasm JIT in the browser: the only permissive `.exe` story |
| [danoon2/Boxedwine](https://github.com/danoon2/Boxedwine) | 1.1k | the only maintained Win32-in-browser that needs no Windows image — and it is GPL-2.0 |
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 25.6k | canonical APK decode semantics (AXML, resources.arsc) |
| [google/magika](https://github.com/google/magika) | 18.6k | file-type identification, ships a JS/wasm package |
| [lief-project/LIEF](https://github.com/lief-project/LIEF) | 5.5k | one API over ELF/PE/Mach-O/DEX/ART |
| [m4b/goblin](https://github.com/m4b/goblin) | 1.5k | MIT, `no_std`-capable PE/ELF parsing — what to adopt if the hand-rolled reader grows |
| [futurepress/epub.js](https://github.com/futurepress/epub.js/blob/master/src/store.js) | 7.0k | the same archive→`createObjectURL`→revoke shape, in production (licence is a custom BSD variant, so read it before vendoring) |
| [ofk/libarchive-wasm](https://github.com/ofk/libarchive-wasm) | 23 | proof that libarchive builds to wasm |
