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
  sandbox with relative references rewritten to `data:` URLs; `.exe`/`.dll` get the PE panel.
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
generates PNG/GIF/BMP readers, and parses fixtures this repo wrote itself - 4 tests, 0 failures.


* Licences: **compiler GPLv3+** (so it runs in CI and is never shipped), **JS runtime
  `kaitai-struct@0.11.0` Apache-2.0**, Python and Rust runtimes MIT. What kaitai.io does **not**
  state is the licence of generated code - that has to be settled in writing before a generated
  reader is linked into a paid product.
* Measured runtime trap: `new Png(uint8)` left `_io` without `readBytes` on Node 22, while
  `new Png(new KaitaiStream(bytes), null, null)` parsed the same file completely and returned the
  full three-chunk list. Drive generated readers with an explicit stream.
* [ImHex-Patterns](https://github.com/WerWolv/ImHex-Patterns) holds 314 `.hexpat` format
  descriptions but is **GPL-2.0**: something to read, not to vendor. For identification,
  [google/magika](https://github.com/google/magika) (star 18622, Apache-2.0) is the permissive pick.


### What that costs, by family

Re-generated on CI from compiler 0.11 (the numbers below are the CI numbers, not a local run):

| family | formats | generated JS | mean | heaviest |
|---|---|---|---|---|
| image | 8 | 440,090 B | 55,011 B | Dicom 347,766 B |
| executable | 7 | 289,667 B | 41,381 B | MachO 92,584 B |
| archive | 6 | 85,933 B | 14,322 B | Rpm 38,514 B |
| media | 4 | 70,569 B | 17,642 B | Wav 33,543 B |
| serialization | 4 | 54,514 B | 13,629 B | PhpSerializedValue 21,631 B |
| font | 1 | 52,968 B | 52,968 B | Ttf 52,968 B |
| filesystem | 4 | 46,764 B | 11,691 B | Vfat 16,072 B |
| database | 1 | 13,475 B | 13,475 B | Sqlite3 13,475 B |
| log | 1 | 9,437 B | 9,437 B | SystemdJournal 9,437 B |
| network | 1 | 4,165 B | 4,165 B | Ipv4Packet 4,165 B |
| **total** | **37** | **1,067,582 B** | 28,854 B | + 11 shared files, 93,499 B |

**Three tiers, because the mean hides the tail.** 22 formats stay under 15 KB apiece (189 KB
together) and can ship in one bundle; 12 land between 15 and 60 KB (353 KB); 3 are heavy enough
to load on demand - `Dicom` alone is 347,766 B, a third of the whole 37-format set, with
`MachO` 92,584 B and `Elf` 85,025 B behind it. The practical grouping is therefore: always-load
core (images, archives, containers), lazy-load binaries, and consider dropping DICOM unless a
medical use case is real.

Scaling: at the measured mean of 28,854 B, all 189 upstream specs would be
about 5.2 MB of unminified JavaScript - still not hundreds of wasm modules, and the heavy tail
above is what makes the number shrink once tiered.

## Reproduce

```bash
node scripts/fetch-sources.mjs   # pulls Tika, libarchive, LIEF, Apktool, v86
node scripts/build-catalog.mjs   # writes catalog/formats.json and the counts above
node scripts/make-fixture.mjs    # rewrites test/fixtures/lab-fixture.apk
node --test test/wasm.test.mjs engine/target/wasm32-unknown-unknown/release/apk_lens.wasm
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
