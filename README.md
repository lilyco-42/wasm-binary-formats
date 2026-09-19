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
| `unpack` | list entries and extract files, plus decompressors | 47 | libarchive `archive.h` `ARCHIVE_FORMAT_*` / `ARCHIVE_FILTER_*` (BSD-2) |
| `parse` | structured parsing of executables and package layers | 12 | LIEF supported formats (Apache-2.0) + Apktool's decoded layers (Apache-2.0) |
| `execute` | actually run the thing | 2 | v86 x86 emulator (BSD-2) for `.exe`; a sandbox for APK `assets/` |

**Actionable today: 61 formats.** The 1688 identification rows are a signature table, not 1688
modules — counting them to reach "200" would be padding, so this file says 61 instead.

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
controlled JS: it needs its own origin or a Service Worker sandbox with no access to this site's
cookies, storage or same-origin documents. That decision (sandbox model, CSP, storage quota) is
the actual work, and it is orthogonal to how many formats we can list.

## Reproduce

```bash
node scripts/fetch-sources.mjs   # pulls Tika, libarchive, LIEF, Apktool, v86
node scripts/build-catalog.mjs   # writes catalog/formats.json and the counts above
```

## Prior art worth copying instead of rebuilding

| Project | Stars | Why it matters here |
|---|---|---|
| [copy/v86](https://github.com/copy/v86) | 23.5k | x86 emulation + x86→wasm JIT in the browser: the `.exe` answer |
| [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool) | 25.6k | canonical APK decode semantics (AXML, resources.arsc) |
| [google/magika](https://github.com/google/magika) | 18.6k | file-type identification, ships a JS/wasm package |
| [lief-project/LIEF](https://github.com/lief-project/LIEF) | 5.5k | one API over ELF/PE/Mach-O/DEX/ART |
| [ofk/libarchive-wasm](https://github.com/ofk/libarchive-wasm) | 23 | proof that libarchive builds to wasm |
