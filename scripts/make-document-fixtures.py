"""Office package fixtures for the document reader's tests (engine/tests/office.rs).

The .docx comes from python-docx, so it is a real writer's output. The others are assembled with
Python's `zipfile` around the minimum set of parts each specification requires. The XML is synthetic
and deliberately not validated - the reader only looks at part names, the ODF/EPUB `mimetype` string
and one EPUB `full-path` attribute - and the test asserts nothing beyond that, so nothing here needs
to be a document any word processor would open.

Both ODF and EPUB mandate `mimetype` as the first member, stored rather than deflated; that ordering
is why the reader checks the mimetype string before it looks at anything else.

    python scripts/make-document-fixtures.py [out_dir]   (default: test/fixtures)
"""

import os
import sys
import zipfile

out = sys.argv[1] if len(sys.argv) > 1 else "test/fixtures"
os.makedirs(out, exist_ok=True)

DECL = '<?xml version="1.0" encoding="UTF-8"?>\n'


def target(name: str) -> str:
    return os.path.join(out, name)


def odf(name: str, media: str) -> None:
    with zipfile.ZipFile(target(name), "w", zipfile.ZIP_DEFLATED) as book:
        info = zipfile.ZipInfo("mimetype")
        info.compress_type = zipfile.ZIP_STORED
        book.writestr(info, f"application/vnd.oasis.opendocument.{media}")
        book.writestr(
            "META-INF/manifest.xml",
            DECL
            + '<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0">'
            + f'<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.{media}"/>'
            + '<manifest:file-entry manifest:full-path="/content.xml" manifest:media-type="text/xml"/>'
            + "</manifest:manifest>",
        )
        book.writestr("content.xml", DECL + f"<office:{media}-content/>")


def ooxml(name: str, directory: str, main: str) -> None:
    with zipfile.ZipFile(target(name), "w", zipfile.ZIP_DEFLATED) as book:
        book.writestr(
            "[Content_Types].xml",
            DECL
            + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            + '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            + f'<Override PartName="/{directory}/{main}" ContentType="application/octet-stream"/>'
            + "</Types>",
        )
        book.writestr(
            "_rels/.rels",
            DECL
            + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + f'<Relationship Id="rId1" Type="officeDocument" Target="{directory}/{main}"/>'
            + "</Relationships>",
        )
        book.writestr(f"{directory}/{main}", DECL + f"<{directory}/>")


def epub() -> None:
    with zipfile.ZipFile(target("tiny.epub"), "w", zipfile.ZIP_DEFLATED) as book:
        info = zipfile.ZipInfo("mimetype")
        info.compress_type = zipfile.ZIP_STORED
        book.writestr(info, "application/epub+zip")
        book.writestr(
            "META-INF/container.xml",
            DECL
            + '<container xmlns="urn:oasis:names:tc:opendocument:xmlns:container">'
            + '<rootfiles><rootfile full-path="OEBPS/content.opf" '
            + 'media-type="application/oebps-package+xml"/></rootfiles></container>',
        )
        book.writestr(
            "OEBPS/content.opf",
            DECL + '<package xmlns="http://www.idpf.org/2007/opf" version="3.0"/>',
        )


try:
    import docx

    document = docx.Document()
    document.add_paragraph("Lab fixture paragraph")
    document.save(target("tiny.docx"))
    print("made tiny.docx (python-docx)")
except Exception as exc:  # a build without the library still gets the rest
    print("skipped: tiny.docx", exc.__class__.__name__)

ooxml("tiny.xlsx", "xl", "workbook.xml")
ooxml("tiny.pptx", "ppt", "presentation.xml")
odf("tiny.odt", "text")
odf("tiny.ods", "spreadsheet")
odf("tiny.odp", "presentation")
epub()

for name in ("tiny.docx", "tiny.xlsx", "tiny.pptx", "tiny.odt", "tiny.ods", "tiny.odp", "tiny.epub"):
    if os.path.exists(target(name)):
        with zipfile.ZipFile(target(name)) as book:
            first = book.namelist()[0]
            stored = book.getinfo(first).compress_type == zipfile.ZIP_STORED
            print("fixture", name, os.path.getsize(target(name)), "B", len(book.namelist()),
                  "parts, first =", first, "stored" if stored else "")
