"""A second reading of the Rust bencode walk in `engine/src/containers.rs`, producing the same rows.

Not a test: this exists so the numbers the Rust and JS tests pin are known to be right before a CI cycle
is spent on them. It mirrors the Rust control flow - same caps, same row order, same refusals - so a
mistake in the *rule* shows up here rather than in CI.

One walk does the whole job. Every value is told the key it sits under, which is how `pieces`, `length`,
`piece length` and `files` are picked up on the way past rather than by a second scan, and why the node
count cannot double-count anything. Everything else about bencode is a length the file states itself:
that is the whole reason this format can be checked without a magic.

    python tools/torrent-sim.py
"""
import json
import os

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test', 'fixtures')
MAX_NODES = 4096
MAX_DEPTH = 32


class Reader(object):
    def __init__(self, raw):
        self.raw = raw
        self.nodes = 0
        self.keys = 0
        self.broken = 0
        self.unsorted = 0
        self.max_depth = 0
        self.failed = False
        self.truncated = False
        self.announce = None
        self.info = False
        self.pieces = None
        self.length = None
        self.piece_length = None
        self.files = None

    def fail(self):
        self.broken += 1
        self.failed = True
        return None

    def digits(self, pos):
        start = pos
        while pos < len(self.raw) and 48 <= self.raw[pos] <= 57:
            pos += 1
        return (None, pos) if start == pos else (int(self.raw[start:pos]), pos)

    def plain(self, pos):
        """An `i…e` integer or a `len:` string, as (kind, value, next)."""
        if pos >= len(self.raw):
            return self.fail()
        if self.raw[pos] == ord('i'):
            number, at = self.digits(pos + 1)
            if number is None or at >= len(self.raw) or self.raw[at] != ord('e'):
                return self.fail()
            return 'int', number, at + 1
        length, at = self.digits(pos)
        if length is None or at >= len(self.raw) or self.raw[at] != ord(':'):
            return self.fail()
        start = at + 1
        if start + length > len(self.raw):
            return self.fail()
        return 'text', self.raw[start:start + length], start + length

    def value(self, pos, key, inside, depth):
        """One value of any kind. `key` is the dictionary key it was reached through, if any."""
        if self.nodes >= MAX_NODES or depth > MAX_DEPTH:
            self.broken += 1
            self.truncated = True
            return self.fail()
        self.nodes += 1
        self.max_depth = max(self.max_depth, depth)
        if pos >= len(self.raw):
            return self.fail()
        first = self.raw[pos]
        if first == ord('d'):
            return self.dictionary(pos + 1, key, inside, depth)
        if first == ord('l'):
            return self.list_at(pos + 1, key, inside, depth)
        if first == ord('i') or 48 <= first <= 57:
            got = self.plain(pos)
            if got is None:
                return None
            self.note(key, inside, got)
            return got[2]
        return self.fail()

    def note(self, key, inside, got):
        """The handful of named values the report carries, seen as they go past."""
        if key == 'pieces' and got[0] == 'text' and inside == 'info':
            self.pieces = len(got[1])
        elif key == 'length' and got[0] == 'int' and inside == 'info':
            self.length = got[1]
        elif key == 'piece length' and got[0] == 'int' and inside == 'info':
            self.piece_length = got[1]
        elif key == 'announce' and got[0] == 'text' and inside is None:
            printable = all(32 <= each <= 126 for each in got[1])
            if printable:
                self.announce = got[1].decode('latin-1')

    def dictionary(self, pos, key, inside, depth):
        if key == 'info':
            self.info = True
        previous = None
        counted = 0
        while pos < len(self.raw) and self.raw[pos] != ord('e'):
            name = self.plain(pos)
            if name is None:
                return None
            field = name[1].decode('latin-1')
            if previous is not None and previous > field:
                self.unsorted += 1
            previous = field
            counted += 1
            if depth == 1:
                self.keys = counted
            nxt = self.value(name[2], field, key, depth + 1)
            if nxt is None:
                return None
            pos = nxt
        if pos >= len(self.raw):
            return self.fail()
        return pos + 1

    def list_at(self, pos, key, inside, depth):
        items = 0
        while pos < len(self.raw) and self.raw[pos] != ord('e'):
            nxt = self.value(pos, None, None, depth + 1)
            if nxt is None:
                return None
            items += 1
            pos = nxt
        if pos >= len(self.raw):
            return self.fail()
        if key == 'files' and inside == 'info':
            self.files = items
        return pos + 1


def read(raw):
    if raw[:1] != b'd':
        return None
    book = Reader(raw)
    end = book.value(0, None, None, 1)
    if end != len(raw) or not book.info:
        return None
    shape = 'single' if book.length is not None else 'multi'
    rows = [
        'bencode\tkeys\t{}\tnodes\t{}\tdepth\t{}\tbytes\t{}\tends\tyes'.format(
            book.keys, book.nodes, book.max_depth, len(raw)),
        'sorted\t{}\tunsorted\t{}'.format('yes' if not book.unsorted else 'no', book.unsorted),
        'info\t{}\tpieces\t{}\tpieces_x20\t{}\tpiece_length\t{}'.format(
            shape, book.pieces if book.pieces is not None else '-',
            'yes' if book.pieces and book.pieces % 20 == 0 else 'no',
            book.piece_length if book.piece_length is not None else '-'),
    ]
    if shape == 'single':
        rows.append('length\t{}'.format(book.length))
    else:
        rows.append('files\t{}'.format(book.files if book.files is not None else '-'))
    if book.announce is not None:
        rows.append('announce\t{}'.format(book.announce))
    rows.append('broken\t{}'.format(book.broken))
    if book.truncated:
        rows.append('stopped\tnodes\t{}'.format(MAX_NODES))
    return rows


def text(value):
    return str(len(value)).encode() + b':' + value


def number(value):
    return b'i' + str(value).encode() + b'e'


def dictionary(pairs):
    return b'd' + b''.join(text(key) + value for key, value in pairs) + b'e'


INFO = dictionary([(b'length', number(1)), (b'piece length', number(16384)),
                   (b'pieces', text(b'a' * 20))])

CASES = {
    # Bencode that is well formed but says nothing about a torrent: no info dictionary.
    'no-info': dictionary([(b'announce', text(b'tracker'))]),
    # Keys out of BEP-3's byte order: counted, reported, still read.
    'unsorted': dictionary([(b'info', INFO), (b'announce', text(b'tracker'))]),
    # A dict that never closes.
    'truncated': b'd4:infod6:lengthi1e',
    # Not a dict at the root at all.
    'not-a-dict': number(42),
    # A string length that runs off the end of the file.
    'over-read': b'd4:name99:abce',
    # A pieces value that is not a whole number of SHA-1 hashes.
    'odd-pieces': dictionary([(b'info', dictionary([(b'pieces', text(b'a' * 21))]))]),
}


def main():
    for name in ('lab.torrent', 'lab-multi.torrent'):
        raw = open(os.path.join(FIXTURES, name), 'rb').read()
        rows = read(raw)
        print('==', name, len(raw))
        for row in rows or ['<refused>']:
            print('   ', repr(row))
    for name, raw in sorted(CASES.items()):
        print('==', name, read(raw))
    return 0


if __name__ == '__main__':
    main()
