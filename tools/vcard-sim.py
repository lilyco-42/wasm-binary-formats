"""A second reading of the Rust control flow in `read_vcard`, diffed against its expected rows.

Not a test: this file exists so the numbers the Rust test pins are known to be right before a CI cycle
is spent. It mirrors `engine/src/containers.rs` line for line - same split, same fold rule, same
escape-carrying part count, same row order - so a mistake in the *rule* shows up here rather than in CI.
"""
import io
import json
import os
import sys

FIXTURES = os.path.join(os.path.dirname(__file__), '..', 'test', 'fixtures')
MAX_NAMES = 24


def split(line):
    quoted = False
    at = None
    for index, ch in enumerate(line):
        if ch == '"':
            quoted = not quoted
        elif ch == ':' and not quoted:
            at = index
            break
    if at is None:
        return None
    pieces = line[:at].split(';')
    name = pieces[0]
    if not name:
        return None
    return name, pieces[1:], line[at + 1:]


def parts(value):
    count = 1
    escaped = False
    for ch in value:
        if escaped:
            escaped = False
            continue
        if ch == '\\':
            escaped = True
        elif ch == ';':
            count += 1
    return count


def read(data):
    text = data.decode('utf8', 'strict')
    trimmed = text[1:] if text.startswith('\ufeff') else text
    if not trimmed[:11].upper().startswith('BEGIN:VCARD'):
        return None
    if len(trimmed) > 11 and trimmed[11] not in '\r\n':
        return None
    card = {
        'names': {}, 'props': 0, 'logical': 0, 'physical': 0, 'crlf': 0, 'lf': 0,
        'folded': 0, 'broken': 0, 'escapes': 0, 'components': 0, 'depth': 0,
        'version': '', 'version_second': False, 'ended': False, 'terminated': False,
        'truncated': False,
    }
    pending = ''
    pieces = [chunk for chunk in trimmed.split('\n')]
    chunks = [chunk + '\n' for chunk in pieces[:-1]] + ([pieces[-1]] if pieces[-1] else [])
    for piece in chunks:
        card['physical'] += 1
        if piece.endswith('\r\n'):
            card['crlf'] += 1
            body, terminated = piece[:-2], True
        elif piece.endswith('\n'):
            card['lf'] += 1
            body, terminated = piece[:-1], True
        else:
            body, terminated = piece, False
        card['terminated'] = terminated
        if not body:
            card['broken'] += 1
            continue
        if body[0] in ' \t':
            if not pending:
                card['broken'] += 1
                continue
            card['folded'] += 1
            pending += body[1:]
            continue
        if pending:
            record(card, pending)
            if card['truncated']:
                break
        pending = body
    if not card['truncated'] and pending:
        record(card, pending)

    rows = ['vcard\t{}\tprops\t{}\tnames\t{}\tlines\t{}\tfolded\t{}\tcomponents\t{}'.format(
        card['version'] or '-', card['props'], len(card['names']), card['physical'],
        card['folded'], card['components'])]
    rows.append('endings\tcrlf\t{}\tlf\t{}\tlogical\t{}\tlast_newline\t{}'.format(
        card['crlf'], card['lf'], card['logical'], 'yes' if card['terminated'] else 'no'))
    rows.append('version\t{}\tsecond\t{}'.format(
        card['version'] or '-', 'yes' if card['version_second'] else 'no'))
    rows.append('end\t{}\tbroken\t{}\tescapes\t{}'.format(
        'yes' if card['ended'] else 'no', card['broken'], card['escapes']))
    listed = sorted(card['names'])[:MAX_NAMES]
    for name in listed:
        count, most, keys = card['names'][name]
        rows.append('prop\t{}\tcount\t{}\tparts\t{}\tparams\t{}'.format(
            name, count, most, ','.join(sorted(keys)) if keys else '-'))
    if len(card['names']) > len(listed):
        rows.append('cut\tnames\t{}'.format(len(card['names']) - len(listed)))
    if card['truncated']:
        rows.append('stopped\tlines\t20000')
    return rows


def record(card, line):
    card['logical'] += 1
    if card['logical'] > 20000:
        card['truncated'] = True
        return
    parsed = split(line)
    if parsed is None:
        card['broken'] += 1
        return
    name, params, value = parsed
    upper = name.upper()
    card['escapes'] += value.count('\\')
    card['ended'] = False
    if upper == 'BEGIN':
        card['depth'] += 1
        card['components'] += 1
        return
    if upper == 'END':
        card['depth'] = max(0, card['depth'] - 1)
        card['ended'] = card['depth'] == 0
        return
    if card['depth'] == 0:
        card['broken'] += 1
    card['props'] += 1
    if card['logical'] == 2 and upper == 'VERSION':
        card['version'] = value.strip()
        card['version_second'] = True
    keys = [item.split('=')[0].upper() for item in params if '=' in item]
    got = parts(value)
    seen = card['names'].get(upper)
    if seen:
        card['names'][upper] = (seen[0] + 1, max(seen[1], got), sorted(set(seen[2]) | set(keys)))
    else:
        card['names'][upper] = (1, got, sorted(set(keys)))


def main():
    out = {}
    for label in ('lab.vcard', 'lab3.vcard'):
        rows = read(open(os.path.join(FIXTURES, label), 'rb').read())
        out[label] = rows
        print('==', label)
        for row in rows:
            print('   ', repr(row))
    hostile = {
        # A fold with nothing to continue, and a property after the card has closed.
        'stray': b'BEGIN:VCARD\r\nVERSION:4.0\r\nFN:a\r\nEND:VCARD\r\n trailing\r\nFN:after\r\n',
        # No final newline: the file stops mid-record.
        'unterminated': b'BEGIN:VCARD\r\nVERSION:3.0\r\nFN:a\r\nEND:VCARD',
        # A quoted parameter value with a colon and a semicolon inside it.
        'quoted': b'BEGIN:VCARD\r\nVERSION:4.0\r\nX;P="a:b;c":one\r\nEND:VCARD\r\n',
        # A colonless line, and an escaped semicolon inside a value.
        'escape': b'BEGIN:VCARD\r\nVERSION:4.0\r\nNOTE:a\;b\r\nbroken line\r\nEND:VCARD\r\n',
        # vCalendar shares the grammar and is not this format.
        'calendar': b'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nEND:VCALENDAR\r\n',
        # lower case begin
        'lower': b'begin:vcard\r\nversion:2.1\r\nFN:x\r\nEND:VCARD\r\n',
    }
    for label, data in hostile.items():
        rows = read(data)
        print('==', label, 'None' if rows is None else rows)
        out[label] = rows
    with io.open(os.path.join(FIXTURES, '..', '..', 'temp', 'vcard-shadow.json'), 'w', encoding='utf8') as handle:
        json.dump(out, handle, indent=1, sort_keys=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
