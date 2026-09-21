"""Produce and check the C++ name-decoding fixture - what two demanglers have to agree on.

A listing where every `_ZN...` is still the compiler's own handwriting is not much use for reading a
binary, so the analysis module demangles the Itanium names it meets in a symbol table. What it prints is
credited to two demanglers that are not this one: binutils' `c++filt` and LLVM's `llvm-cxxfilt`, each run
over the exact name list read out of the object's own symbol table with `llvm-readobj --symbols`. Where
the two agree, that string is the thing the Rust reader has to reproduce. Where they do not - `Dn` is
`decltype(nullptr)` to binutils and `std::nullptr_t` to LLVM - the name is recorded as diverged and the
reader refuses it, because choosing between two witnesses would be an opinion about a spelling rather
than a reading of the bytes.

Nothing here is a hand-typed mangled name: clang decides which shapes the fixture holds, and the script
stops if a shape it means to cover is missing from clang's list (a constructor written only as `C2`, say,
or no substitution at all), so the claim cannot narrow silently when a compiler changes.

    temp/venv/Scripts/python.exe scripts/make-demangle-fixtures.py [--refresh]

The committed `cxx.o` is reused unless `--refresh` is given, because clang stamps its version into the
object's comment section and a rebuild would move bytes the probe has nothing to say about.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "test", "fixtures")

TARGET = "x86_64-unknown-linux-gnu"

SOURCE = """\
// Every construct below is there because a demangled form of it is wanted in the probe; the shapes are
// clang's choice to spell, and this file only says which ones must appear.

namespace ns {
struct Box { int i; double arr[3]; };
long counter;
int nested_fn(Box*, char);
}

struct Foo {
  int value;
  Foo();
  ~Foo();
  int read() const;
  void set(double* p, const char& c);
  static int stat(long);
  int* matrix(int (&r)[5]);
  char op(Foo const&) const;
};

template <class T>
T pick(T a, T b) { return a > b ? a : b; }

int free_fn(int, double*, char const&);
void ref_fn(int&, const long**, short);
void bytes(float, unsigned long long, signed char, unsigned, bool);
void (*retfn(int))(double);
unsigned long long tail(unsigned, long long, __int128, unsigned __int128);
long double wide(long double);
void vars(char*, const wchar_t*, decltype(nullptr));

int ns::nested_fn(Box*, char) { return 0; }
Foo::Foo() {}
Foo::~Foo() {}
int Foo::read() const { return 0; }
void Foo::set(double*, const char&) {}
int Foo::stat(long) { return 0; }
int* Foo::matrix(int (&r)[5]) { return r; }
char Foo::op(Foo const&) const { return 0; }
int free_fn(int, double*, char const&) { return 0; }
void ref_fn(int&, const long**, short) {}
void bytes(float, unsigned long long, signed char, unsigned, bool) {}
void (*retfn(int))(double) { return 0; }
unsigned long long tail(unsigned, long long, __int128, unsigned __int128) { return 0; }
long double wide(long double) { return 0; }
void vars(char*, const wchar_t*, decltype(nullptr)) {}
int use_pick() { return pick(1, 2); }
"""

# Each entry is (what the probe needs to see, a regex over the mangled name). These are the shapes the
# Rust reader implements, so a fixture that stopped containing one is a narrowing of the claim.
SHAPES = [
    ("a nested name", re.compile(r"^_ZN.*E")),
    ("a constructor written C1", re.compile(r"C1E?v?$")),
    ("a constructor written C2", re.compile(r"C2E?v?$")),
    ("a destructor", re.compile(r"D[012]E?v?$")),
    ("a const member function", re.compile(r"^_ZNK")),
    ("a self substitution", re.compile(r"S_")),
    ("a nested substitution", re.compile(r"NS_\w+E")),
    ("a reference parameter", re.compile(r"R[A-Za-z]")),
    ("a pointer parameter", re.compile(r"P[A-Za-z]")),
    ("an array type", re.compile(r"A\d+_")),
    ("a template argument list", re.compile(r"^_Z\w+I\w+E")),
    ("a template parameter as the return type", re.compile(r"T_")),
    ("a data object rather than a function", re.compile(r"E$")),
    ("a 128-bit integer", re.compile(r"x[no]")),
    ("a long double", re.compile(r"e$")),
    ("wchar_t", re.compile(r"w")),
]


def run(cmd, work=None, data=None):
    out = subprocess.run(cmd, capture_output=True, shell=False, timeout=600, cwd=work, input=data)
    text = out.stdout.decode("utf-8", "replace") + out.stderr.decode("utf-8", "replace")
    if out.returncode:
        raise SystemExit("%s failed: %s" % (cmd[0], text[-800:]))
    return text


def tool(name):
    found = shutil.which(name)
    if not found:
        raise SystemExit("%s is not on PATH, so nothing here can be credited" % name)
    return found


def build():
    """clang's own object file, or the committed one if it is already here."""
    keep = os.path.join(FIX, "cxx.o")
    if os.path.exists(keep) and "--refresh" not in sys.argv:
        return open(keep, "rb").read()
    if not shutil.which("clang++"):
        raise SystemExit("clang++ is not on PATH and %s is missing" % keep)
    work = tempfile.mkdtemp(prefix="demangle-")
    try:
        source = os.path.join(work, "cxx.cpp")
        with open(source, "w", newline="\n") as handle:
            handle.write(SOURCE)
        run([
            "clang++", "-target", TARGET, "-nostdlibinc", "-ffreestanding",
            "-fno-exceptions", "-fno-rtti", "-c", source, "-o", os.path.join(work, "cxx.o"),
        ], work=work)
        with open(os.path.join(work, "cxx.o"), "rb") as handle:
            return handle.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def symbols(raw):
    """The object's own symbol list, as `llvm-readobj --symbols` prints it, in table order.

    Only names starting with `_Z` are kept: that prefix is the whole of how an Itanium mangled name
    announces itself, and everything else in the table - the compilation-unit name, the section
    symbols, a stray C identifier - is nothing for a demangler to answer.
    """
    with tempfile.TemporaryDirectory(prefix="demangle-ro-") as work:
        path = os.path.join(work, "cxx.o")
        with open(path, "wb") as handle:
            handle.write(raw)
        text = run([tool("llvm-readobj"), "--symbols", path])
    found = []
    for line in text.splitlines():
        match = re.match(r"\s+Name: (\S+) \(", line)
        if match and match.group(1).startswith("_Z"):
            found.append(match.group(1))
    return found


def demangle(names, exe):
    """One answer per name, from one witness, with its own line endings taken off."""
    body = ("\n".join(names) + "\n").encode("utf-8")
    text = run([exe], data=body).replace("\r\n", "\n").replace("\r", "\n")
    out = [line.rstrip("\n") for line in text.split("\n") if line != ""]
    if len(out) != len(names):
        raise SystemExit("%s answered %d lines for %d names" % (exe, len(out), len(names)))
    return out


def check(names, gnu, llvm):
    """The shapes have to be present, or the claim below would have quietly shrunk."""
    missing = [label for label, pattern in SHAPES if not any(pattern.search(one) for one in names)]
    if missing:
        raise SystemExit("the fixture no longer holds: %s" % ", ".join(missing))
    if len(names) < 12:
        raise SystemExit("only %d mangled names came out of the object" % len(names))
    agreed, diverged = {}, {}
    for name, first, second in zip(names, gnu, llvm):
        if first == second:
            agreed[name] = first
        else:
            diverged[name] = (first, second)
    if not agreed:
        raise SystemExit("the two demanglers agree on nothing here")
    if gnu == list(names):
        raise SystemExit("no name demangled at all")
    return agreed, diverged


def rows(names, agreed, diverged):
    """The report the reader has to produce: one line per mangled name, in table order.

    A name the two witnesses disagree on is answered with `-` and the reader's own reason for stopping,
    because what the *reader* knows is only that no two-witness spelling exists for it. Which two
    spellings it was is kept separately, in `diverged`, and the host test reads that map.
    """
    out = ["demangle\tmangled\t%d\tdemangled\t%d\trefused\t%d\twitnesses\ttwo"
           % (len(names), len(agreed), len(diverged))]
    for index, name in enumerate(names):
        if name in agreed:
            out.append("sym\t%d\tin\t%s\tout\t%s" % (index, name, agreed[name]))
        else:
            out.append("sym\t%d\tin\t%s\tout\t-\twhy\tnot in the two-witness subset" % (index, name))
    return out


def main():
    raw = build()
    if raw[:4] != b"\x7fELF":
        raise SystemExit("clang did not write an ELF object")
    names = symbols(raw)
    agreed, diverged = check(names, demangle(names, tool("c++filt")),
                             demangle(names, tool("llvm-cxxfilt")))
    report = {
        "target": TARGET,
        "bytes": len(raw),
        "names": names,
        "agreed": {one: agreed[one] for one in names if one in agreed},
        "diverged": {one: {"c++filt": diverged[one][0], "llvm-cxxfilt": diverged[one][1]}
                     for one in names if one in diverged},
        "rows": rows(names, agreed, diverged),
    }
    with open(os.path.join(FIX, "cxx.o"), "wb") as handle:
        handle.write(raw)
    with open(os.path.join(FIX, "demangle.probe.json"), "w", newline="\n") as handle:
        json.dump(report, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    print("%d names, %d agreed, %d diverged, %d B of object"
          % (len(names), len(agreed), len(diverged), len(raw)))
    for one in sorted(diverged):
        print("  diverged %s: c++filt %r vs llvm %r" % (one, diverged[one][0], diverged[one][1]))
    for line in report["rows"][1:4]:
        print("  " + line.replace("\t", " "))


if __name__ == "__main__":
    main()
