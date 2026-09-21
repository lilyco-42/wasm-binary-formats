"""Produce and check the C++ name fixtures - what two demanglers have to agree on.

A listing where every `_ZN...` is still the compiler's own handwriting is not much use for reading a
binary, so the analysis module demangles the Itanium names it meets in a symbol table. What it prints is
credited to two demanglers that are not this one: binutils' `c++filt` and LLVM's `llvm-cxxfilt`, each run
over the exact name list read out of an object's own symbol table with `llvm-readobj --symbols`. Where the
two agree on a spelling *and that spelling is not simply the name echoed back*, the string is the thing
the Rust reader has to reproduce.

The echoed case is its own bucket on purpose. A demangler that does not know a construct prints the name
unchanged, so two of them can "agree" by both giving up - and a reader that then claimed to have decoded
something would be quoting a failure. Every name in `unequal` was spelled differently by the two (so no
spelling is a fact about those bytes), and every name in `not demangled` was left as it came by both.

Two objects are compiled, because the constructs are not all comfortable in one source: `cxx.o` holds
namespaces, members, cv-qualifiers, substitutions, an array under a reference and a template, and `ops.o`
holds the operator names - `pl`, `ix`, `cl`, `cv l`, the compound assignments - which is where a demangler
is most likely to be quoting a table nobody checked.

    temp/venv/Scripts/python.exe scripts/make-demangle-fixtures.py [--refresh]

The committed objects are reused unless `--refresh` is given, because clang stamps its version into a
comment section and a rebuild would move bytes the probe has nothing to say about.
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

NAMES = """\
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
int one_ref(int& a, int& b) { return a; }

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

OPERATORS = """\
// Declarations in the class and definitions outside it, because a body written in the class is inline
// and clang emits an inline member only when something refers to it - which would leave the operator
// codes unrepresented in the symbol table rather than present. Every code the reader's table will carry
// has to appear here, because a code the two demanglers were never asked about is a code nobody checked.

struct Vec {
  int x;
  Vec operator+(const Vec& other) const;
  Vec operator-(const Vec& other) const;
  Vec operator*(const Vec& other) const;
  Vec operator/(const Vec& other) const;
  Vec operator%(const Vec& other) const;
  bool operator==(const Vec& other) const;
  bool operator!=(const Vec& other) const;
  bool operator<(const Vec& other) const;
  bool operator>(const Vec& other) const;
  bool operator<=(const Vec& other) const;
  bool operator>=(const Vec& other) const;
  bool operator&&(const Vec& other) const;
  bool operator||(const Vec& other) const;
  Vec operator-() const;
  Vec operator+() const;
  Vec operator~() const;
  Vec& operator*();
  const int* operator&() const;
  bool operator!() const;
  Vec& operator=(const Vec& other);
  Vec& operator++();
  Vec operator++(int);
  Vec& operator--();
  Vec operator--(int);
  Vec& operator+=(const Vec& other);
  Vec& operator-=(const Vec& other);
  Vec& operator*=(const Vec& other);
  Vec& operator/=(const Vec& other);
  Vec& operator%=(const Vec& other);
  Vec& operator&=(const Vec& other);
  Vec& operator^=(const Vec& other);
  Vec& operator|=(const Vec& other);
  Vec operator<<(const Vec& other) const;
  Vec operator>>(const Vec& other) const;
  int operator[](int at) const;
  int operator()(int at) const;
  const int* operator->() const;
  Vec operator,(const Vec& other) const;
  operator int() const;
  void* operator new(unsigned long n);
  void operator delete(void* p) noexcept;
  void operator delete[](void* p) noexcept;
};

Vec Vec::operator+(const Vec& other) const { return other; }
Vec Vec::operator-(const Vec& other) const { return other; }
Vec Vec::operator*(const Vec& other) const { return other; }
Vec Vec::operator/(const Vec& other) const { return other; }
Vec Vec::operator%(const Vec& other) const { return other; }
bool Vec::operator==(const Vec& other) const { return x == other.x; }
bool Vec::operator!=(const Vec& other) const { return x != other.x; }
bool Vec::operator<(const Vec& other) const { return x < other.x; }
bool Vec::operator>(const Vec& other) const { return x > other.x; }
bool Vec::operator<=(const Vec& other) const { return x <= other.x; }
bool Vec::operator>=(const Vec& other) const { return x >= other.x; }
bool Vec::operator&&(const Vec& other) const { return x && other.x; }
bool Vec::operator||(const Vec& other) const { return x || other.x; }
Vec Vec::operator-() const { return *this; }
Vec Vec::operator+() const { return *this; }
Vec Vec::operator~() const { Vec copy = *this; return copy; }
Vec& Vec::operator*() { return *this; }
const int* Vec::operator&() const { return &x; }
bool Vec::operator!() const { return x == 0; }
Vec& Vec::operator=(const Vec& other) { x = other.x; return *this; }
Vec& Vec::operator++() { ++x; return *this; }
Vec Vec::operator++(int) { Vec copy = *this; ++x; return copy; }
Vec& Vec::operator--() { --x; return *this; }
Vec Vec::operator--(int) { Vec copy = *this; --x; return copy; }
Vec& Vec::operator+=(const Vec& other) { x += other.x; return *this; }
Vec& Vec::operator-=(const Vec& other) { x -= other.x; return *this; }
Vec& Vec::operator*=(const Vec& other) { x *= other.x; return *this; }
Vec& Vec::operator/=(const Vec& other) { x /= other.x; return *this; }
Vec& Vec::operator%=(const Vec& other) { x %= other.x; return *this; }
Vec& Vec::operator&=(const Vec& other) { x &= other.x; return *this; }
Vec& Vec::operator^=(const Vec& other) { x ^= other.x; return *this; }
Vec& Vec::operator|=(const Vec& other) { x |= other.x; return *this; }
Vec Vec::operator<<(const Vec& other) const { return other; }
Vec Vec::operator>>(const Vec& other) const { return other; }
int Vec::operator[](int at) const { return x + at; }
int Vec::operator()(int at) const { return x + at; }
const int* Vec::operator->() const { return &x; }
Vec Vec::operator,(const Vec& other) const { return other; }
Vec::operator int() const { return x; }
void* Vec::operator new(unsigned long) { return 0; }
void Vec::operator delete(void*) {}
void Vec::operator delete[](void*) {}

void take_int(int&& moved, const double& held) {}
void bits(unsigned char c, short s, unsigned short u, unsigned long l) {}

// Free operators, because a stream-style `operator<<` is a top-level name with the left operand as its
// first type, which is a different shape from the member form above.
Vec operator-(const Vec& a, const Vec& b) { return a; }
Vec operator-(const Vec& a) { return a; }
bool operator!=(const Vec& a, const Vec& b) { return false; }
int& shift_in(int& sink, const Vec& src) { return sink; }
"""

# Each entry is (what the probe has to see, a regex over the mangled name, the object that owes it).
# These are the shapes the Rust reader implements, so an object that stopped containing one is a
# narrowing of the claim - which is why the operator codes are pinned to `ops.o` rather than asked of
# both files.
SHAPES = [
    ("a nested name", re.compile(r"^_ZN.*E"), "both"),
    ("a constructor written C1 or C2", re.compile(r"C[12]E"), "cxx.o"),
    ("a destructor", re.compile(r"D[012]E"), "cxx.o"),
    ("a const member function", re.compile(r"^_ZNK"), "both"),
    ("a self substitution", re.compile(r"S_"), "both"),
    ("a nested substitution", re.compile(r"NS_\w+E"), "cxx.o"),
    ("a reference parameter", re.compile(r"R[A-Za-z]"), "both"),
    ("a pointer parameter", re.compile(r"P[A-Za-z]"), "cxx.o"),
    ("an array under a reference", re.compile(r"RA\d+_"), "cxx.o"),
    ("a template argument list", re.compile(r"^_Z\w+I\w+E"), "cxx.o"),
    ("a template parameter as the return type", re.compile(r"T_"), "cxx.o"),
    ("a data object rather than a function", re.compile(r"E$"), "cxx.o"),
    ("a 128-bit integer", re.compile(r"x[no]"), "cxx.o"),
    ("a long double", re.compile(r"e$"), "cxx.o"),
    ("an rvalue reference", re.compile(r"O[a-z]"), "ops.o"),
    ("an addition operator", re.compile(r"pl"), "ops.o"),
    ("a subscript operator", re.compile(r"ix"), "ops.o"),
    ("a call operator", re.compile(r"cl"), "ops.o"),
    ("a conversion operator", re.compile(r"cv"), "ops.o"),
    ("a pre-increment operator", re.compile(r"pp"), "ops.o"),
    ("a compound-assignment operator", re.compile(r"pL"), "ops.o"),
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


def compile_one(source, keep):
    """clang's object file, or the committed one if it is already here.

    A freshly built object is written back into the fixture tree: a probe that describes bytes which were
    never saved leaves the committed file and its witness disagreeing, and the tests read the file, so
    the disagreement would surface as a reader that cannot reproduce its own probe.
    """
    path = os.path.join(FIX, keep)
    if os.path.exists(path) and "--refresh" not in sys.argv:
        return open(path, "rb").read()
    if not shutil.which("clang++"):
        raise SystemExit("clang++ is not on PATH and %s is missing" % path)
    work = tempfile.mkdtemp(prefix="demangle-")
    try:
        name = os.path.join(work, "in.cpp")
        with open(name, "w", newline="\n") as handle:
            handle.write(source)
        run([
            "clang++", "-target", TARGET, "-nostdlibinc", "-ffreestanding",
            "-fno-exceptions", "-fno-rtti", "-c", name, "-o", os.path.join(work, "out.o"),
        ], work=work)
        with open(os.path.join(work, "out.o"), "rb") as handle:
            raw = handle.read()
    finally:
        shutil.rmtree(work, ignore_errors=True)
    with open(path, "wb") as handle:
        handle.write(raw)
    return raw


def symbols(raw, label):
    """The object's own `_Z` symbol list, in table order, as `llvm-readobj --symbols` prints it.

    Only the `_Z` prefix counts: that is the whole of how an Itanium mangled name announces itself, and
    everything else in the table - the compilation-unit name, the section symbols, a C identifier - is
    nothing for a C++ demangler to answer.
    """
    with tempfile.TemporaryDirectory(prefix="demangle-ro-") as work:
        path = os.path.join(work, label)
        with open(path, "wb") as handle:
            handle.write(raw)
        text = run([tool("llvm-readobj"), "--symbols", path])
    return [m.group(1) for m in re.finditer(r"Name: (\S+) \(", text)
            if m.group(1).startswith("_Z")]


def demangle(names, exe):
    """One answer per name from one witness, with its own line endings taken off."""
    body = ("\n".join(names) + "\n").encode("utf-8")
    text = run([exe], data=body).replace("\r\n", "\n").replace("\r", "\n")
    out = [line.rstrip("\n") for line in text.split("\n") if line != ""]
    if len(out) != len(names):
        raise SystemExit("%s answered %d lines for %d names" % (exe, len(out), len(names)))
    return out


def sort_names(names, gnu, llvm):
    """Agreed, unequal, and both-gave-up - three answers, only one of which is a claim."""
    agreed, unequal, untouched = {}, {}, []
    for name, first, second in zip(names, gnu, llvm):
        if first == second and first != name:
            agreed[name] = first
        elif first == second:
            untouched.append(name)
        else:
            unequal[name] = (first, second)
    return agreed, unequal, untouched


def check(label, names, agreed, unequal, untouched):
    missing = [text for text, pattern, owner in SHAPES
               if owner in (label, "both")
               and not any(pattern.search(each) for each in names)]
    if missing:
        raise SystemExit("%s no longer holds: %s" % (label, ", ".join(missing)))
    if len(names) < 12:
        raise SystemExit("%s gave only %d mangled names" % (label, len(names)))
    if not agreed:
        raise SystemExit("%s: the two demanglers agree on nothing" % label)
    if len(untouched) > len(names) // 2:
        raise SystemExit("%s: most names demangled to nothing, so the witnesses are not reading" % label)


def rows(names, agreed, unequal, untouched):
    """The report the reader has to produce: one line per name, in the object's own table order.

    Every refusal carries the *same* reason, because that is all the reader can know: it has no access to
    a second demangler at runtime, so it can say only that no two-witness spelling was found. Why each
    name has none - the two spellings differed, or neither witness read the name at all - is kept in the
    probe's `unequal` and `untouched` fields for the tests to check separately.
    """
    out = ["demangle\tmangled\t%d\tdemangled\t%d\trefused\t%d\twitnesses\ttwo"
           % (len(names), len(agreed), len(names) - len(agreed))]
    for index, name in enumerate(names):
        if name in agreed:
            out.append("sym\t%d\tin\t%s\tout\t%s" % (index, name, agreed[name]))
        else:
            out.append("sym\t%d\tin\t%s\tout\t-\twhy\tnot in the two-witness subset"
                       % (index, name))
    return out


def probe(source, keep):
    raw = compile_one(source, keep)
    if raw[:4] != b"\x7fELF":
        raise SystemExit("clang did not write an ELF object for %s" % keep)
    names = symbols(raw, keep)
    agreed, unequal, untouched = sort_names(names, demangle(names, tool("c++filt")),
                                           demangle(names, tool("llvm-cxxfilt")))
    check(keep, names, agreed, unequal, untouched)
    return {
        "bytes": len(raw),
        "names": names,
        "agreed": {each: agreed[each] for each in names if each in agreed},
        "unequal": {each: {"c++filt": unequal[each][0], "llvm-cxxfilt": unequal[each][1]}
                    for each in names if each in unequal},
        "untouched": [each for each in names if each in untouched],
        "rows": rows(names, agreed, unequal, untouched),
    }


def main():
    report = {
        "target": TARGET,
        "cxx.o": probe(NAMES, "cxx.o"),
        "ops.o": probe(OPERATORS, "ops.o"),
    }
    with open(os.path.join(FIX, "demangle.probe.json"), "w", newline="\n") as handle:
        json.dump(report, handle, indent=1, ensure_ascii=False)
        handle.write("\n")
    for keep in ("cxx.o", "ops.o"):
        part = report[keep]
        print("%s: %d names, %d agreed, %d differ, %d unread, %d B"
              % (keep, len(part["names"]), len(part["agreed"]), len(part["unequal"]),
                 len(part["untouched"]), part["bytes"]))
        for name in part["unequal"]:
            print("   differ %s: %r vs %r" % (name, part["unequal"][name]["c++filt"],
                                              part["unequal"][name]["llvm-cxxfilt"]))
        for name in part["untouched"]:
            print("   unread  %s" % name)


if __name__ == "__main__":
    main()
