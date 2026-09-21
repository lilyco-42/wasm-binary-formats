//! A demangler for the subset of the Itanium mangling this lab has two witnesses for.
//!
//! Two programs that are not this one - binutils' `c++filt` and LLVM's `llvm-cxxfilt` - were run over
//! the names clang wrote into `test/fixtures/cxx.o`, and `scripts/make-demangle-fixtures.py` keeps only
//! the ones where they answer with the same string. So every spelling below is a spelling two
//! independent demanglers chose, and anything outside that set is refused rather than approximated: an
//! unknown builtin code, an operator name, a `Dn` (the two witnesses spell `nullptr` differently), a
//! vendor extension. A name this file refuses is reported as refused, which is a true thing to say
//! about bytes; a name it guesses at is not.
//!
//! Two facts the fixture demonstrates and so the code does not hide:
//!
//! - A non-template function's return type is not in its mangled name at all. `retfn` returns a
//!   function pointer and both witnesses print just `retfn(int)`, because what follows the name is the
//!   parameter list. A template's return type *is* there, because `T_` has to be resolved through the
//!   argument list.
//! - `C1`/`C2` and `D1`/`D2` are the complete-object and base-object variants of a constructor and a
//!   destructor, and they demangle to the same string. `cxx.o` carries both, so a listing that showed
//!   only the demangled form could not tell the two symbols apart - the raw name is kept in the row for
//!   exactly that reason.

/// A parsed type, kept as a tree because `int (&) [5]` puts the declarator *inside* the array's
/// brackets: a flat string cannot say that. A substitution or a template parameter is resolved where it
/// is read, so no variant carries one - an unresolved `S_` would otherwise print as one.
enum Ty {
    Builtin(&'static str),
    /// A name already rendered, from the substitution table or a nested-name component.
    Named(String),
    Pointer(Box<Ty>),
    Reference(Box<Ty>),
    Const(Box<Ty>),
    Volatile(Box<Ty>),
    Array(u64, Box<Ty>),
}

impl Ty {
    /// A type as the witnesses write it: `char const&`, `long const**`, `int (&) [5]`.
    fn text(&self) -> String {
        self.spell(false)
    }

    fn spell(&self, inside: bool) -> String {
        match self {
            Ty::Builtin(name) => (*name).to_owned(),
            Ty::Named(name) => name.clone(),
            Ty::Const(inner) => format!("{} const", inner.spell(inside)),
            Ty::Volatile(inner) => format!("{} volatile", inner.spell(inside)),
            Ty::Pointer(inner) => match &**inner {
                Ty::Array(len, element) => format!("{} (*) [{}]", element.spell(true), len),
                other => format!("{}*", other.spell(true)),
            },
            Ty::Reference(inner) => match &**inner {
                Ty::Array(len, element) => format!("{} (&) [{}]", element.spell(true), len),
                other => format!("{}&", other.spell(true)),
            },
            // An array is its element type and its length; the brackets a declarator would push inside
            // them are added by the pointer and reference arms above, which is where `int (&) [5]`
            // comes from.
            Ty::Array(len, element) => format!("{} [{}]", element.spell(inside), len),
        }
    }

    /// True when this tree holds nothing that still has to be resolved. Every node is resolved as it is
    /// read, so this is the walk's own backstop against printing an `S_`.
    fn settled(&self) -> bool {
        match self {
            Ty::Const(inner) | Ty::Volatile(inner) | Ty::Pointer(inner) | Ty::Reference(inner) => {
                inner.settled()
            }
            Ty::Array(_, element) => element.settled(),
            Ty::Builtin(_) | Ty::Named(_) => true,
        }
    }
}

/// The builtin codes the fixture's names use. Every other code is refused: `z`, `u`, `Dn`, `Di`, `Ds`
/// and the rest have no two-witness spelling held here, and `t`/`m` would be recalled rather than
/// checked.
fn builtin(code: u8) -> Option<&'static str> {
    Some(match code {
        b'v' => "void",
        b'b' => "bool",
        b'c' => "char",
        b'a' => "signed char",
        b'h' => "unsigned char",
        b's' => "short",
        b'i' => "int",
        b'j' => "unsigned int",
        b'l' => "long",
        b'x' => "long long",
        b'y' => "unsigned long long",
        b'n' => "__int128",
        b'o' => "unsigned __int128",
        b'e' => "long double",
        b'f' => "float",
        b'd' => "double",
        b'w' => "wchar_t",
        _ => return None,
    })
}

struct Parse<'a> {
    raw: &'a [u8],
    at: usize,
    /// What `S_`, `S0_`, ... stand for, in the order the parser recorded them.
    subs: Vec<String>,
    /// The template arguments in scope, for `T_` and friends.
    args: Vec<String>,
}

impl<'a> Parse<'a> {
    fn peek(&self) -> Option<u8> {
        self.raw.get(self.at).copied()
    }

    fn starts(&self, with: &[u8]) -> bool {
        self.raw.get(self.at..self.at + with.len()) == Some(with)
    }

    fn eat(&mut self, len: usize) {
        self.at += len;
    }

    /// `<source-name>`: a decimal length and that many bytes of identifier. The length has to be a
    /// positive number without a leading zero, and the identifier has to look like one - clang writes
    /// `$` inside local names, and those are outside this subset, so a `$` stops the walk and the name
    /// is refused.
    fn source_name(&mut self) -> Option<String> {
        let start = self.at;
        let mut digits = 0usize;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            digits += 1;
            self.at += 1;
        }
        if digits == 0 || (digits > 1 && *self.raw.get(start)? == b'0') {
            return None;
        }
        let length = std::str::from_utf8(self.raw.get(start..self.at)?)
            .ok()?
            .parse::<usize>()
            .ok()?;
        let body = self.raw.get(self.at..self.at.checked_add(length)?)?;
        if !body
            .iter()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
        {
            return None;
        }
        // A number cannot start an identifier, which is how `2ns` is told apart from a length that
        // would have been the start of something else.
        if matches!(body[0], b'0'..=b'9') {
            return None;
        }
        self.at = self.at.checked_add(length)?;
        Some(String::from_utf8(body.to_vec()).ok()?)
    }

    /// `A <number> _`: an array bound. The `A` is part of the spelling, so the walk steps over it
    /// here and the digits have to be followed by the `_` that ends them.
    fn array_bound(&mut self) -> Option<u64> {
        self.eat(1);
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        if start == self.at {
            return None;
        }
        let value = std::str::from_utf8(self.raw.get(start..self.at)?)
            .ok()?
            .parse::<u64>()
            .ok()?;
        if self.peek() != Some(b'_') {
            return None;
        }
        self.eat(1);
        Some(value)
    }

    fn substitution(&mut self) -> Option<usize> {
        if self.starts(b"S_") {
            self.eat(2);
            return Some(0);
        }
        if !self.starts(b"S") {
            return None;
        }
        let start = self.at + 1;
        let mut stop = start;
        while matches!(self.raw.get(stop), Some(b'0'..=b'9')) {
            stop += 1;
        }
        if stop == start || self.raw.get(stop) != Some(&b'_') {
            return None;
        }
        let index = std::str::from_utf8(self.raw.get(start..stop)?)
            .ok()?
            .parse::<usize>()
            .ok()?
            .checked_add(1)?;
        self.at = stop.checked_add(1)?;
        Some(index)
    }

    fn template_param(&mut self) -> Option<usize> {
        if self.starts(b"T_") {
            self.eat(2);
            return Some(0);
        }
        if !self.starts(b"T") {
            return None;
        }
        let start = self.at + 1;
        let mut stop = start;
        while matches!(self.raw.get(stop), Some(b'0'..=b'9')) {
            stop += 1;
        }
        if stop == start || self.raw.get(stop) != Some(&b'_') {
            return None;
        }
        let index = std::str::from_utf8(self.raw.get(start..stop)?)
            .ok()?
            .parse::<usize>()
            .ok()?
            .checked_add(1)?;
        self.at = stop.checked_add(1)?;
        Some(index)
    }

    /// A type, as far as this subset reaches. `Option::None` means "not in the subset", which the
    /// caller turns into a refused name rather than a partial answer.
    fn ty(&mut self) -> Option<Ty> {
        let head = self.peek()?;
        match head {
            b'P' | b'R' | b'K' | b'V' => {
                self.eat(1);
                let inner = self.ty()?;
                Some(match head {
                    b'P' => Ty::Pointer(Box::new(inner)),
                    b'R' => Ty::Reference(Box::new(inner)),
                    // `K` is const and `V` volatile in this grammar, which is not the C spelling anyone
                    // would guess from the letters.
                    b'K' => Ty::Const(Box::new(inner)),
                    _ => Ty::Volatile(Box::new(inner)),
                })
            }
            b'A' => {
                let length = self.array_bound()?;
                let element = self.ty()?;
                Some(Ty::Array(length, Box::new(element)))
            }
            b'S' => {
                let index = self.substitution()?;
                let text = self.subs.get(index)?.clone();
                self.subs.push(text.clone());
                Some(Ty::Named(text))
            }
            b'T' => {
                let index = self.template_param()?;
                let text = self.args.get(index)?.clone();
                self.subs.push(text.clone());
                Some(Ty::Named(text))
            }
            b'N' => {
                let (name, _) = self.nested_name()?;
                Some(Ty::Named(name))
            }
            b'I' => {
                self.eat(1);
                let name = self.source_name()?;
                let args = self.template_args()?;
                let text = format!("{}<{}>", name, args.join(", "));
                self.subs.push(text.clone());
                Some(Ty::Named(text))
            }
            byte => match builtin(byte) {
                Some(text) => {
                    self.eat(1);
                    Some(Ty::Builtin(text))
                }
                None => None,
            },
        }
    }

    /// `I <args> E`, returning each argument's spelling. Only type arguments are in this subset.
    fn template_args(&mut self) -> Option<Vec<String>> {
        let mut out = Vec::new();
        loop {
            if self.peek()? == b'E' {
                self.eat(1);
                return Some(out);
            }
            let arg = self.ty()?;
            if !arg.settled() {
                return None;
            }
            let text = arg.text();
            self.subs.push(text.clone());
            out.push(text);
        }
    }

    /// `<name>`: a top-level one, with a template argument list if `I..E` follows it. The arguments are
    /// kept as the list in scope, because that is what a later `T_` in the return type or a parameter
    /// stands for.
    fn simple_name(&mut self) -> Option<String> {
        let mut text = self.source_name()?;
        if self.starts(b"I") {
            self.eat(1);
            let args = self.template_args()?;
            self.args = args.clone();
            text = format!("{}<{}>", text, args.join(", "));
        }
        Some(text)
    }

    /// The nested-name walk itself: `N` components `E`, with `K` allowed straight after the `N`.
    ///
    /// Returns the rendered name and whether that `K` was read, which the caller writes after the
    /// parameter list as `const`.
    fn nested_name(&mut self) -> Option<(String, bool)> {
        self.eat(1);
        let qualified = self.peek() == Some(b'K');
        if qualified {
            self.eat(1);
        }
        let mut parts: Vec<String> = Vec::new();
        loop {
            match self.peek()? {
                b'E' => {
                    self.eat(1);
                    if parts.is_empty() {
                        return None;
                    }
                    // The first component and the whole name are both substitutions, which is what
                    // makes `NS_3BoxE` mean `ns::Box` after `2ns` has been seen once.
                    let joined = parts.join("::");
                    if parts.len() > 1 {
                        self.subs.push(parts[0].clone());
                    }
                    self.subs.push(joined.clone());
                    return Some((joined, qualified));
                }
                b'C' | b'D' => {
                    let kind = self.peek()?;
                    self.eat(1);
                    if !matches!(self.peek(), Some(b'0'..=b'2')) {
                        return None;
                    }
                    self.eat(1);
                    // A constructor or destructor borrows the class name one level out and demangles
                    // to it, so `C1` and `C2` of the same class print the same string.
                    let owner = parts.last()?.clone();
                    let leaf = owner.rsplit("::").next().unwrap_or(&owner);
                    parts.push(if kind == b'D' {
                        format!("~{}", leaf)
                    } else {
                        leaf.to_owned()
                    });
                }
                b'S' => {
                    let index = self.substitution()?;
                    parts.push(self.subs.get(index)?.clone());
                }
                b'T' => {
                    let index = self.template_param()?;
                    parts.push(self.args.get(index)?.clone());
                }
                _ => {
                    let mut one = self.source_name()?;
                    if self.starts(b"I") {
                        self.eat(1);
                        let args = self.template_args()?;
                        one = format!("{}<{}>", one, args.join(", "));
                    }
                    parts.push(one);
                }
            }
        }
    }
}

/// The demangled spelling of an Itanium name, or `None` when the name is outside the subset two
/// witnesses have pinned down.
pub fn demangle(name: &str) -> Option<String> {
    let raw = name.as_bytes();
    if raw.len() < 3 || !raw.starts_with(b"_Z") {
        return None;
    }
    let mut walk = Parse {
        raw,
        at: 2,
        subs: Vec::new(),
        args: Vec::new(),
    };
    // `_ZN...` is a nested name; `_Z<name><types>` is a top-level one. Whether a return type sits in
    // front of the parameter list is decided by the name being a template-id - a non-template
    // function's return type is not in its mangled name at all, which is why both witnesses print
    // `retfn(int)` for a function that returns a function pointer.
    let (rendered, qualified) = match walk.peek()? {
        b'N' => walk.nested_name()?,
        _ => (walk.simple_name()?, false),
    };
    let templated = rendered.contains('<');
    if walk.peek().is_none() {
        // A data object: the name is the whole answer.
        return Some(rendered);
    }
    let mut return_ty: Option<String> = None;
    if templated {
        let head = walk.ty()?;
        if !head.settled() {
            return None;
        }
        return_ty = Some(head.text());
    }
    let mut params: Vec<String> = Vec::new();
    if walk.peek()? == b'v' && walk.raw.len() == walk.at + 1 {
        walk.eat(1);
    } else {
        while walk.peek().is_some() {
            let one = walk.ty()?;
            if !one.settled() {
                return None;
            }
            params.push(one.text());
        }
    }
    let mut out = String::new();
    if let Some(text) = return_ty {
        out.push_str(&text);
        out.push(' ');
    }
    out.push_str(&rendered);
    out.push('(');
    out.push_str(&params.join(", "));
    out.push(')');
    if qualified {
        out.push_str(" const");
    }
    Some(out)
}
