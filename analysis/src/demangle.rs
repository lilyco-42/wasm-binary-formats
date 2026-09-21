//! A demangler for the subset of the Itanium mangling this lab has two witnesses for.
//!
//! Two programs that are not this one - binutils' `c++filt` and LLVM's `llvm-cxxfilt` - were run over
//! the names clang wrote into `test/fixtures/cxx.o` and `test/fixtures/ops.o`, and
//! `scripts/make-demangle-fixtures.py` keeps only the names where they answer with the same string. So
//! every spelling below is one two independent demanglers chose, and anything outside that set is
//! refused rather than approximated: a builtin code nobody showed them, a `Dn` (they spell `nullptr`
//! differently), a template argument that is a value rather than a type, an allocation form the fixture
//! does not hold.
//!
//! Three facts the fixtures demonstrate and so the code does not hide:
//!
//! - A non-template function's return type is not in its mangled name at all. `retfn` returns a
//!   function pointer and both witnesses print just `retfn(int)`, because what follows the name is the
//!   parameter list. A template's return type *is* there, because `T_` has to be resolved through the
//!   argument list.
//! - `C1`/`C2` and `D1`/`D2` are the complete-object and base-object variants of a constructor and a
//!   destructor, and they demangle to the same string. `cxx.o` carries both, so a listing that showed
//!   only the demangled form could not tell the two symbols apart - the raw name stays in the row for
//!   exactly that reason.
//! - What a substitution stands for is decided by what was *completed*, not by what was read first:
//!   `one_ref(int&, int&)` arrives as `_Z7one_refRiS_`, where `S_` is the whole reference and not the
//!   `int` inside it, and `operator-(Vec const&, Vec const&)` arrives as `_ZmiRK3VecS1_` - three
//!   candidates deep. A function's own name is never one of those candidates, which is the difference
//!   between the two: `_Zmi` pushes nothing before its parameter list does.

/// A parsed type, kept as a tree because `int (&) [5]` puts the declarator *inside* the array's
/// brackets: a flat string cannot say that. A substitution or a template parameter is resolved where it
/// is read, so no variant carries one - an unresolved `S_` would otherwise print as one.
enum Ty {
    Builtin(&'static str),
    /// A name already rendered, from the substitution table or a nested-name component.
    Named(String),
    Pointer(Box<Ty>),
    Reference(Box<Ty>),
    RValue(Box<Ty>),
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
            Ty::RValue(inner) => format!("{}&&", inner.spell(true)),
            // An array is its element type and its length; the brackets a declarator would push inside
            // them are added by the pointer and reference arms above, which is where `int (&) [5]`
            // comes from.
            Ty::Array(len, element) => format!("{} [{}]", element.spell(inside), len),
        }
    }
}

/// The builtin codes the two witnesses were both shown, and no others. `Dn` is excluded on purpose: one
/// writes `decltype(nullptr)` and the other `std::nullptr_t` for those two bytes, so neither spelling
/// is a fact about them.
fn builtin(code: u8) -> Option<&'static str> {
    Some(match code {
        b'v' => "void",
        b'b' => "bool",
        b'c' => "char",
        b'a' => "signed char",
        b'h' => "unsigned char",
        b's' => "short",
        b't' => "unsigned short",
        b'i' => "int",
        b'j' => "unsigned int",
        b'l' => "long",
        b'm' => "unsigned long",
        b'x' => "long long",
        b'y' => "unsigned long long",
        b'n' => "__int128",
        b'o' => "unsigned __int128",
        b'f' => "float",
        b'd' => "double",
        b'e' => "long double",
        b'w' => "wchar_t",
        _ => return None,
    })
}

/// `<operator-name>`, spelled as the witnesses spelled it - including the space in `operator new` and
/// the brackets of `operator delete[]`, and the fact that `pl` and `ps` are both a plus, one binary and
/// one unary. `cv` is absent because a conversion names a *type* after the code, which is handled where
/// the walk can keep parsing. Codes outside this table end the walk.
fn operator_code(code: &[u8]) -> Option<&'static str> {
    Some(match code {
        b"pl" => "operator+",
        b"mi" => "operator-",
        b"ml" => "operator*",
        b"dv" => "operator/",
        b"rm" => "operator%",
        b"ps" => "operator+",
        b"ng" => "operator-",
        b"ad" => "operator&",
        b"de" => "operator*",
        b"co" => "operator~",
        b"nt" => "operator!",
        b"cl" => "operator()",
        b"ix" => "operator[]",
        b"pt" => "operator->",
        b"aa" => "operator&&",
        b"oo" => "operator||",
        b"eq" => "operator==",
        b"ne" => "operator!=",
        b"lt" => "operator<",
        b"gt" => "operator>",
        b"le" => "operator<=",
        b"ge" => "operator>=",
        b"aS" => "operator=",
        b"pL" => "operator+=",
        b"mI" => "operator-=",
        b"mL" => "operator*=",
        b"dV" => "operator/=",
        b"rM" => "operator%=",
        b"aN" => "operator&=",
        b"eO" => "operator^=",
        b"oR" => "operator|=",
        b"ls" => "operator<<",
        b"rs" => "operator>>",
        b"pp" => "operator++",
        b"mm" => "operator--",
        b"cm" => "operator,",
        b"nw" => "operator new",
        // `dl` is the scalar form and `da` the array one, which is the opposite of what the letters
        // suggest and is read off the probe rather than recalled.
        b"dl" => "operator delete",
        b"da" => "operator delete[]",
        _ => return None,
    })
}

struct Parse<'a> {
    raw: &'a [u8],
    at: usize,
    /// What `S_`, `S0_`, ... stand for, in the order the walk completed them.
    subs: Vec<String>,
    /// The template arguments in scope, for `T_` and its numbered brothers.
    args: Vec<String>,
    /// Set when a name carried `I <args> E`, which is the only case where a return type stands in
    /// front of the parameter list. Sniffing the rendered name for a `<` would not do: `operator<` and
    /// `operator<<` are full of them, and both are ordinary functions with no return type to read.
    templated: bool,
}

impl<'a> Parse<'a> {
    fn peek(&self) -> Option<u8> {
        self.raw.get(self.at).copied()
    }

    fn starts(&self, with: &[u8]) -> bool {
        self.raw.get(self.at..self.at.saturating_add(with.len())) == Some(with)
    }

    fn eat(&mut self, len: usize) {
        self.at += len;
    }

    /// `<source-name>`: a decimal length and that many bytes of identifier. The length has to be a
    /// positive number without a leading zero, and the identifier has to look like one - clang writes
    /// `$` inside local names, those are outside this subset, so a `$` stops the walk and the name is
    /// refused rather than read as a shorter one.
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
        if body.is_empty()
            || body[0].is_ascii_digit()
            || !body
                .iter()
                .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
        {
            return None;
        }
        self.at = self.at.checked_add(length)?;
        Some(String::from_utf8(body.to_vec()).ok()?)
    }

    /// `A <number> _`: an array bound. The `A` is part of the spelling, so the walk steps over it here
    /// and the digits have to be followed by the `_` that ends them.
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

    /// True when the bytes here are a numbered substitution or template parameter rather than a name
    /// that happens to start with the same letter. The walk has to ask before it moves, because after
    /// consuming an `S` there is no way back to reading `S` as the start of something else.
    fn marks(&self, head: u8) -> bool {
        let mut at = self.at;
        if self.raw.get(at) != Some(&head) {
            return false;
        }
        at += 1;
        if self.raw.get(at) == Some(&b'_') {
            return true;
        }
        let first = at;
        while matches!(self.raw.get(at), Some(b'0'..=b'9')) {
            at += 1;
        }
        at > first && self.raw.get(at) == Some(&b'_')
    }

    /// `S_`, `S0_`, ... - the first substitution is `_`, and the numbered ones count up from there.
    fn substitution(&mut self) -> Option<usize> {
        if self.raw.get(self.at + 1) == Some(&b'_') {
            self.eat(2);
            return Some(0);
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

    /// `T_`, `T0_`, ... - a template parameter, resolved against the argument list the name carried.
    fn template_param(&mut self) -> Option<usize> {
        if self.raw.get(self.at + 1) == Some(&b'_') {
            self.eat(2);
            return Some(0);
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

    /// A type, as far as this subset reaches. `None` means "not in the subset", which the caller turns
    /// into a refused name rather than a partial answer.
    fn ty(&mut self) -> Option<Ty> {
        let head = self.peek()?;
        let built = match head {
            b'P' | b'R' | b'O' | b'K' | b'V' => {
                self.eat(1);
                let inner = self.ty()?;
                match head {
                    b'P' => Ty::Pointer(Box::new(inner)),
                    b'R' => Ty::Reference(Box::new(inner)),
                    b'O' => Ty::RValue(Box::new(inner)),
                    // `K` is const and `V` volatile in this grammar, which is not the spelling anyone
                    // reading the letters would guess.
                    b'K' => Ty::Const(Box::new(inner)),
                    _ => Ty::Volatile(Box::new(inner)),
                }
            }
            b'A' => {
                let length = self.array_bound()?;
                let element = self.ty()?;
                Ty::Array(length, Box::new(element))
            }
            b'S' if self.marks(b'S') => {
                let index = self.substitution()?;
                // A resolved substitution is not itself a new candidate, which is why nothing is pushed
                // here - the entry it names is already in the table.
                return Some(Ty::Named(self.subs.get(index)?.clone()));
            }
            b'T' if self.marks(b'T') => {
                let index = self.template_param()?;
                let text = self.args.get(index)?.clone();
                // A template parameter *is* recorded once resolved, which is how a function whose
                // return type is `T_` can then write its parameters as `S0_`.
                self.subs.push(text.clone());
                return Some(Ty::Named(text));
            }
            b'N' => {
                // The nested-name walk already recorded the name it completed, so this arm returns
                // early rather than adding the same spelling to the table twice.
                return Some(Ty::Named(self.nested_name()?.0));
            }
            byte if byte.is_ascii_digit() => {
                let text = self.source_name()?;
                self.subs.push(text.clone());
                return Some(Ty::Named(text));
            }
            byte => match builtin(byte) {
                Some(text) => {
                    self.eat(1);
                    return Some(Ty::Builtin(text));
                }
                None => return None,
            },
        };
        // A declarator or cv-qualification is a candidate when it is *complete*, which is what makes
        // `RK3Vec` leave three entries behind: the class name, the qualified type, the reference.
        self.subs.push(built.text());
        Some(built)
    }

    /// `I <args> E`, the argument list after a name. Only type arguments are in this subset, and each
    /// one is a substitution candidate in the order it appears.
    fn template_args(&mut self) -> Option<Vec<String>> {
        self.eat(1);
        let mut out = Vec::new();
        loop {
            if self.peek()? == b'E' {
                self.eat(1);
                return Some(out);
            }
            let arg = self.ty()?;
            let text = arg.text();
            self.subs.push(text.clone());
            out.push(text);
        }
    }

    /// One `<unscoped-name>`: a source name, optionally a template-id, an operator code, or a
    /// conversion to a type. A template-id records its own name before its arguments, which is the
    /// order the witnesses' `S_` numbering assumes, and leaves the arguments in scope for the `T_`s
    /// that follow.
    fn component(&mut self) -> Option<String> {
        if self.starts(b"cv") {
            self.eat(2);
            let target = self.ty()?;
            return Some(format!("operator {}", target.text()));
        }
        if let Some(text) = self.raw.get(self.at..self.at + 2).and_then(operator_code) {
            self.eat(2);
            return Some(text.to_owned());
        }
        let text = self.source_name()?;
        if !self.starts(b"I") {
            return Some(text);
        }
        self.subs.push(text.clone());
        let args = self.template_args()?;
        self.args = args.clone();
        self.templated = true;
        Some(format!("{}<{}>", text, args.join(", ")))
    }

    /// The name and its cv-qualifier: `N ... E`, with the `K` that follows the `N` for a const member,
    /// a constructor or destructor designator where the last identifier would be, and an operator code
    /// or `cv <type>` in the same place.
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
                    // The first component and the whole name are both candidates, which is what makes
                    // `NS_3BoxE` mean `ns::Box` after `2ns` has been read once.
                    let joined = parts.join("::");
                    if parts.len() > 1 {
                        self.subs.push(parts[0].clone());
                    }
                    self.subs.push(joined.clone());
                    return Some((joined, qualified));
                }
                b'C' | b'D' if matches!(self.peek(), Some(b'C' | b'D')) => {
                    let kind = self.peek()?;
                    self.eat(1);
                    if !matches!(self.peek(), Some(b'0'..=b'2')) {
                        return None;
                    }
                    self.eat(1);
                    // A constructor or destructor borrows the class name one level out and demangles to
                    // it, so `C1` and `C2` of the same class print the same string.
                    let owner = parts.last()?.clone();
                    let leaf = owner.rsplit("::").next().unwrap_or(&owner);
                    parts.push(if kind == b'D' {
                        format!("~{}", leaf)
                    } else {
                        leaf.to_owned()
                    });
                }
                b'S' if self.marks(b'S') => {
                    let index = self.substitution()?;
                    parts.push(self.subs.get(index)?.clone());
                }
                b'T' if self.marks(b'T') => {
                    let index = self.template_param()?;
                    parts.push(self.args.get(index)?.clone());
                }
                _ => parts.push(self.component()?),
            }
        }
    }

    /// The parameter list: `<type>*`, with a lone `v` standing for none - the mangling writes a
    /// function of no arguments as `Ev`, and both witnesses print `()` for it.
    fn params(&mut self) -> Option<Vec<String>> {
        if self.peek()? == b'v' && self.at + 1 == self.raw.len() {
            self.eat(1);
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        while self.peek().is_some() {
            out.push(self.ty()?.text());
        }
        Some(out)
    }
}

/// The demangled spelling of an Itanium name, or `None` when the name is outside the subset two
/// demanglers agree on. `None` is the ordinary answer for a name this lab has no witness for, and the
/// row prints it as `-`.
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
        templated: false,
    };
    let (rendered, qualified) = if walk.peek()? == b'N' {
        walk.nested_name()?
    } else {
        // A top-level name: a free function, a data object, or a free operator. Its own name is not a
        // substitution candidate unless it is a template-id, and `component` records that case itself.
        (walk.component()?, false)
    };
    if walk.peek().is_none() {
        // A data object: the name is the whole answer, with no parentheses to invent.
        return Some(rendered);
    }
    let return_ty = if walk.templated {
        Some(walk.ty()?.text())
    } else {
        None
    };
    let params = walk.params()?;
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
