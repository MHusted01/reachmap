//! `glob()`-style matching of one path component, as Nginx uses for `include`.

/// Matches `text` against a `glob()` pattern: `*` matches any run of
/// characters, `?` one character, and `[...]` one character from a class with
/// ranges (`a-z`), negation (`!` or `^`) and POSIX classes such as
/// `[:digit:]` (ASCII, as in the C locale). A `[` without a closing `]` is a
/// literal. Backslash escapes are not supported.
pub(super) fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    // After a `*`: the pattern index behind it and the text index it covers up to.
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        let step = match pattern.get(p) {
            Some('*') => {
                star = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some('?') => Some(p + 1),
            Some('[') => match match_class(&pattern, p, text[t]) {
                Some((true, next)) => Some(next),
                Some((false, _)) => None,
                None => (text[t] == '[').then_some(p + 1),
            },
            Some(&literal) => (literal == text[t]).then_some(p + 1),
            None => None,
        };
        match (step, star) {
            (Some(next), _) => {
                p = next;
                t += 1;
            }
            (None, Some((after_star, covered))) => {
                p = after_star;
                t = covered + 1;
                star = Some((after_star, covered + 1));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

/// Matches `c` against the class starting at `pattern[open] == '['`. Returns
/// whether it matched and the index after the closing `]`, or `None` when the
/// class is not closed.
fn match_class(pattern: &[char], open: usize, c: char) -> Option<(bool, usize)> {
    let mut i = open + 1;
    let negated = matches!(pattern.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let first = i;
    let mut matched = false;
    while let Some(&low) = pattern.get(i) {
        if low == ']' && i > first {
            return Some((matched != negated, i + 1));
        }
        if low == '['
            && let Some(&kind @ (':' | '.' | '=')) = pattern.get(i + 1)
            && let Some((name, end)) = bracket_expression(pattern, i + 2, kind)
        {
            matched |= if kind == ':' {
                named_class(&name, c)
            } else {
                name.chars().eq(std::iter::once(c))
            };
            i = end;
            continue;
        }
        match (pattern.get(i + 1), pattern.get(i + 2)) {
            (Some('-'), Some(&high)) if high != ']' => {
                matched |= (low..=high).contains(&c);
                i += 3;
            }
            _ => {
                matched |= low == c;
                i += 1;
            }
        }
    }
    None
}

/// Reads a `[:name:]`, `[.c.]` or `[=c=]` body from `start` up to the closing
/// `kind` and `]`. Returns the body and the index after the closing `]`.
fn bracket_expression(pattern: &[char], start: usize, kind: char) -> Option<(String, usize)> {
    (start..pattern.len().saturating_sub(1))
        .find(|&end| pattern[end] == kind && pattern[end + 1] == ']')
        .map(|end| (pattern[start..end].iter().collect(), end + 2))
}

/// Whether `c` is in the POSIX class `name` in the C locale. An unknown class
/// matches nothing, as with `fnmatch()`.
fn named_class(name: &str, c: char) -> bool {
    match name {
        "alnum" => c.is_ascii_alphanumeric(),
        "alpha" => c.is_ascii_alphabetic(),
        "blank" => matches!(c, ' ' | '\t'),
        "cntrl" => c.is_ascii_control(),
        "digit" => c.is_ascii_digit(),
        "graph" => c.is_ascii_graphic(),
        "lower" => c.is_ascii_lowercase(),
        "print" => c.is_ascii_graphic() || c == ' ',
        "punct" => c.is_ascii_punctuation(),
        "space" => c.is_ascii_whitespace() || c == '\u{b}',
        "upper" => c.is_ascii_uppercase(),
        "xdigit" => c.is_ascii_hexdigit(),
        _ => false,
    }
}
