//! `glob()`-style matching of one path component, as Nginx uses for `include`.
//! Matching is on bytes, as `glob()` does in the C locale.

use std::borrow::Cow;

/// Removes `glob()` backslash escapes from a pattern component without
/// wildcards, as `glob()` does for the literal parts of a pattern.
pub fn unescape(component: &str) -> Cow<'_, str> {
    if !component.contains('\\') {
        return Cow::Borrowed(component);
    }
    let mut plain = String::with_capacity(component.len());
    let mut chars = component.chars();
    while let Some(c) = chars.next() {
        plain.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }
    Cow::Owned(plain)
}

/// Matches `text` against a `glob()` pattern: `*` matches any run of bytes,
/// `?` one byte, `\` makes the next byte literal, and `[...]` matches one byte
/// from a class with ranges (`a-z`), negation (`!` or `^`) and POSIX classes
/// such as `[:digit:]`. A `[` without a closing `]` is a literal.
pub(super) fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    // After a `*`: the pattern index behind it and the text index it covers up to.
    let mut star: Option<(usize, usize)> = None;

    while t < text.len() {
        let step = match pattern.get(p) {
            Some(b'*') => {
                star = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some(b'?') => Some(p + 1),
            Some(b'\\') if p + 1 < pattern.len() => (pattern[p + 1] == text[t]).then_some(p + 2),
            Some(b'[') => match match_class(pattern, p, text[t]) {
                Some((true, next)) => Some(next),
                Some((false, _)) => None,
                None => (text[t] == b'[').then_some(p + 1),
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
    pattern[p..].iter().all(|&b| b == b'*')
}

/// Matches `byte` against the class starting at `pattern[open] == b'['`.
/// Returns whether it matched and the index after the closing `]`, or `None`
/// when the class is not closed.
fn match_class(pattern: &[u8], open: usize, byte: u8) -> Option<(bool, usize)> {
    let mut i = open + 1;
    let negated = matches!(pattern.get(i), Some(b'!' | b'^'));
    if negated {
        i += 1;
    }
    let first = i;
    let mut matched = false;
    while let Some(&current) = pattern.get(i) {
        if current == b']' && i > first {
            return Some((matched != negated, i + 1));
        }
        if current == b'['
            && let Some(&kind @ (b':' | b'.' | b'=')) = pattern.get(i + 1)
            && let Some((name, end)) = bracket_expression(pattern, i + 2, kind)
        {
            matched |= if kind == b':' {
                named_class(name, byte)
            } else {
                name == [byte]
            };
            i = end;
            continue;
        }
        let (low, after_low) = class_byte(pattern, i)?;
        match (pattern.get(after_low), pattern.get(after_low + 1)) {
            (Some(b'-'), Some(&next)) if next != b']' => {
                let (high, after_high) = class_byte(pattern, after_low + 1)?;
                matched |= (low..=high).contains(&byte);
                i = after_high;
            }
            _ => {
                matched |= low == byte;
                i = after_low;
            }
        }
    }
    None
}

/// The class member at `i`, where `\` makes the next byte literal, and the
/// index after it.
fn class_byte(pattern: &[u8], i: usize) -> Option<(u8, usize)> {
    match pattern.get(i)? {
        b'\\' => pattern.get(i + 1).map(|&escaped| (escaped, i + 2)),
        &plain => Some((plain, i + 1)),
    }
}

/// Reads a `[:name:]`, `[.c.]` or `[=c=]` body from `start` up to the closing
/// `kind` and `]`. Returns the body and the index after the closing `]`.
fn bracket_expression(pattern: &[u8], start: usize, kind: u8) -> Option<(&[u8], usize)> {
    (start..pattern.len().saturating_sub(1))
        .find(|&end| pattern[end] == kind && pattern[end + 1] == b']')
        .map(|end| (&pattern[start..end], end + 2))
}

/// Whether `byte` is in the POSIX class `name` in the C locale. An unknown
/// class matches nothing, as with `fnmatch()`.
fn named_class(name: &[u8], byte: u8) -> bool {
    match name {
        b"alnum" => byte.is_ascii_alphanumeric(),
        b"alpha" => byte.is_ascii_alphabetic(),
        b"blank" => matches!(byte, b' ' | b'\t'),
        b"cntrl" => byte.is_ascii_control(),
        b"digit" => byte.is_ascii_digit(),
        b"graph" => byte.is_ascii_graphic(),
        b"lower" => byte.is_ascii_lowercase(),
        b"print" => byte.is_ascii_graphic() || byte == b' ',
        b"punct" => byte.is_ascii_punctuation(),
        b"space" => byte.is_ascii_whitespace() || byte == 0x0b,
        b"upper" => byte.is_ascii_uppercase(),
        b"xdigit" => byte.is_ascii_hexdigit(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{glob_match, unescape};

    #[test]
    fn backslash_escapes_match_literally() {
        assert!(glob_match(b"site\\?.conf", "site?.conf".as_bytes()));
        assert!(!glob_match(b"site\\?.conf", "site1.conf".as_bytes()));
        assert!(glob_match(b"a\\*", "a*".as_bytes()));
        assert!(!glob_match(b"a\\*", "ab".as_bytes()));
        assert!(glob_match(b"[\\]]", "]".as_bytes()));
    }

    #[test]
    fn matching_counts_bytes_like_the_c_locale() {
        assert!(
            glob_match(b"??.conf", "é.conf".as_bytes()),
            "é is two bytes"
        );
        assert!(!glob_match(b"?.conf", "é.conf".as_bytes()));
        assert!(glob_match(b"*.conf", "é.conf".as_bytes()));
    }

    #[test]
    fn literal_components_lose_their_escapes() {
        assert_eq!(unescape(r"conf\.d"), "conf.d");
        assert_eq!(unescape(r"a\\b"), r"a\b");
        assert_eq!(unescape("plain"), "plain");
        assert_eq!(unescape("trailing\\"), "trailing\\");
    }
}
