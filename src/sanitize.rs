//! Making text from other programs safe to print.
//!
//! Process names, container names, Docker labels and Docker's error messages
//! are not under reachmap's control. A container label can hold a terminal
//! escape sequence that rewrites what the user sees, or a right-to-left
//! override that reorders it, so such text is cleaned when it is parsed.

/// Replaces every character that could change how the terminal shows the
/// output with its visible escape, e.g. `\u{1b}`, and keeps the rest as is.
pub fn sanitize(text: &str) -> String {
    let mut clean = String::with_capacity(text.len());
    for character in text.chars() {
        if is_unsafe(character) {
            clean.extend(character.escape_default());
        } else {
            clean.push(character);
        }
    }
    clean
}

/// Control characters, line separators and the invisible characters that
/// change the direction of the text around them.
fn is_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_ordinary_text() {
        assert_eq!(sanitize("app-web_1.2"), "app-web_1.2");
    }

    #[test]
    fn keeps_non_ascii_text() {
        assert_eq!(sanitize("tjeneste-æøå-日本"), "tjeneste-æøå-日本");
    }

    #[test]
    fn escape_sequences_lose_their_escape_character() {
        assert_eq!(sanitize("\u{1b}[2Jgone"), "\\u{1b}[2Jgone");
    }

    #[test]
    fn line_breaks_cannot_fake_a_table_row() {
        assert_eq!(sanitize("a\nb\rc"), "a\\nb\\rc");
        assert_eq!(sanitize("a\u{2028}b"), "a\\u{2028}b");
    }

    #[test]
    fn c1_controls_and_delete_are_escaped() {
        assert_eq!(sanitize("\u{9b}31m\u{7f}"), "\\u{9b}31m\\u{7f}");
    }

    #[test]
    fn direction_overrides_are_escaped() {
        assert_eq!(sanitize("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(sanitize("a\u{2066}b"), "a\\u{2066}b");
    }
}
