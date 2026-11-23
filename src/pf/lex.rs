//! Splitting one `pfctl` line into tokens.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Token<'a> {
    /// A run of text without spaces. A parenthesized group such as `(en0)` or
    /// `(all, to pflog0)` is one word, parentheses included.
    Word(&'a str),
    /// Text between double quotes, quotes removed.
    Quoted(&'a str),
    Open,
    Close,
    Comma,
}

/// `None` when a quote or parenthesis is never closed.
pub(super) fn tokenize(line: &str) -> Option<Vec<Token<'_>>> {
    let mut tokens = Vec::new();
    let mut rest = line.trim_start();
    while let Some(first) = rest.chars().next() {
        let (token, used) = match first {
            '{' => (Token::Open, 1),
            '}' => (Token::Close, 1),
            ',' => (Token::Comma, 1),
            '"' => {
                let end = rest[1..].find('"')?;
                (Token::Quoted(&rest[1..=end]), end + 2)
            }
            '(' => {
                let end = rest.find(')')?;
                (Token::Word(&rest[..=end]), end + 1)
            }
            _ => {
                let end = rest
                    .find(|c: char| c.is_whitespace() || matches!(c, '{' | '}' | ',' | '"'))
                    .unwrap_or(rest.len());
                (Token::Word(&rest[..end]), end)
            }
        };
        tokens.push(token);
        rest = rest[used..].trim_start();
    }
    Some(tokens)
}
