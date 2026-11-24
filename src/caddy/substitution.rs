//! Values known to have been substituted into a config before it was parsed.

use std::fmt;

/// Shortest substituted value looked for, in characters. Shorter values
/// would match almost every path or name, and are not secrets worth hiding.
pub const MIN_SUBSTITUTION_CHARS: usize = 4;

/// Values that were substituted into the config before reachmap saw it, for
/// example the environment values behind Caddyfile `{$VAR}` placeholders,
/// which `caddy adapt` writes into the JSON as plain text.
///
/// The parser leaves out every modeled value that contains one of them and
/// reports a [`SubstitutedValue`](super::UncertaintyKind::SubstitutedValue)
/// uncertainty instead. Matching ignores case, as Caddy lowercases hosts and
/// paths. `Debug` shows only how many values are held.
#[derive(Clone, Default)]
pub struct Substitutions {
    /// Lowercased values of at least [`MIN_SUBSTITUTION_CHARS`] characters.
    values: Vec<String>,
}

impl Substitutions {
    /// Values to look for; ones shorter than [`MIN_SUBSTITUTION_CHARS`] are
    /// dropped.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let values = values
            .into_iter()
            .filter(|value| value.as_ref().chars().count() >= MIN_SUBSTITUTION_CHARS)
            .map(|value| value.as_ref().to_lowercase())
            .collect();
        Self { values }
    }

    /// No known substitutions.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether `text` contains a substituted value.
    pub(crate) fn taints(&self, text: &str) -> bool {
        if self.values.is_empty() {
            return false;
        }
        let text = text.to_lowercase();
        self.values
            .iter()
            .any(|value| text.contains(value.as_str()))
    }
}

impl fmt::Debug for Substitutions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Substitutions")
            .field("count", &self.values.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_values_inside_text_ignoring_case() {
        let substitutions = Substitutions::new(["Tok3nValue"]);
        assert!(substitutions.taints("/download/tok3nvalue/file"));
        assert!(substitutions.taints("TOK3NVALUE.example.test"));
        assert!(!substitutions.taints("/download/other"));
    }

    #[test]
    fn ignores_short_values_and_matches_nothing_when_empty() {
        let substitutions = Substitutions::new(["", "abc"]);
        assert!(!substitutions.taints("abc"));
        assert!(!Substitutions::none().taints("anything"));
    }

    #[test]
    fn debug_never_shows_the_values() {
        let shown = format!("{:?}", Substitutions::new(["synthetic-secret"]));
        assert_eq!(shown, "Substitutions { count: 1 }");
    }
}
