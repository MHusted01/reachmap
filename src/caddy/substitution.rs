//! Values known to have been substituted into a config before it was parsed.

use std::fmt;

/// Shortest substituted value looked for inside longer text, in characters.
/// A shorter value would match inside almost every path or name, so it only
/// taints a value it equals, such as a port number.
pub const MIN_SUBSTITUTION_CHARS: usize = 4;

/// Values that were substituted into the config before reachmap saw it, for
/// example the environment values behind Caddyfile `{$VAR}` placeholders,
/// which `caddy adapt` writes into the JSON as plain text.
///
/// The parser leaves out every modeled value that contains one of them (or,
/// for values shorter than [`MIN_SUBSTITUTION_CHARS`], equals one) and
/// reports a [`SubstitutedValue`](super::UncertaintyKind::SubstitutedValue)
/// uncertainty instead. Matching ignores case, as Caddy lowercases hosts and
/// paths. `Debug` shows only how many values are held.
#[derive(Clone, Default)]
pub struct Substitutions {
    /// Lowercased, non-empty values.
    values: Vec<String>,
}

impl Substitutions {
    /// Values to look for; empty ones are dropped.
    pub fn new<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let values = values
            .into_iter()
            .filter(|value| !value.as_ref().is_empty())
            .map(|value| value.as_ref().to_lowercase())
            .collect();
        Self { values }
    }

    /// No known substitutions.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether `text` contains a long substituted value or equals a short one.
    pub(crate) fn taints(&self, text: &str) -> bool {
        if self.values.is_empty() {
            return false;
        }
        let text = text.to_lowercase();
        self.values.iter().any(|value| {
            if value.chars().count() >= MIN_SUBSTITUTION_CHARS {
                text.contains(value.as_str())
            } else {
                text == *value
            }
        })
    }

    /// Whether a number written in decimal is a substituted value.
    pub(crate) fn taints_number(&self, number: u16) -> bool {
        self.taints(&number.to_string())
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
    fn short_values_only_match_whole_values() {
        let substitutions = Substitutions::new(["", "Abc", "443"]);
        assert!(substitutions.taints("abc"));
        assert!(!substitutions.taints("/abc/def"));
        assert!(substitutions.taints_number(443));
        assert!(!substitutions.taints_number(4430));
        assert!(!Substitutions::none().taints("anything"));
        assert!(!Substitutions::new([""]).taints(""));
    }

    #[test]
    fn long_numbers_match_inside_text_and_as_numbers() {
        let substitutions = Substitutions::new(["48217"]);
        assert!(substitutions.taints_number(48217));
        assert!(substitutions.taints(":48217"));
    }

    #[test]
    fn debug_never_shows_the_values() {
        let shown = format!("{:?}", Substitutions::new(["synthetic-secret"]));
        assert_eq!(shown, "Substitutions { count: 1 }");
    }
}
