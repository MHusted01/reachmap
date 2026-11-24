//! JSON locations for uncertainties, and bounded names taken from the config.

use crate::sanitize::sanitize;

/// Longest configuration key or construct name kept, in characters.
const MAX_NAME_CHARS: usize = 64;

/// Where a construct sits in the config, e.g.
/// `apps.http.servers["srv0"].routes[1].handle[0]`. Built from field names
/// the parser chooses, sanitized keys and indexes, never from values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JsonPath(String);

impl JsonPath {
    /// A path starting at a top-level field.
    pub(crate) fn root(field: &str) -> Self {
        Self(field.to_owned())
    }

    /// `self.field`.
    pub(crate) fn field(&self, field: &str) -> Self {
        Self(format!("{}.{field}", self.0))
    }

    /// `self["key"]`, with the key sanitized and length-bounded.
    pub(crate) fn key(&self, key: &str) -> Self {
        let key = bounded_name(key).replace('"', "\\\"");
        Self(format!("{}[\"{key}\"]", self.0))
    }

    /// `self[index]`.
    pub(crate) fn index(&self, index: usize) -> Self {
        Self(format!("{}[{index}]", self.0))
    }
}

impl From<&JsonPath> for String {
    fn from(path: &JsonPath) -> Self {
        path.0.clone()
    }
}

/// A name from the config (server key, handler type, matcher name) made safe
/// to print and cut to [`MAX_NAME_CHARS`] characters, marked with `...`.
pub(crate) fn bounded_name(name: &str) -> String {
    let mut characters = name.chars();
    let kept: String = characters.by_ref().take(MAX_NAME_CHARS).collect();
    let mut clean = sanitize(&kept);
    if characters.next().is_some() {
        clean.push_str("...");
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_dotted_and_indexed_paths() {
        let path = JsonPath::root("apps")
            .field("http")
            .field("servers")
            .key("srv0")
            .field("routes")
            .index(2);
        assert_eq!(
            String::from(&path),
            r#"apps.http.servers["srv0"].routes[2]"#
        );
    }

    #[test]
    fn keys_cannot_break_out_of_their_quotes_or_the_terminal() {
        let path = JsonPath::root("servers").key("a\"]\u{1b}[2J");
        assert_eq!(String::from(&path), r#"servers["a\"]\u{1b}[2J"]"#);
    }

    #[test]
    fn long_names_are_cut() {
        let name = bounded_name(&"x".repeat(100));
        assert_eq!(name, format!("{}...", "x".repeat(MAX_NAME_CHARS)));
        assert_eq!(bounded_name("srv0"), "srv0");
    }
}
