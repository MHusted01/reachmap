//! What reachmap checks in a Caddyfile's own text before adapting it.

use std::collections::HashSet;

/// Whether the Caddyfile has an `import` that may name files rather than a
/// snippet it defines. Caddy expands `{$VAR}` placeholders in imported files
/// too, and those files are not read, so their placeholders go unchecked.
/// Anything that is not clearly a snippet import counts as a file import.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(super) fn imports_files(text: &str) -> bool {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let tokens: Vec<&str> = text
        .lines()
        .flat_map(|line| {
            line.split_whitespace()
                .take_while(|token| !token.starts_with('#'))
        })
        .collect();
    let snippets: HashSet<&str> = tokens
        .iter()
        .filter_map(|token| token.strip_prefix('(')?.strip_suffix(')'))
        .collect();
    tokens.iter().enumerate().any(|(index, token)| {
        *token == "import"
            && tokens
                .get(index + 1)
                .is_none_or(|name| !snippets.contains(name.trim_matches('"')))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snippet_imports_are_not_file_imports() {
        let text = "(common) {\n\tencode gzip\n}\n\napp.example.test {\n\timport common\n\treverse_proxy 127.0.0.1:3000\n}\n";
        assert!(!imports_files(text));
        assert!(!imports_files(
            ":80 {\n\t# import sites/*\n\trespond ok\n}\n"
        ));
    }

    #[test]
    fn file_and_unknown_imports_count() {
        assert!(imports_files("import sites/*\n"));
        assert!(imports_files("(a) {\n}\n:80 {\n\timport \"b\"\n}\n"));
        assert!(imports_files(":80 {\n\timport\n}\n"));
        assert!(imports_files(":80 { import extra.caddy }"));
        assert!(
            imports_files("\u{feff}import sites/*\n"),
            "Caddy strips a byte-order mark"
        );
    }
}
