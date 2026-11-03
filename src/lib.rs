//! reachmap shows which services on a host can be reached, from where, and why.

/// The line printed by `reachmap --version`, e.g. `reachmap 0.1.0`.
pub fn version_line() -> String {
    format!("reachmap {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_names_the_tool_and_its_version() {
        assert_eq!(
            version_line(),
            format!("reachmap {}", env!("CARGO_PKG_VERSION"))
        );
    }
}
