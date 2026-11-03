//! Collectors: the only code that reads from the running system. They gather
//! raw text and hand it to the pure parsers in [`crate::parse`].

#[cfg(target_os = "linux")]
mod linux;

use std::fs;
use std::io::{self, ErrorKind};
use std::path::PathBuf;

use thiserror::Error;

use crate::socket::AddressFamily;

/// A kernel table to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSource {
    /// IP version of the sockets in the table.
    pub family: AddressFamily,
    /// File to read.
    pub path: PathBuf,
    /// When true, a missing file means "no sockets of this kind" instead of
    /// an error (e.g. `/proc/net/tcp6` on a kernel without IPv6).
    pub optional: bool,
}

/// The raw text of one kernel table, as read from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTable {
    /// IP version of the sockets in the table.
    pub family: AddressFamily,
    /// Where the text came from, used in error messages.
    pub path: PathBuf,
    /// The file's content.
    pub text: String,
}

/// Why the system could not be read.
#[derive(Debug, Error)]
pub enum CollectError {
    /// A table file exists but could not be read, or a required one is missing.
    #[error("could not read {}", path.display())]
    Read {
        /// The file that failed.
        path: PathBuf,
        /// The operating system's reason.
        #[source]
        source: io::Error,
    },
    /// This operating system has no collector yet.
    #[error("reachmap scan is Linux only for now (this system is {os})")]
    UnsupportedOs {
        /// Value of `std::env::consts::OS`, e.g. `macos`.
        os: &'static str,
    },
}

/// Reads this host's TCP tables: `/proc/net/tcp` and, when IPv6 is enabled,
/// `/proc/net/tcp6`.
#[cfg(target_os = "linux")]
pub fn read_tcp_tables() -> Result<Vec<RawTable>, CollectError> {
    read_tables(&linux::tcp_sources())
}

/// Reads this host's TCP tables. Only Linux is supported for now.
#[cfg(not(target_os = "linux"))]
pub fn read_tcp_tables() -> Result<Vec<RawTable>, CollectError> {
    Err(CollectError::UnsupportedOs {
        os: std::env::consts::OS,
    })
}

/// Reads each source in order, skipping optional sources that do not exist.
pub fn read_tables(sources: &[TableSource]) -> Result<Vec<RawTable>, CollectError> {
    let mut tables = Vec::with_capacity(sources.len());
    for source in sources {
        match fs::read_to_string(&source.path) {
            Ok(text) => tables.push(RawTable {
                family: source.family,
                path: source.path.clone(),
                text,
            }),
            Err(error) if source.optional && error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CollectError::Read {
                    path: source.path.clone(),
                    source: error,
                });
            }
        }
    }
    Ok(tables)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::render_chain;
    use std::path::Path;

    /// A fresh directory per test, removed when the guard is dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("reachmap-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn file(&self, name: &str, text: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn source(family: AddressFamily, path: &Path, optional: bool) -> TableSource {
        TableSource {
            family,
            path: path.to_path_buf(),
            optional,
        }
    }

    #[test]
    fn reads_every_source_in_order() {
        let dir = TempDir::new("in-order");
        let tcp = dir.file("tcp", "four");
        let tcp6 = dir.file("tcp6", "six");

        let tables = read_tables(&[
            source(AddressFamily::Ipv4, &tcp, false),
            source(AddressFamily::Ipv6, &tcp6, true),
        ])
        .unwrap();

        assert_eq!(
            tables,
            vec![
                RawTable {
                    family: AddressFamily::Ipv4,
                    path: tcp,
                    text: "four".to_string()
                },
                RawTable {
                    family: AddressFamily::Ipv6,
                    path: tcp6,
                    text: "six".to_string()
                },
            ]
        );
    }

    #[test]
    fn a_missing_optional_source_is_skipped() {
        let dir = TempDir::new("optional");
        let tcp = dir.file("tcp", "four");
        let missing = dir.0.join("tcp6");

        let tables = read_tables(&[
            source(AddressFamily::Ipv4, &tcp, false),
            source(AddressFamily::Ipv6, &missing, true),
        ])
        .unwrap();

        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0].family, AddressFamily::Ipv4);
    }

    #[test]
    fn a_missing_required_source_is_an_error_naming_the_file() {
        let dir = TempDir::new("required");
        let missing = dir.0.join("tcp");

        let error = read_tables(&[source(AddressFamily::Ipv4, &missing, false)]).unwrap_err();

        assert!(matches!(error, CollectError::Read { .. }));
        assert!(
            render_chain(&error).starts_with(&format!("could not read {}: ", missing.display())),
            "got: {}",
            render_chain(&error)
        );
    }

    #[test]
    fn errors_other_than_not_found_fail_even_for_optional_sources() {
        // Reading a directory as a file fails with an error that is not NotFound.
        let dir = TempDir::new("not-a-file");

        let result = read_tables(&[source(AddressFamily::Ipv6, &dir.0, true)]);

        assert!(matches!(result, Err(CollectError::Read { .. })));
    }
}
