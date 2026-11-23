use std::collections::BTreeMap;
use std::io::{self, ErrorKind};

use super::*;
use crate::collect::nginx_files::EntryName;
use crate::nginx::UncertaintyKind;
use crate::parse::nginx::parse_nginx_config;

/// What a fake path holds.
enum Entry {
    Text(String),
    Bytes(Vec<u8>),
    Special,
    Fails(ErrorKind),
}

/// An in-memory filesystem: directories are implied by the file paths.
#[derive(Default)]
struct FakeFiles(BTreeMap<String, Entry>);

impl FakeFiles {
    fn with(mut self, path: &str, entry: Entry) -> Self {
        self.0.insert(path.to_owned(), entry);
        self
    }

    fn text(self, path: &str, text: impl Into<String>) -> Self {
        self.with(path, Entry::Text(text.into()))
    }
}

impl ConfigFiles for FakeFiles {
    fn read(&self, path: &str, limit: u64) -> io::Result<FileRead> {
        let bytes = match self.0.get(path) {
            None => return Ok(FileRead::Missing),
            Some(Entry::Special) => return Ok(FileRead::NotRegular),
            Some(Entry::Fails(kind)) => return Err(io::Error::from(*kind)),
            Some(Entry::Text(text)) => text.as_bytes().to_vec(),
            Some(Entry::Bytes(bytes)) => bytes.clone(),
        };
        Ok(if bytes.len() as u64 > limit {
            FileRead::TooLarge
        } else {
            FileRead::Bytes(bytes)
        })
    }

    fn list(&self, dir: &str, limit: usize) -> io::Result<DirList> {
        if let Some(Entry::Fails(kind)) = self.0.get(dir) {
            return Err(io::Error::from(*kind));
        }
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        let mut names: Vec<String> = self
            .0
            .keys()
            .filter_map(|path| path.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or(rest).to_owned())
            .collect();
        names.dedup();
        if names.len() > limit {
            return Ok(DirList::TooMany);
        }
        // Directory order is arbitrary; the walk must sort. A `\u{fffd}` marks
        // a name that is not UTF-8 on disk.
        names.reverse();
        Ok(DirList::Entries(
            names
                .into_iter()
                .map(|name| EntryName {
                    utf8: !name.contains('\u{fffd}'),
                    name,
                })
                .collect(),
        ))
    }
}

const MAIN: &str = "/etc/nginx/nginx.conf";

fn debian_layout() -> FakeFiles {
    FakeFiles::default()
        .text(
            MAIN,
            "include modules-enabled/*.conf;\n\
             http {\n    include mime.types;\n    include conf.d/*.conf;\n    \
             include /etc/nginx/sites-enabled/*;\n}\n",
        )
        .text("/etc/nginx/mime.types", "types { text/html html; }")
        .text(
            "/etc/nginx/conf.d/app.conf",
            "server {\n    listen 80;\n    location / { include snippets/proxy.conf; }\n}\n",
        )
        .text(
            "/etc/nginx/snippets/proxy.conf",
            "proxy_pass http://127.0.0.1:8080;\n",
        )
        .text(
            "/etc/nginx/sites-enabled/b-site",
            "server { listen 8082; }\n",
        )
        .text(
            "/etc/nginx/sites-enabled/a-site",
            "server { listen 8081; }\n",
        )
        .text("/etc/nginx/sites-enabled/.a-site.swp", "not nginx {")
}

#[test]
fn reads_includes_depth_first_in_nginx_order() {
    let dump = read_config(MAIN, &debian_layout()).unwrap();
    let headers: Vec<&str> = dump
        .lines()
        .filter_map(|line| line.strip_prefix("# configuration file "))
        .collect();
    assert_eq!(
        headers,
        [
            "/etc/nginx/nginx.conf:",
            "/etc/nginx/mime.types:",
            "/etc/nginx/conf.d/app.conf:",
            "/etc/nginx/snippets/proxy.conf:",
            "/etc/nginx/sites-enabled/a-site:",
            "/etc/nginx/sites-enabled/b-site:",
        ]
    );
    assert!(dump.contains("types { text/html html; }\n# configuration file"));

    let config = parse_nginx_config(&dump).unwrap();
    assert!(
        config.uncertainties.is_empty(),
        "{:?}",
        config.uncertainties
    );
    assert_eq!(config.servers.len(), 3);
}

#[test]
fn reads_each_file_once_even_with_repeats_and_cycles() {
    let files = FakeFiles::default()
        .text(MAIN, "include a.conf;\ninclude a.conf;\ninclude b.conf;\n")
        .text("/etc/nginx/a.conf", "include b.conf;\n")
        .text(
            "/etc/nginx/b.conf",
            "include a.conf;\ninclude nginx.conf;\n",
        );
    let dump = read_config(MAIN, &files).unwrap();
    assert_eq!(dump.matches("# configuration file").count(), 3);

    // The cycle ends in an incomplete report (exit 1), not a stack overflow.
    let report =
        super::super::collect_with(Ok(dump), || panic!("no listeners to look up")).unwrap();
    assert!(!report.is_complete());
    assert!(
        report
            .config()
            .uncertainties
            .iter()
            .any(|u| u.kind == UncertaintyKind::UnresolvedInclude)
    );
}

#[test]
fn missing_literal_includes_are_left_for_the_parser() {
    let files = FakeFiles::default().text(
        MAIN,
        "http { include missing.conf; include none/*.conf; include none/site[12].conf; }",
    );
    let dump = read_config(MAIN, &files).unwrap();
    assert_eq!(dump.matches("# configuration file").count(), 1);
    let unresolved = parse_nginx_config(&dump)
        .unwrap()
        .uncertainties
        .into_iter()
        .filter(|u| u.kind == UncertaintyKind::UnresolvedInclude)
        .count();
    assert_eq!(unresolved, 1, "only the literal; globs may match nothing");

    assert!(matches!(
        read_config(MAIN, &FakeFiles::default()),
        Err(NginxScanError::ConfigNotFound { path }) if path == MAIN
    ));
}

#[test]
fn bracket_classes_expand_like_glob() {
    let files = FakeFiles::default()
        .text(
            MAIN,
            "http { include conf.d/site[12]*.conf; include conf.d/[!s]*.conf; }",
        )
        .text("/etc/nginx/conf.d/site1-prod.conf", "server { listen 81; }")
        .text("/etc/nginx/conf.d/site2.conf", "server { listen 82; }")
        .text("/etc/nginx/conf.d/site3.conf", "server { listen 83; }")
        .text("/etc/nginx/conf.d/api.conf", "server { listen 84; }");
    let dump = read_config(MAIN, &files).unwrap();
    for (name, read) in [
        ("site1-prod.conf", true),
        ("site2.conf", true),
        ("site3.conf", false),
        ("api.conf", true),
    ] {
        assert_eq!(dump.contains(&format!("/conf.d/{name}:")), read, "{name}");
    }
    let config = parse_nginx_config(&dump).unwrap();
    assert!(
        config.uncertainties.is_empty(),
        "{:?}",
        config.uncertainties
    );
    assert_eq!(config.servers.len(), 3);
}

#[test]
fn expands_wildcards_in_directory_components() {
    let files = FakeFiles::default()
        .text(MAIN, "http { include /srv/vhosts/*/site.conf; }")
        .text("/srv/vhosts/beta/site.conf", "server { listen 82; }")
        .text("/srv/vhosts/alpha/site.conf", "server { listen 81; }")
        .text("/srv/vhosts/alpha/other.conf", "not nginx {")
        .text("/srv/vhosts/notes.txt", "");
    let dump = read_config(MAIN, &files).unwrap();
    let alpha = dump.find("/srv/vhosts/alpha/site.conf").unwrap();
    let beta = dump.find("/srv/vhosts/beta/site.conf").unwrap();
    assert!(alpha < beta);
    assert!(!dump.contains("other.conf"));
}

#[test]
fn unsafe_or_unreadable_files_fail_cleanly() {
    let cases = [
        (Entry::Special, "not a regular file"),
        (Entry::Bytes(vec![b'#', 0xff]), "not valid UTF-8"),
    ];
    for (entry, reason) in cases {
        let files = FakeFiles::default()
            .text(MAIN, "include x.conf;")
            .with("/etc/nginx/x.conf", entry);
        let error = read_config(MAIN, &files).unwrap_err();
        assert!(
            matches!(&error, NginxScanError::UnreadableFile { path, reason: r }
                if path == "/etc/nginx/x.conf" && *r == reason),
            "{error:?}"
        );
    }

    let denied = FakeFiles::default().with(MAIN, Entry::Fails(ErrorKind::PermissionDenied));
    assert!(matches!(
        read_config(MAIN, &denied),
        Err(NginxScanError::PermissionDenied)
    ));

    let broken = FakeFiles::default()
        .text(MAIN, "include conf.d/*.conf;")
        .with("/etc/nginx/conf.d", Entry::Fails(ErrorKind::Interrupted));
    let error = read_config(MAIN, &broken).unwrap_err();
    assert!(
        matches!(&error, NginxScanError::ReadFailed { path, .. } if path == "/etc/nginx/conf.d")
    );
    assert!(error.to_string().contains("/etc/nginx/conf.d"));

    let bad_name = FakeFiles::default()
        .text(MAIN, "include conf.d/*.conf;")
        .text("/etc/nginx/conf.d/app.conf", "")
        .text("/etc/nginx/conf.d/notes\u{fffd}.txt", "");
    assert!(
        read_config(MAIN, &bad_name).is_ok(),
        "a name that cannot match is skipped"
    );
    let bad_match = bad_name.text("/etc/nginx/conf.d/x\u{fffd}.conf", "");
    assert!(matches!(
        read_config(MAIN, &bad_match),
        Err(NginxScanError::UnreadableFile {
            reason: "a matching file name is not valid UTF-8",
            ..
        })
    ));

    let control = FakeFiles::default()
        .text(MAIN, "include conf.d/*.conf;")
        .text("/etc/nginx/conf.d/x\n.conf", "");
    assert!(matches!(
        read_config(MAIN, &control),
        Err(NginxScanError::UnreadableFile {
            reason: "the path has control characters",
            ..
        })
    ));
}

#[test]
fn parse_errors_name_the_included_file() {
    let files = FakeFiles::default()
        .text(MAIN, "include broken.conf;")
        .text("/etc/nginx/broken.conf", "server {");
    let error = read_config(MAIN, &files).unwrap_err();
    assert!(error.to_string().contains("could not parse"), "{error}");
    let NginxScanError::Parse(source) = error else {
        panic!("expected a parse error");
    };
    assert!(source.to_string().contains("/etc/nginx/broken.conf:1"));
}

#[test]
fn byte_file_and_depth_limits_are_enforced() {
    let huge = FakeFiles::default().with(MAIN, Entry::Bytes(vec![b'#'; MAX_INPUT_BYTES + 1]));
    assert!(matches!(
        read_config(MAIN, &huge),
        Err(NginxScanError::ConfigTooLarge { .. })
    ));

    let mut many = FakeFiles::default().text(MAIN, "include conf.d/*;");
    for index in 0..=MAX_FILES {
        many = many.text(&format!("/etc/nginx/conf.d/{index:05}"), "");
    }
    assert!(matches!(
        read_config(MAIN, &many),
        Err(NginxScanError::TooManyFiles { limit: MAX_FILES })
    ));

    // Many directories with no match are fine; only matches count as files.
    let mut wide = FakeFiles::default().text(MAIN, "include /srv/*/routes.conf;");
    for index in 0..=MAX_FILES {
        wide = wide.text(&format!("/srv/{index:05}/other.conf"), "");
    }
    assert_eq!(
        read_config(MAIN, &wide)
            .unwrap()
            .matches("# configuration")
            .count(),
        1
    );

    let mut huge_dir = FakeFiles::default().text(MAIN, "include conf.d/*.conf;");
    for index in 0..=MAX_GLOB_ENTRIES {
        huge_dir = huge_dir.text(&format!("/etc/nginx/conf.d/{index:06}.txt"), "");
    }
    assert!(matches!(
        read_config(MAIN, &huge_dir),
        Err(NginxScanError::GlobTooWide {
            limit: MAX_GLOB_ENTRIES
        })
    ));

    let mut deep = FakeFiles::default().text(MAIN, "include 0.conf;");
    for index in 0..=MAX_INCLUDE_DEPTH + 1 {
        let next = format!("include {}.conf;", index + 1);
        deep = deep.text(&format!("/etc/nginx/{index}.conf"), next);
    }
    assert!(matches!(
        read_config(MAIN, &deep),
        Err(NginxScanError::IncludeTooDeep {
            limit: MAX_INCLUDE_DEPTH
        })
    ));
}
