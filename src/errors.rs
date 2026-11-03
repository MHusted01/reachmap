//! Turning errors into one line a user can act on.

use std::error::Error;

/// Joins an error and all its causes with `": "`, outermost first, e.g.
/// `could not read /proc/net/tcp: Permission denied (os error 13)`.
pub fn render_chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |&current| current.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::CollectError;
    use std::io;

    #[test]
    fn joins_every_cause_outermost_first() {
        let error = CollectError::Read {
            path: "/proc/net/tcp".into(),
            source: io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"),
        };
        assert_eq!(
            render_chain(&error),
            "could not read /proc/net/tcp: permission denied"
        );
    }

    #[test]
    fn an_error_without_causes_is_just_its_message() {
        let error = CollectError::UnsupportedOs { os: "macos" };
        assert_eq!(
            render_chain(&error),
            "reachmap scan is Linux only for now (this system is macos)"
        );
    }
}
