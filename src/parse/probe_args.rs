//! The values of command-line options: the port list that `reachmap probe` and
//! `reachmap diff` share, and the probe's timeout.

use std::collections::BTreeSet;
use std::ops::RangeInclusive;
use std::str::FromStr;
use std::time::Duration;

use thiserror::Error;

/// A set of ports from the command line: sorted, without duplicates, never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList(BTreeSet<u16>);

/// Why a list of ports was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortListError {
    /// Not a number from 1 to 65535. Empty items end up here too.
    #[error("{text:?} is not a port: use a number from 1 to 65535")]
    InvalidPort {
        /// The text that was given.
        text: String,
    },
    /// A range that ends before it starts.
    #[error("the range {first}-{last} ends before it starts")]
    ReversedRange {
        /// The first port of the range.
        first: u16,
        /// The last port of the range.
        last: u16,
    },
}

impl PortList {
    /// The list of `ports`, without port 0, which cannot be connected to.
    /// `None` when no port is left, because a list is never empty.
    pub fn from_ports(ports: impl IntoIterator<Item = u16>) -> Option<Self> {
        let ports: BTreeSet<u16> = ports.into_iter().filter(|&port| port != 0).collect();
        (!ports.is_empty()).then_some(PortList(ports))
    }

    /// The ports in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.0.iter().copied()
    }

    /// Whether `port` is in the list.
    pub fn contains(&self, port: u16) -> bool {
        self.0.contains(&port)
    }
}

impl FromStr for PortList {
    type Err = PortListError;

    /// Reads a comma-separated list of ports and ranges, e.g. `22,80,8000-8100`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let ranges = text
            .split(',')
            .map(parse_range)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PortList(ranges.into_iter().flatten().collect()))
    }
}

/// Reads `80` or `8000-8100`. A single port is a range of one.
fn parse_range(item: &str) -> Result<RangeInclusive<u16>, PortListError> {
    let (first, last) = item.split_once('-').unwrap_or((item, item));
    let (first, last) = (parse_port(first)?, parse_port(last)?);
    if first > last {
        return Err(PortListError::ReversedRange { first, last });
    }
    Ok(first..=last)
}

/// Reads one port: digits only, because `u16` would also accept `+80`. Port 0
/// cannot be connected to.
fn parse_port(text: &str) -> Result<u16, PortListError> {
    let text = text.trim();
    Some(text)
        .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|digits| digits.parse().ok())
        .filter(|&port| port != 0)
        .ok_or_else(|| PortListError::InvalidPort {
            text: text.to_string(),
        })
}

/// Why a `--timeout` value was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{text:?} is not a timeout: use a number of seconds above 0, e.g. 2 or 0.5")]
pub struct TimeoutError {
    /// The text that was given.
    pub text: String,
}

/// Reads a timeout in seconds, which may have a fraction.
pub fn parse_timeout(text: &str) -> Result<Duration, TimeoutError> {
    text.parse()
        .ok()
        .and_then(|seconds| Duration::try_from_secs_f64(seconds).ok())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| TimeoutError {
            text: text.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports(text: &str) -> Result<Vec<u16>, PortListError> {
        text.parse::<PortList>().map(|list| list.iter().collect())
    }

    #[test]
    fn a_list_can_be_built_from_ports_sorted_and_without_duplicates() {
        let list = PortList::from_ports([443, 22, 443]).unwrap();
        assert_eq!(list.iter().collect::<Vec<_>>(), [22, 443]);
    }

    #[test]
    fn port_zero_is_left_out_of_a_built_list() {
        let list = PortList::from_ports([0, 22]).unwrap();
        assert_eq!(list.iter().collect::<Vec<_>>(), [22]);
    }

    #[test]
    fn a_list_without_ports_cannot_be_built() {
        assert_eq!(PortList::from_ports([]), None);
        assert_eq!(PortList::from_ports([0]), None);
    }

    #[test]
    fn a_list_knows_which_ports_it_holds() {
        let list: PortList = "22,8000-8002".parse().unwrap();

        assert!(list.contains(22));
        assert!(list.contains(8000));
        assert!(list.contains(8002));
        assert!(!list.contains(80));
        assert!(!list.contains(8003));
    }

    fn invalid(text: &str) -> PortListError {
        PortListError::InvalidPort {
            text: text.to_string(),
        }
    }

    #[test]
    fn reads_single_ports_and_ranges() {
        assert_eq!(ports("22,80,8000-8002"), Ok(vec![22, 80, 8000, 8001, 8002]));
    }

    #[test]
    fn sorts_and_removes_duplicates() {
        assert_eq!(ports("443,22,20-22"), Ok(vec![20, 21, 22, 443]));
    }

    #[test]
    fn a_range_may_be_one_port_wide() {
        assert_eq!(ports("80-80"), Ok(vec![80]));
    }

    #[test]
    fn allows_spaces_around_items() {
        assert_eq!(ports(" 22, 80 - 81 "), Ok(vec![22, 80, 81]));
    }

    #[test]
    fn accepts_the_highest_port() {
        assert_eq!(ports("65535"), Ok(vec![65535]));
    }

    #[test]
    fn refuses_port_zero() {
        assert_eq!(ports("0"), Err(invalid("0")));
    }

    #[test]
    fn refuses_a_port_above_the_maximum() {
        assert_eq!(ports("65536"), Err(invalid("65536")));
    }

    #[test]
    fn refuses_a_sign_in_front_of_a_port() {
        assert_eq!(ports("+80"), Err(invalid("+80")));
    }

    #[test]
    fn refuses_text() {
        assert_eq!(ports("22,ssh"), Err(invalid("ssh")));
    }

    #[test]
    fn refuses_an_empty_list_and_empty_items() {
        assert_eq!(ports(""), Err(invalid("")));
        assert_eq!(ports("22,,80"), Err(invalid("")));
        assert_eq!(ports("22,"), Err(invalid("")));
    }

    #[test]
    fn refuses_an_open_ended_range() {
        assert_eq!(ports("80-"), Err(invalid("")));
    }

    #[test]
    fn refuses_a_reversed_range() {
        assert_eq!(
            ports("90-80"),
            Err(PortListError::ReversedRange {
                first: 90,
                last: 80
            })
        );
    }

    #[test]
    fn an_invalid_port_error_says_what_is_allowed() {
        assert_eq!(
            invalid("ssh").to_string(),
            "\"ssh\" is not a port: use a number from 1 to 65535"
        );
    }

    #[test]
    fn reads_whole_and_fractional_seconds() {
        assert_eq!(parse_timeout("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_timeout("0.5"), Ok(Duration::from_millis(500)));
    }

    #[test]
    fn refuses_timeouts_that_cannot_work() {
        for text in ["0", "-1", "soon", "", "NaN", "inf", "1e300"] {
            assert_eq!(
                parse_timeout(text),
                Err(TimeoutError {
                    text: text.to_string()
                }),
                "{text}"
            );
        }
    }
}
