use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;

use super::*;
use crate::errors::render_chain;
use crate::parse::sock_diag::REQUEST_LEN;

const IPV4: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_ipv4.bin");
const IPV6: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_ipv6.bin");
const UDP_IPV4: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_udp_ipv4.bin");
const UDP_IPV6: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_udp_ipv6.bin");

/// Length of one captured message in the IPv4 fixture, before the next one.
const FIRST_MESSAGE_LEN: usize = 124;

/// Plays back datagrams and remembers the requests.
#[derive(Default)]
struct FakeChannel {
    replies: RefCell<VecDeque<Result<Vec<u8>, CollectError>>>,
    requests: RefCell<Vec<Vec<u8>>>,
    send_error: RefCell<Option<CollectError>>,
}

impl FakeChannel {
    fn replying(replies: Vec<Result<Vec<u8>, CollectError>>) -> Self {
        FakeChannel {
            replies: RefCell::new(replies.into()),
            ..FakeChannel::default()
        }
    }
}

impl SockDiagChannel for FakeChannel {
    fn send(&self, request: &[u8]) -> Result<(), CollectError> {
        self.requests.borrow_mut().push(request.to_vec());
        self.send_error.borrow_mut().take().map_or(Ok(()), Err)
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<usize, CollectError> {
        let reply = self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("the code stops reading after the last reply")?;
        buffer[..reply.len()].copy_from_slice(&reply);
        Ok(reply.len())
    }
}

fn timed_out() -> CollectError {
    CollectError::SockDiag {
        action: "read",
        source: io::Error::from(io::ErrorKind::WouldBlock),
    }
}

/// The reply to all four requests.
fn all_replies() -> Vec<Result<Vec<u8>, CollectError>> {
    [IPV4, IPV6, UDP_IPV4, UDP_IPV6]
        .into_iter()
        .map(|reply| Ok(reply.to_vec()))
        .collect()
}

/// A netlink message of this type that carries a negated `errno`.
fn refusal(kind: u16, errno: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(20u32.to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.resize(16, 0);
    bytes.extend((-errno).to_ne_bytes());
    bytes
}

#[test]
fn every_protocol_and_address_family_is_asked_and_merged_by_inode() {
    let channel = FakeChannel::replying(all_replies());

    let report = options_from(&channel);

    assert!(report.error.is_none());
    assert_eq!(report.by_inode.len(), 10);
    assert_eq!(report.by_inode[&68171].bound_device, Some(2));
    assert!(report.by_inode[&68173].ipv6_only);
    assert_eq!(report.by_inode[&81558].bound_device, Some(2));
    assert!(report.by_inode[&81560].ipv6_only);
    let requests = channel.requests.borrow();
    assert_eq!(
        *requests,
        [
            dump_request(Protocol::Tcp, AddressFamily::Ipv4),
            dump_request(Protocol::Tcp, AddressFamily::Ipv6),
            dump_request(Protocol::Udp, AddressFamily::Ipv4),
            dump_request(Protocol::Udp, AddressFamily::Ipv6),
        ]
    );
    assert_eq!(requests[1].len(), REQUEST_LEN);
}

#[test]
fn a_reply_may_span_several_datagrams() {
    let (first, rest) = IPV4.split_at(FIRST_MESSAGE_LEN);
    let mut replies = vec![Ok(first.to_vec()), Ok(rest.to_vec())];
    replies.extend(all_replies().into_iter().skip(1));
    let channel = FakeChannel::replying(replies);

    let report = options_from(&channel);

    assert!(report.error.is_none());
    assert_eq!(report.by_inode.len(), 10);
}

#[test]
fn a_refused_udp_request_keeps_what_the_kernel_said_about_tcp() {
    // A kernel without `INET_UDP_DIAG` answers ENOENT, as an error message or
    // as the status of the message that ends a dump.
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    for kind in [NLMSG_ERROR, NLMSG_DONE] {
        let channel = FakeChannel::replying(vec![
            Ok(IPV4.to_vec()),
            Ok(IPV6.to_vec()),
            Ok(refusal(kind, 2)),
        ]);

        let report = options_from(&channel);

        assert_eq!(report.by_inode.len(), 6);
        let error = report.error.unwrap();
        assert!(
            render_chain(&error)
                .starts_with("could not read udp socket options: the kernel refused the request: "),
            "{}",
            render_chain(&error)
        );
        assert_eq!(error.hint(), None);
        assert_eq!(channel.requests.borrow().len(), 3);
    }
}

#[test]
fn a_timeout_is_an_error_not_a_hang() {
    let channel = FakeChannel::replying(vec![Ok(IPV4.to_vec()), Err(timed_out())]);

    let report = options_from(&channel);

    assert_eq!(report.by_inode.len(), 2);
    let error = report.error.unwrap();
    assert!(matches!(error, SocketOptionsError::Collect { .. }));
    assert!(
        render_chain(&error).starts_with(
            "could not read tcp socket options: could not read the kernel's socket diagnostics: "
        ),
        "{}",
        render_chain(&error)
    );
    assert_eq!(error.hint(), None);
}

#[test]
fn nothing_more_is_asked_after_a_failure() {
    let channel = FakeChannel::replying(vec![Err(timed_out())]);

    options_from(&channel);

    assert_eq!(channel.requests.borrow().len(), 1);
}

#[test]
fn a_request_that_cannot_be_sent_is_an_error() {
    let channel = FakeChannel::default();
    channel.send_error.replace(Some(timed_out()));

    assert!(matches!(
        options_from(&channel).error,
        Some(SocketOptionsError::Collect { .. })
    ));
}

#[test]
fn a_malformed_reply_asks_for_a_bug_report() {
    let channel = FakeChannel::replying(vec![Ok(vec![1, 2, 3])]);

    let error = options_from(&channel).error.unwrap();

    assert_eq!(
        render_chain(&error),
        "could not read tcp socket options: the reply is malformed"
    );
    assert!(error.hint().unwrap().contains(ISSUES_URL));
}

#[test]
fn a_refusal_from_the_kernel_gets_no_bug_report_hint() {
    let error = SocketOptionsError::Reply {
        protocol: Protocol::Tcp,
        source: SockDiagError::Refused(io::Error::from_raw_os_error(13)),
    };
    assert_eq!(error.hint(), None);
}

#[test]
fn a_channel_that_cannot_be_opened_is_named_without_a_protocol() {
    let error = SocketOptionsError::Open(timed_out());

    assert!(
        render_chain(&error).starts_with("could not read socket options: "),
        "{}",
        render_chain(&error)
    );
}
