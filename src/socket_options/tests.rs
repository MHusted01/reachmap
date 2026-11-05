use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;

use super::*;
use crate::errors::render_chain;
use crate::parse::sock_diag::REQUEST_LEN;

const IPV4: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_ipv4.bin");
const IPV6: &[u8] = include_bytes!("../../tests/fixtures/sock_diag_ipv6.bin");

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

#[test]
fn both_address_families_are_asked_and_merged_by_inode() {
    let channel = FakeChannel::replying(vec![Ok(IPV4.to_vec()), Ok(IPV6.to_vec())]);

    let options = options_from(&channel).unwrap();

    assert_eq!(options.len(), 6);
    assert_eq!(options[&68171].bound_device, Some(2));
    assert!(options[&68173].ipv6_only);
    let requests = channel.requests.borrow();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], dump_request(AddressFamily::Ipv4));
    assert_eq!(requests[1], dump_request(AddressFamily::Ipv6));
    assert_eq!(requests[1].len(), REQUEST_LEN);
}

#[test]
fn a_reply_may_span_several_datagrams() {
    let (first, rest) = IPV4.split_at(FIRST_MESSAGE_LEN);
    let channel = FakeChannel::replying(vec![
        Ok(first.to_vec()),
        Ok(rest.to_vec()),
        Ok(IPV6.to_vec()),
    ]);

    assert_eq!(options_from(&channel).unwrap().len(), 6);
}

#[test]
fn a_timeout_is_an_error_not_a_hang() {
    let channel = FakeChannel::replying(vec![Ok(IPV4.to_vec()), Err(timed_out())]);

    let error = options_from(&channel).unwrap_err();

    assert!(matches!(error, SocketOptionsError::Collect(_)));
    assert!(
        render_chain(&error).starts_with(
            "could not read socket options: could not read the kernel's socket diagnostics: "
        ),
        "{}",
        render_chain(&error)
    );
    assert_eq!(error.hint(), None);
}

#[test]
fn a_request_that_cannot_be_sent_is_an_error() {
    let channel = FakeChannel::default();
    channel.send_error.replace(Some(timed_out()));

    assert!(matches!(
        options_from(&channel),
        Err(SocketOptionsError::Collect(_))
    ));
}

#[test]
fn a_malformed_reply_asks_for_a_bug_report() {
    let channel = FakeChannel::replying(vec![Ok(vec![1, 2, 3])]);

    let error = options_from(&channel).unwrap_err();

    assert_eq!(
        render_chain(&error),
        "could not read socket options: the reply is malformed"
    );
    assert!(error.hint().unwrap().contains(ISSUES_URL));
}

#[test]
fn a_refusal_from_the_kernel_gets_no_bug_report_hint() {
    let refused = SockDiagError::Refused(io::Error::from_raw_os_error(13));
    assert_eq!(SocketOptionsError::Reply(refused).hint(), None);
}
