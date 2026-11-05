use super::*;

/// A netlink message of this type around `payload`, padded to the alignment.
fn message(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = HEADER_LEN + payload.len();
    let mut bytes = Vec::new();
    bytes.extend((len as u32).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.resize(HEADER_LEN, 0);
    bytes.extend(payload);
    bytes.resize(len.next_multiple_of(ALIGNMENT), 0);
    bytes
}

fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = ATTRIBUTE_HEADER_LEN + value.len();
    let mut bytes = Vec::new();
    bytes.extend((len as u16).to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(value);
    bytes.resize(len.next_multiple_of(ALIGNMENT), 0);
    bytes
}

/// The fixed fields of a socket, followed by `attributes`.
fn socket(family: u8, device: u32, inode: u32, attributes: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; SOCKET_LEN];
    bytes[0] = family;
    bytes[SOCKET_DEVICE_OFFSET..][..4].copy_from_slice(&device.to_ne_bytes());
    bytes[SOCKET_INODE_OFFSET..][..4].copy_from_slice(&inode.to_ne_bytes());
    bytes.extend(attributes);
    bytes
}

fn done() -> Vec<u8> {
    message(NLMSG_DONE, &0i32.to_ne_bytes())
}

fn options(bound_device: Option<u32>, ipv6_only: bool) -> SocketOptions {
    SocketOptions {
        bound_device,
        ipv6_only,
    }
}

fn assert_malformed(bytes: &[u8]) {
    assert!(
        matches!(parse_dump(bytes), Err(SockDiagError::Malformed)),
        "{bytes:?}"
    );
}

#[test]
fn the_request_asks_for_listening_tcp_sockets_of_one_family() {
    let request = dump_request(AddressFamily::Ipv6);

    let mut expected = Vec::new();
    expected.extend(72u32.to_ne_bytes());
    expected.extend(20u16.to_ne_bytes());
    expected.extend(0x301u16.to_ne_bytes());
    expected.extend(1u32.to_ne_bytes());
    expected.extend(0u32.to_ne_bytes());
    expected.extend([10, 6, 0, 0]);
    expected.extend(0x400u32.to_ne_bytes());
    expected.resize(REQUEST_LEN, 0);
    assert_eq!(request.as_slice(), expected);
    assert_eq!(dump_request(AddressFamily::Ipv4)[HEADER_LEN], 2);
}

#[test]
fn a_datagram_without_done_asks_for_more() {
    let bytes = message(SOCK_DIAG_BY_FAMILY, &socket(AF_INET, 0, 7, &[]));

    assert_eq!(
        parse_dump(&bytes).unwrap(),
        Dump {
            sockets: vec![(7, options(None, false))],
            done: false,
        }
    );
}

#[test]
fn the_ipv6_only_flag_is_found_among_other_attributes() {
    let attributes = [attribute(8, &[0]), attribute(INET_DIAG_SKV6ONLY, &[1])].concat();
    let bytes = message(SOCK_DIAG_BY_FAMILY, &socket(AF_INET6, 4, 7, &attributes));

    assert_eq!(
        parse_dump(&bytes).unwrap().sockets,
        [(7, options(Some(4), true))]
    );
}

#[test]
fn an_ipv6_socket_without_its_flag_is_left_out() {
    let bytes = message(SOCK_DIAG_BY_FAMILY, &socket(AF_INET6, 0, 7, &[]));
    assert!(parse_dump(&bytes).unwrap().sockets.is_empty());
}

#[test]
fn messages_of_other_types_are_skipped() {
    let bytes = [message(1, &[]), done()].concat();
    assert_eq!(
        parse_dump(&bytes).unwrap(),
        Dump {
            sockets: Vec::new(),
            done: true,
        }
    );
}

#[test]
fn an_error_message_with_status_zero_is_only_an_acknowledgement() {
    let bytes = [message(NLMSG_ERROR, &0i32.to_ne_bytes()), done()].concat();
    assert!(parse_dump(&bytes).unwrap().done);
}

#[test]
fn a_negative_status_is_the_kernels_error_code() {
    for kind in [NLMSG_ERROR, NLMSG_DONE] {
        let bytes = message(kind, &(-13i32).to_ne_bytes());
        let Err(SockDiagError::Refused(error)) = parse_dump(&bytes) else {
            panic!("expected a refusal for message type {kind}");
        };
        assert_eq!(error.raw_os_error(), Some(13));
    }
}

#[test]
fn nothing_after_done_is_read() {
    let bytes = [done(), vec![0xff; 3]].concat();
    assert!(parse_dump(&bytes).unwrap().done);
}

#[test]
fn an_empty_datagram_is_malformed() {
    assert_malformed(&[]);
}

#[test]
fn a_message_cut_off_anywhere_is_malformed_never_a_panic() {
    let attributes = attribute(INET_DIAG_SKV6ONLY, &[1]);
    let bytes = message(SOCK_DIAG_BY_FAMILY, &socket(AF_INET6, 2, 7, &attributes));

    for len in 1..bytes.len() {
        assert_malformed(&bytes[..len]);
    }
}

#[test]
fn a_length_smaller_than_the_header_is_malformed() {
    let mut bytes = done();
    bytes[..4].copy_from_slice(&4u32.to_ne_bytes());
    assert_malformed(&bytes);
}

#[test]
fn a_length_beyond_the_datagram_is_malformed() {
    let mut bytes = done();
    bytes[..4].copy_from_slice(&u32::MAX.to_ne_bytes());
    assert_malformed(&bytes);
}

#[test]
fn a_socket_shorter_than_its_fixed_fields_is_malformed() {
    assert_malformed(&message(SOCK_DIAG_BY_FAMILY, &[AF_INET; 40]));
}

#[test]
fn an_attribute_with_an_impossible_length_is_malformed() {
    let zero_length = [0, 0, 0, 0];
    assert_malformed(&message(
        SOCK_DIAG_BY_FAMILY,
        &socket(AF_INET6, 0, 7, &zero_length),
    ));
}

#[test]
fn an_ipv6_only_attribute_without_a_value_is_malformed() {
    let attributes = attribute(INET_DIAG_SKV6ONLY, &[]);
    assert_malformed(&message(
        SOCK_DIAG_BY_FAMILY,
        &socket(AF_INET6, 0, 7, &attributes),
    ));
}

#[test]
fn a_status_without_its_number_is_malformed() {
    assert_malformed(&message(NLMSG_DONE, &[]));
}
