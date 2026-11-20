use std::net::{IpAddr, Ipv6Addr};

use crate::network::HostAddress;

use super::{Coverage, Reason, Verdict, classify, classify_covered};

/// Classify a Docker binding when no host socket supplies the scope.
pub(crate) fn classify_publish(address: IpAddr, host: Option<&[HostAddress]>) -> Verdict {
    if address != IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
        return classify(address, None, host);
    }
    let Some(host) = host else {
        return Verdict::unknown(Reason::InterfacesUnknown);
    };
    let covers = Coverage::Ipv6;
    // Docker reports a separate binding for IPv4. There is no socket to check.
    classify_covered(
        covers,
        None,
        host,
        Reason::AllAddresses {
            covers,
            checked: false,
        },
    )
}
