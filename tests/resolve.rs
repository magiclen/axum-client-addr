use std::net::IpAddr;

use axum::http::{HeaderMap, HeaderValue};
use axum_client_addr::{
    ChainHeader, ClientIpConfig, ClientIpSource, HeaderName, IpCidr, TrustAllChainIpSelection,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

fn chain_header_source(name: &'static str) -> ClientIpSource {
    ClientIpSource::ChainHeader(HeaderName::from_static(name))
}

#[test]
fn untrusted_socket_uses_socket_ip() {
    let config = ClientIpConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn trusted_proxy_uses_configured_client_ip_header() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(
        &ClientIpSource::ConfiguredHeader(HeaderName::from_static("x-real-ip")),
        client_ip.source(),
    );
}

#[test]
fn configured_client_ip_header_uses_the_last_value() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    // A client may send its own value, and a proxy that appends puts the trusted value after it.
    headers.append("x-real-ip", HeaderValue::from_static("203.0.113.10"));
    headers.append("x-real-ip", HeaderValue::from_static("198.51.100.7"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("198.51.100.7"), client_ip.ip());
}

#[test]
fn configured_client_ip_header_ignores_an_invalid_last_value() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .disable_chain_headers()
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    // The proxy appends after the client, so an unusable proxy value must not let the client value win.
    headers.append("x-real-ip", HeaderValue::from_static("203.0.113.10"));
    headers.append("x-real-ip", HeaderValue::from_static("not-an-ip"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn ipv4_mapped_socket_peer_matches_an_ipv4_trusted_proxy() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.10"));

    // A dual-stack listener reports an IPv4 peer in this form.
    let client_ip = config.resolve_client_ip(&headers, ip("::ffff:10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(
        &ClientIpSource::ConfiguredHeader(HeaderName::from_static("x-real-ip")),
        client_ip.source(),
    );
}

#[test]
fn trusted_proxy_scans_x_forwarded_for_from_the_right() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("198.51.100.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.10, 198.51.100.7, 10.0.0.2"),
    );

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn x_forwarded_for_lines_are_scanned_as_one_chain() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("198.51.100.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    // Several lines of the same header are one list, joined in the order they arrived.
    headers.append("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7, 10.0.0.2"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn trusted_proxy_falls_back_to_socket_when_every_hop_is_trusted() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.5, 10.0.0.2"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn ipv4_mapped_chain_hops_are_normalized() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("::ffff:203.0.113.10, ::ffff:10.0.0.5"),
    );

    // The rightmost hop is a trusted proxy in its IPv4 form, so the scan walks past it.
    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn trusted_proxy_reads_forwarded_header() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        HeaderValue::from_static(r#"for="[2001:db8::17]:4711";proto=https, for=10.0.0.2"#),
    );

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("2001:db8::17"), client_ip.ip());
    assert_eq!(&chain_header_source("forwarded"), client_ip.source());
}

#[test]
fn custom_chain_order_changes_header_priority() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .chain_header_order([ChainHeader::forwarded(), ChainHeader::x_forwarded_for()])
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    headers.insert("forwarded", HeaderValue::from_static("for=198.51.100.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("198.51.100.10"), client_ip.ip());
    assert_eq!(&chain_header_source("forwarded"), client_ip.source());
}

#[test]
fn trusted_proxy_stops_at_an_opaque_hop() {
    let config =
        ClientIpConfig::builder().trusted_proxies().proxy(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10, unknown, 10.0.0.2"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn trusted_proxy_disable_chain_headers_falls_back_to_socket() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .disable_chain_headers()
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn trust_all_defaults_to_rightmost_x_forwarded_for() {
    let config = ClientIpConfig::builder().trust_all_proxies().build();
    let mut headers = HeaderMap::new();
    // A client can write anything on the left, but the proxy appends the address it saw.
    headers.insert("x-forwarded-for", HeaderValue::from_static("9.9.9.9, 203.0.113.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn trust_all_can_select_the_leftmost_hop() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10, 198.51.100.7"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn trust_all_can_skip_rightmost_hops() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_ip_selection(TrustAllChainIpSelection::SkipRightmostHops(1))
        .build();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.10, 198.51.100.7, 10.0.0.2"),
    );

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("198.51.100.7"), client_ip.ip());
    assert_eq!(&chain_header_source("x-forwarded-for"), client_ip.source());
}

#[test]
fn trust_all_skips_a_chain_header_with_an_opaque_selected_hop() {
    let config = ClientIpConfig::builder().trust_all_proxies().build();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10, unknown"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn trust_all_uses_custom_single_ip_header() {
    let header = HeaderName::from_static("x-client-ip");
    let config =
        ClientIpConfig::builder().trust_all_proxies().client_ip_header(header.clone()).build();
    let mut headers = HeaderMap::new();
    headers.insert(header.clone(), HeaderValue::from_static("203.0.113.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader(header), client_ip.source());
}

#[test]
fn trust_all_can_use_custom_list_header() {
    let header = HeaderName::from_static("x-client-chain");
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_header_order([ChainHeader::new(header.clone())])
        .build();
    let mut headers = HeaderMap::new();
    headers.insert(header.clone(), HeaderValue::from_static("203.0.113.10, 198.51.100.10"));

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("198.51.100.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ChainHeader(header), client_ip.source());
}

#[test]
fn chain_header_new_forwarded_uses_standard_parser() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .chain_header_order([ChainHeader::new(HeaderName::from_static("forwarded"))])
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build();
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        HeaderValue::from_static(r#"for="[2001:db8::17]:4711";proto=https, for=198.51.100.10"#),
    );

    let client_ip = config.resolve_client_ip(&headers, ip("10.0.0.2"));

    assert_eq!(ip("2001:db8::17"), client_ip.ip());
    assert_eq!(&chain_header_source("forwarded"), client_ip.source());
}
