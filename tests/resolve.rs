use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use axum_client_addr::{
    ChainHeader, ClientIpConfig, ClientIpSource, IpCidr, TrustAllChainIpSelection,
    resolve_client_ip,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

fn socket(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 12345)
}

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

#[test]
fn untrusted_socket_uses_socket_ip() {
    let config = ClientIpConfig::default();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("10.0.0.2"), client_ip.ip());
    assert_eq!(&ClientIpSource::Socket, client_ip.source());
}

#[test]
fn trusted_proxy_uses_configured_client_ip_header() {
    let config =
        ClientIpConfig::builder().proxy_with_x_real_ip(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.10"));

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(
        &ClientIpSource::ConfiguredHeader(HeaderName::from_static("x-real-ip")),
        client_ip.source(),
    );
}

#[test]
fn trusted_proxy_scans_x_forwarded_for_from_the_right() {
    let config = ClientIpConfig::builder()
        .proxy(cidr("10.0.0.0/24"))
        .proxy(cidr("198.51.100.0/24"))
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.10, 198.51.100.7, 10.0.0.2"),
    );

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::XForwardedFor, client_ip.source());
}

#[test]
fn trusted_proxy_reads_forwarded_header() {
    let config = ClientIpConfig::builder().proxy(cidr("10.0.0.0/24")).build().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        HeaderValue::from_static(r#"for="[2001:db8::17]:4711";proto=https, for=10.0.0.2"#),
    );

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("2001:db8::17"), client_ip.ip());
    assert_eq!(&ClientIpSource::Forwarded, client_ip.source());
}

#[test]
fn custom_chain_order_changes_header_priority() {
    let config = ClientIpConfig::builder()
        .proxy(cidr("10.0.0.0/24"))
        .chain_header_order([ChainHeader::forwarded(), ChainHeader::x_forwarded_for()])
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.10"));
    headers.insert("forwarded", HeaderValue::from_static("for=198.51.100.10"));

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("198.51.100.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::Forwarded, client_ip.source());
}

#[test]
fn trust_all_uses_custom_single_ip_header() {
    let header = HeaderName::from_static("x-client-ip");
    let config = ClientIpConfig::builder()
        .trust_all_proxies_with_client_ip_header(header.clone())
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header.clone(), HeaderValue::from_static("203.0.113.10"));

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader(header), client_ip.source());
}

#[test]
fn trust_all_can_use_custom_list_header_rightmost() {
    let header = HeaderName::from_static("x-client-chain");
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .trust_all_chain_header_order([ChainHeader::new(header.clone())])
        .trust_all_chain_ip_selection(TrustAllChainIpSelection::Rightmost)
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(header.clone(), HeaderValue::from_static("203.0.113.10, 198.51.100.10"));

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("198.51.100.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::List(header), client_ip.source());
}

#[test]
fn chain_header_new_forwarded_uses_standard_parser() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .trust_all_chain_header_order([ChainHeader::new(HeaderName::from_static("forwarded"))])
        .build()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "forwarded",
        HeaderValue::from_static(r#"for="[2001:db8::17]:4711";proto=https, for=198.51.100.10"#),
    );

    let client_ip = resolve_client_ip(&headers, socket("10.0.0.2"), &config);

    assert_eq!(ip("2001:db8::17"), client_ip.ip());
    assert_eq!(&ClientIpSource::Forwarded, client_ip.source());
}
