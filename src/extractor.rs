use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::{
    ChainHeader, ClientIpConfig, ClientIpConfigSource,
    ClientIpRejection::{self, MissingConnectInfo},
    TrustAllChainIpSelection, TrustAllProxyMode,
    headers::{configured_client_ip_header, forwarded_ips, list_header_ips, x_forwarded_for_ips},
};

/// The resolved client IP and the source that produced it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIp {
    ip:     IpAddr,
    source: ClientIpSource,
}

impl ClientIp {
    #[inline]
    const fn new(ip: IpAddr, source: ClientIpSource) -> Self {
        Self {
            ip,
            source,
        }
    }

    /// Return the resolved client IP.
    #[inline]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Return where the client IP came from.
    #[inline]
    pub const fn source(&self) -> &ClientIpSource {
        &self.source
    }
}

/// The data source used to resolve a [`ClientIp`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientIpSource {
    /// The configured client IP header for the matched trusted proxy.
    ///
    /// This means the socket peer matched a trusted proxy rule that names this header, and the header contained a plain IP address.
    ConfiguredHeader(axum::http::HeaderName),

    /// The `X-Forwarded-For` header.
    XForwardedFor,

    /// The standard `Forwarded` header.
    Forwarded,

    /// A custom comma-separated IP list header.
    ///
    /// The contained header name is the source header that provided the IP.
    List(axum::http::HeaderName),

    /// The socket peer IP address.
    Socket,
}

impl<S> FromRequestParts<S> for ClientIp
where
    S: Send + Sync + ClientIpConfigSource,
{
    type Rejection = ClientIpRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ConnectInfo(socket_addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| MissingConnectInfo)?;

        Ok(resolve_client_ip(&parts.headers, socket_addr, state.client_ip_config()))
    }
}

/// Resolve the client IP from request headers, socket address, and config.
///
/// See the crate-level docs for the full resolution order.
#[inline]
pub fn resolve_client_ip(
    headers: &HeaderMap,
    socket_addr: SocketAddr,
    config: &ClientIpConfig,
) -> ClientIp {
    let socket_ip = socket_addr.ip();

    if let Some(mode) = config.trust_all_proxy_mode() {
        return resolve_client_ip_trusting_all_proxies(headers, socket_ip, mode);
    }

    let Some(socket_proxy_rule) = config.rule_for(socket_ip) else {
        return ClientIp::new(socket_ip, ClientIpSource::Socket);
    };

    if let Some(header) = socket_proxy_rule.client_ip_header() {
        if let Some(ip) = configured_client_ip_header(headers, header) {
            return ClientIp::new(ip, ClientIpSource::ConfiguredHeader(header.clone()));
        }
    }

    if let Some((ip, source)) = client_ip_from_chain_headers(headers, config) {
        return ClientIp::new(ip, source);
    }

    ClientIp::new(socket_ip, ClientIpSource::Socket)
}

fn resolve_client_ip_trusting_all_proxies(
    headers: &HeaderMap,
    socket_ip: IpAddr,
    mode: &TrustAllProxyMode,
) -> ClientIp {
    if let Some(header) = mode.client_ip_header() {
        if let Some(ip) = configured_client_ip_header(headers, header) {
            return ClientIp::new(ip, ClientIpSource::ConfiguredHeader(header.clone()));
        }
    }

    if let Some((ip, source)) = client_ip_from_trust_all_chain_headers(headers, mode) {
        return ClientIp::new(ip, source);
    }

    ClientIp::new(socket_ip, ClientIpSource::Socket)
}

fn client_ip_from_chain_headers(
    headers: &HeaderMap,
    config: &ClientIpConfig,
) -> Option<(IpAddr, ClientIpSource)> {
    for chain_header in config.chain_header_order() {
        let ips = chain_header_ips(headers, chain_header);

        // Scan from the socket side toward the original client.
        let Some(ip) = first_non_trusted_from_right(&ips, config) else {
            continue;
        };

        return Some((ip, chain_header_source(chain_header)));
    }

    None
}

fn client_ip_from_trust_all_chain_headers(
    headers: &HeaderMap,
    mode: &TrustAllProxyMode,
) -> Option<(IpAddr, ClientIpSource)> {
    for chain_header in mode.chain_header_order() {
        let ips = chain_header_ips(headers, chain_header);
        let Some(ip) = select_trust_all_chain_ip(&ips, mode.chain_ip_selection()) else {
            continue;
        };

        return Some((ip, chain_header_source(chain_header)));
    }

    None
}

fn chain_header_ips(headers: &HeaderMap, chain_header: &ChainHeader) -> Vec<IpAddr> {
    match chain_header.as_header_name().as_str() {
        "x-forwarded-for" => x_forwarded_for_ips(headers),
        "forwarded" => forwarded_ips(headers),
        _ => list_header_ips(headers, chain_header.as_header_name()),
    }
}

fn chain_header_source(chain_header: &ChainHeader) -> ClientIpSource {
    let header = chain_header.as_header_name();

    match header.as_str() {
        "x-forwarded-for" => ClientIpSource::XForwardedFor,
        "forwarded" => ClientIpSource::Forwarded,
        _ => ClientIpSource::List(header.clone()),
    }
}

fn select_trust_all_chain_ip(
    ips: &[IpAddr],
    selection: TrustAllChainIpSelection,
) -> Option<IpAddr> {
    match selection {
        TrustAllChainIpSelection::Leftmost => ips.first().copied(),
        TrustAllChainIpSelection::Rightmost => ips.last().copied(),
    }
}

#[inline]
fn first_non_trusted_from_right(ips: &[IpAddr], config: &ClientIpConfig) -> Option<IpAddr> {
    ips.iter().rev().copied().find(|ip| !config.is_trusted_proxy(*ip))
}
