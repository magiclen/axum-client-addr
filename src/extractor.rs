use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, request::Parts},
};

use crate::{
    ChainHeader, ClientIpConfig, ClientIpConfigSource,
    ClientIpRejection::{self, MissingConnectInfo},
    TrustAllChainIpSelection, TrustAllProxyMode,
    config::ChainHeaderKind,
    headers::{ChainEntry, configured_client_ip_header, forwarded_entries, list_header_entries},
};

/// The resolved client IP and the source that produced it.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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

    /// Consume this value and return the client IP and its source.
    #[inline]
    pub fn into_parts(self) -> (IpAddr, ClientIpSource) {
        (self.ip, self.source)
    }
}

impl fmt::Display for ClientIp {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.ip, f)
    }
}

impl From<ClientIp> for IpAddr {
    #[inline]
    fn from(client_ip: ClientIp) -> Self {
        client_ip.ip
    }
}

/// The data source used to resolve a [`ClientIp`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
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
    let mut entries = Vec::new();

    // This path only runs in CIDR mode, so read the field directly instead of the mode-aware getter.
    for chain_header in &config.chain_header_order {
        chain_header_entries(headers, chain_header, &mut entries);

        // Scan from the socket side toward the original client.
        let Some(ip) = first_non_trusted_from_right(&entries, config) else {
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
    let mut entries = Vec::new();

    for chain_header in mode.chain_header_order() {
        chain_header_entries(headers, chain_header, &mut entries);

        let Some(ip) = select_trust_all_chain_ip(&entries, mode.chain_ip_selection()) else {
            continue;
        };

        return Some((ip, chain_header_source(chain_header)));
    }

    None
}

fn chain_header_entries(
    headers: &HeaderMap,
    chain_header: &ChainHeader,
    entries: &mut Vec<ChainEntry>,
) {
    entries.clear();

    let header = chain_header.as_header_name();

    match chain_header.kind() {
        ChainHeaderKind::Forwarded => forwarded_entries(headers, header, entries),
        ChainHeaderKind::XForwardedFor | ChainHeaderKind::List => {
            list_header_entries(headers, header, entries)
        },
    }
}

fn chain_header_source(chain_header: &ChainHeader) -> ClientIpSource {
    match chain_header.kind() {
        ChainHeaderKind::XForwardedFor => ClientIpSource::XForwardedFor,
        ChainHeaderKind::Forwarded => ClientIpSource::Forwarded,
        ChainHeaderKind::List => ClientIpSource::List(chain_header.as_header_name().clone()),
    }
}

fn select_trust_all_chain_ip(
    entries: &[ChainEntry],
    selection: TrustAllChainIpSelection,
) -> Option<IpAddr> {
    let entry = match selection {
        TrustAllChainIpSelection::Leftmost => entries.first(),
        TrustAllChainIpSelection::Rightmost => entries.last(),
    }?;

    match entry {
        ChainEntry::Ip(ip) => Some(*ip),
        ChainEntry::Opaque => None,
    }
}

#[inline]
fn first_non_trusted_from_right(entries: &[ChainEntry], config: &ClientIpConfig) -> Option<IpAddr> {
    for entry in entries.iter().rev() {
        match entry {
            // Keep walking left past hops that are known trusted proxies.
            ChainEntry::Ip(ip) if config.is_trusted_proxy(*ip) => continue,
            ChainEntry::Ip(ip) => return Some(*ip),
            // This hop cannot be checked against the trusted proxy rules, so nothing further left can be trusted either.
            ChainEntry::Opaque => return None,
        }
    }

    None
}
