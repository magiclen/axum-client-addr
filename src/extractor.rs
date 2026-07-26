use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, HeaderName, request::Parts},
};

use crate::{
    ChainHeader, ClientIpConfig, ClientIpConfigSource,
    ClientIpRejection::{self, MissingConnectInfo},
    TrustAllChainIpSelection, TrustAllProxyMode,
    config::{ChainHeaderKind, TrustModel},
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
    /// The single-IP header of a trusted proxy, such as `X-Real-IP`.
    ///
    /// The contained name is the header that provided the IP.
    ConfiguredHeader(HeaderName),

    /// One hop of a chain header, such as `X-Forwarded-For` or `Forwarded`.
    ///
    /// The contained name is the header that provided the IP.
    ChainHeader(HeaderName),

    /// The socket peer IP address.
    Socket,
}

impl ClientIpSource {
    /// Return the header that provided the IP, or `None` for [`Self::Socket`].
    #[inline]
    pub const fn header_name(&self) -> Option<&HeaderName> {
        match self {
            ClientIpSource::ConfiguredHeader(header) | ClientIpSource::ChainHeader(header) => {
                Some(header)
            },
            ClientIpSource::Socket => None,
        }
    }
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

        Ok(state.client_ip_config().resolve_client_ip(&parts.headers, socket_addr.ip()))
    }
}

impl ClientIpConfig {
    /// Resolve the client IP of a request from its headers and its socket peer IP.
    ///
    /// Use this when the request does not come from `axum`, or when the [`ClientIp`] extractor is not convenient. See the crate-level docs for the full resolution order.
    pub fn resolve_client_ip(&self, headers: &HeaderMap, peer_ip: IpAddr) -> ClientIp {
        match &self.trust {
            TrustModel::NoProxy => ClientIp::new(peer_ip, ClientIpSource::Socket),
            TrustModel::TrustedProxies {
                chain_header_order, ..
            } => resolve_client_ip_from_trusted_proxies(headers, peer_ip, self, chain_header_order),
            TrustModel::TrustAllProxies(mode) => {
                resolve_client_ip_trusting_all_proxies(headers, peer_ip, mode)
            },
        }
    }
}

fn resolve_client_ip_from_trusted_proxies(
    headers: &HeaderMap,
    socket_ip: IpAddr,
    config: &ClientIpConfig,
    chain_header_order: &[ChainHeader],
) -> ClientIp {
    let Some(socket_proxy_rule) = config.rule_for(socket_ip) else {
        return ClientIp::new(socket_ip, ClientIpSource::Socket);
    };

    if let Some(header) = socket_proxy_rule.client_ip_header() {
        if let Some(ip) = configured_client_ip_header(headers, header) {
            return ClientIp::new(ip, ClientIpSource::ConfiguredHeader(header.clone()));
        }
    }

    if let Some((ip, source)) = client_ip_from_chain_headers(headers, config, chain_header_order) {
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
    chain_header_order: &[ChainHeader],
) -> Option<(IpAddr, ClientIpSource)> {
    let mut entries = Vec::new();

    for chain_header in chain_header_order {
        chain_header_entries(headers, chain_header, &mut entries);

        // Scan from the socket side toward the original client.
        let Some(ip) = first_non_trusted_from_right(&entries, config) else {
            continue;
        };

        return Some((ip, ClientIpSource::ChainHeader(chain_header.as_header_name().clone())));
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

        return Some((ip, ClientIpSource::ChainHeader(chain_header.as_header_name().clone())));
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

fn select_trust_all_chain_ip(
    entries: &[ChainEntry],
    selection: TrustAllChainIpSelection,
) -> Option<IpAddr> {
    let entry = match selection {
        TrustAllChainIpSelection::Leftmost => entries.first(),
        TrustAllChainIpSelection::Rightmost => entries.last(),
        // Counting is positional, so a hop without a usable IP address still takes one place.
        TrustAllChainIpSelection::SkipRightmostHops(hops) => entries.iter().rev().nth(hops),
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
