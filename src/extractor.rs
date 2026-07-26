use std::{
    convert::Infallible,
    fmt,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts, OptionalFromRequestParts},
    http::{HeaderName, request::Parts},
};

use crate::{
    ClientIpConfigSource,
    ClientIpRejection::{self, MissingConnectInfo},
};

/// The resolved client IP, and where it came from.
///
/// This is an `axum` extractor. It needs `ConnectInfo<SocketAddr>` in the request, which `axum` adds when the server is started with `into_make_service_with_connect_info::<SocketAddr>()`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ClientIp {
    ip:     IpAddr,
    source: ClientIpSource,
}

impl ClientIp {
    #[inline]
    pub(crate) const fn new(ip: IpAddr, source: ClientIpSource) -> Self {
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
    ///
    /// Use this to tell a header value apart from the socket peer IP, for example when logging.
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

/// Where a [`ClientIp`] came from.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ClientIpSource {
    /// The client IP header of a trusted proxy, such as `X-Real-IP`.
    ///
    /// The name inside is the header that gave the address.
    ConfiguredHeader(HeaderName),

    /// One hop of a chain header, such as `X-Forwarded-For` or `Forwarded`.
    ///
    /// The name inside is the header that gave the address.
    ChainHeader(HeaderName),

    /// The socket peer IP, which is the address the connection came from.
    ///
    /// This is the answer whenever no header is trusted enough to change it.
    Socket,
}

impl ClientIpSource {
    /// Return the header that gave the address, or [`None`] for [`Self::Socket`].
    #[inline]
    pub const fn header_name(&self) -> Option<&HeaderName> {
        match self {
            Self::ConfiguredHeader(header) | Self::ChainHeader(header) => Some(header),
            Self::Socket => None,
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

impl<S> OptionalFromRequestParts<S> for ClientIp
where
    S: Send + Sync + ClientIpConfigSource,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        // Every answer falls back to the socket peer IP, so without one there is no address to report at all. That means the extractor does not apply to this request, which is why it reports None instead of an error.
        let Ok(ConnectInfo(socket_addr)) =
            <ConnectInfo<SocketAddr> as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
        else {
            return Ok(None);
        };

        Ok(Some(state.client_ip_config().resolve_client_ip(&parts.headers, socket_addr.ip())))
    }
}
