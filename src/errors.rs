use std::{error::Error, fmt};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::TrustedProxyRule;

/// An error returned while building a [`crate::ClientIpConfig`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientIpConfigBuildError {
    /// Trusted proxy CIDRs cover a common address but do not agree on the client IP header.
    ///
    /// One socket peer IP has to mean one policy, so the config cannot be built until the CIDRs are changed to agree or to stop overlapping.
    OverlappingTrustedProxyRules {
        /// The first of the two rules that overlap.
        left: Box<TrustedProxyRule>,

        /// The second of the two rules that overlap.
        right: Box<TrustedProxyRule>,
    },
}

impl fmt::Display for ClientIpConfigBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverlappingTrustedProxyRules {
                left,
                right,
            } => write!(
                f,
                "trusted proxy CIDRs overlap but use different client IP headers: {} ({}) \
                 overlaps {} ({})",
                left.cidr(),
                describe_client_ip_header(left),
                right.cidr(),
                describe_client_ip_header(right),
            ),
        }
    }
}

/// Name the client IP header of a rule, for an error message.
fn describe_client_ip_header(rule: &TrustedProxyRule) -> &str {
    match rule.client_ip_header() {
        Some(header) => header.as_str(),
        None => "no client IP header",
    }
}

impl Error for ClientIpConfigBuildError {}

/// The rejection returned by the [`crate::ClientIp`] extractor.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientIpRejection {
    /// The request carries no `ConnectInfo<SocketAddr>`.
    ///
    /// Start the server with `into_make_service_with_connect_info::<SocketAddr>()` so that `axum` records the address every connection came from.
    MissingConnectInfo,
}

impl fmt::Display for ClientIpRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConnectInfo => write!(
                f,
                "missing ConnectInfo<SocketAddr>; start axum with \
                 into_make_service_with_connect_info::<SocketAddr>()"
            ),
        }
    }
}

impl Error for ClientIpRejection {}

impl IntoResponse for ClientIpRejection {
    fn into_response(self) -> Response {
        // This is a server setup mistake, not a bad request, and the Display message names internal details, so the response body says nothing about it.
        match self {
            Self::MissingConnectInfo => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            },
        }
    }
}
