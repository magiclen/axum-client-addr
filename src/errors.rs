use std::{error::Error, fmt};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::TrustedProxyRule;

/// Error returned while building a [`crate::ClientIpConfig`].
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientIpConfigBuildError {
    /// Trusted proxy CIDRs cover a common address but do not agree on the client IP header.
    OverlappingTrustedProxyRules {
        /// The first overlapping trusted proxy rule.
        left: Box<TrustedProxyRule>,

        /// The second overlapping trusted proxy rule.
        right: Box<TrustedProxyRule>,
    },
}

impl fmt::Display for ClientIpConfigBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientIpConfigBuildError::OverlappingTrustedProxyRules {
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

/// Describe the client IP header of a rule for an error message.
fn describe_client_ip_header(rule: &TrustedProxyRule) -> &str {
    match rule.client_ip_header() {
        Some(header) => header.as_str(),
        None => "no client IP header",
    }
}

impl Error for ClientIpConfigBuildError {}

/// Rejection returned by the [`crate::ClientIp`] extractor.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientIpRejection {
    /// The request does not contain Axum connection information.
    MissingConnectInfo,
}

impl fmt::Display for ClientIpRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientIpRejection::MissingConnectInfo => write!(
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
        // The Display message names internal setup details, so it is kept out of the response body.
        match self {
            ClientIpRejection::MissingConnectInfo => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            },
        }
    }
}
