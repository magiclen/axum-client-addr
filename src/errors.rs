use std::{error::Error, fmt};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::TrustedProxyRule;

/// Error returned while building a [`crate::ClientIpConfig`].
#[derive(Debug)]
pub enum ClientIpConfigBuildError {
    /// CIDRs overlap but carry different metadata.
    OverlappingTrustedProxyMetadata {
        /// The first overlapping trusted proxy rule.
        left: Box<TrustedProxyRule>,

        /// The second overlapping trusted proxy rule.
        right: Box<TrustedProxyRule>,
    },

    /// Trust-all proxy mode cannot be combined with CIDR proxy rules.
    TrustAllProxyModeWithTrustedProxyRules,
}

impl fmt::Display for ClientIpConfigBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientIpConfigBuildError::OverlappingTrustedProxyMetadata {
                left,
                right,
            } => write!(
                f,
                "trusted proxy CIDRs overlap but have different metadata: {} {:?} overlaps {} {:?}",
                left.cidr(),
                left.metadata(),
                right.cidr(),
                right.metadata(),
            ),

            ClientIpConfigBuildError::TrustAllProxyModeWithTrustedProxyRules => {
                write!(f, "trust-all proxy mode cannot be combined with trusted proxy CIDR rules")
            },
        }
    }
}

impl Error for ClientIpConfigBuildError {}

/// Rejection returned by the [`crate::ClientIp`] extractor.
#[derive(Debug)]
pub enum ClientIpRejection {
    /// The request does not contain Axum connection information.
    MissingConnectInfo,
}

impl IntoResponse for ClientIpRejection {
    fn into_response(self) -> Response {
        match self {
            ClientIpRejection::MissingConnectInfo => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "missing ConnectInfo<SocketAddr>; start axum with \
                 into_make_service_with_connect_info::<SocketAddr>()",
            )
                .into_response(),
        }
    }
}
