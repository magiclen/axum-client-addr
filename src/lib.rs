/*!
# Client's IP Address Extractor for axum Framework

Resolve client IP addresses in `axum` from trusted proxy headers with safe socket fallback.

By default, this crate does not trust any proxy header and returns the socket peer IP from `ConnectInfo`. When CIDR trusted proxies are configured, it first checks whether the socket peer is in a trusted proxy range.

If it is trusted, a configured single-IP header, such as `X-Real-IP`, is read first. If that header is missing or invalid, the configured chain headers are checked in order, such as `X-Forwarded-For` or `Forwarded`.

In trust-all mode, every socket peer is treated as trusted and the same header order is used without a CIDR check.

If no trusted header gives a valid IP, the resolver falls back to the socket peer IP.

## Example

```rust,no_run
use std::net::SocketAddr;

use axum::{Router, http::HeaderName, routing::get};
use axum_client_addr::{ClientIp, ClientIpConfig, IpCidr};

#[tokio::main]
async fn main() {
    let config = ClientIpConfig::builder()
        // Trust this proxy range and read X-Real-IP only when the socket peer is inside it.
        .proxy_with_client_ip_header(
            "10.0.0.0/24".parse::<IpCidr>().unwrap(),
            HeaderName::from_static("x-real-ip"),
        )
        .build()
        .unwrap();

    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}
```
*/

mod cidr_merge;
mod config;
mod errors;
mod extractor;
mod headers;

pub use cidr::IpCidr;
pub use config::{
    ChainHeader, ClientIpConfig, ClientIpConfigBuilder, ClientIpConfigSource,
    TrustAllChainIpSelection, TrustAllProxyMode, TrustedProxyMetadata, TrustedProxyRule,
};
pub use errors::{ClientIpConfigBuildError, ClientIpRejection};
pub use extractor::{ClientIp, ClientIpSource, resolve_client_ip};
