/*!
# Client's IP Address Extractor for axum Framework

Resolve client IP addresses in `axum` from trusted proxy headers with safe socket fallback.

The [`ClientIp`] extractor reads a [`ClientIpConfig`] from the application state. The config decides how much of a request is allowed to influence the answer, and it always falls back to the socket peer IP that `axum` stores in `ConnectInfo`.

## The forwarding chain

`X-Forwarded-For` is a comma-separated list, and each proxy along the path appends the address it received the request from. Take a client at `203.0.113.10` that reaches the service through two proxies.

```text
203.0.113.10  ->  198.51.100.7  ->  10.0.0.2  ->  service
   client            proxy 1         proxy 2
```

The service then sees this request.

```text
X-Forwarded-For: 203.0.113.10, 198.51.100.7
socket peer: 10.0.0.2
```

* The **leftmost** value is the oldest hop. It is the original client if every proxy on the path appended honestly, but it is also the part a client can write freely, because the first proxy appends to whatever the client sent instead of replacing it.
* The **rightmost** value is the newest hop, written by the proxy closest to the service. It is the address that proxy received the request from.
* The **socket peer IP is not in the header**. It belongs to the proxy that opened the connection, so the full path is the header values followed by the socket peer.

Every hop is only as trustworthy as the proxy that wrote it. The rightmost value came from the proxy in front of the service, so it is the one entry in the list that no client can choose. Everything further left was copied from what an earlier hop claimed.

`Forwarded` (RFC 7239) carries the same chain in a different syntax, with the same left-to-right meaning.

```text
Forwarded: for=203.0.113.10, for=198.51.100.7
```

`X-Forwarded-For` is read as a comma-separated IP list, `Forwarded` is read with the standard RFC 7239 syntax, and any other header name added through [`ChainHeader::new`] is read as a comma-separated IP list. A hop may carry a port, and an IPv6 hop may be bracketed, so `192.0.2.43:47011` and `[2001:db8::17]:4711` both work. A header value that is not valid UTF-8 hides an unknown number of hops, so that whole chain header is skipped and the next one is tried.

IPv4-mapped IPv6 addresses, such as `::ffff:203.0.113.10`, are normalized to their IPv4 form. This covers the socket peer IP as well as every header value, so a service on a dual-stack listener still matches trusted proxy CIDRs that are written in IPv4 form, and one client always resolves to one address.

## Trust models

A config uses exactly one trust model, chosen as the first step of [`ClientIpConfig::builder`].

### Trust no proxy

```rust
use axum_client_addr::ClientIpConfig;

let config = ClientIpConfig::builder().trust_no_proxy();
```

No header is read. Every request resolves to the socket peer IP. This is also what [`ClientIpConfig::default`] gives you.

### Trusted proxies

```rust
use axum_client_addr::{ClientIpConfig, IpCidr};

let config = ClientIpConfig::builder()
    .trusted_proxies()
    .proxy_with_x_real_ip("10.0.0.0/24".parse::<IpCidr>().unwrap())
    .build()
    .unwrap();
```

Headers are read only when the socket peer IP falls inside one of the trusted CIDRs. Use this whenever the proxy addresses are known, because a direct client can never make the service read its own forwarding headers.

Resolution runs in this order.

1. If the socket peer IP matches no trusted proxy rule, the socket peer IP is the answer.
2. If the matched rule names a client IP header, such as `X-Real-IP`, and that header holds a plain IP address, that address is the answer.
3. Otherwise each chain header is tried in the configured order, `X-Forwarded-For` then `Forwarded` by default.
4. Otherwise the socket peer IP is the answer.

A chain header is scanned from the socket side toward the original client, and the first hop that is not itself a trusted proxy becomes the client IP. A hop that carries no usable IP address, such as `unknown` or an RFC 7239 obfuscated identifier, ends the scan of that header, because it cannot be checked against the trusted proxy rules. The next chain header is then tried.

### Trust all proxies

```rust
use axum_client_addr::{ClientIpConfig, HeaderName};

let config = ClientIpConfig::builder()
    .trust_all_proxies()
    .client_ip_header(HeaderName::from_static("x-real-ip"))
    .build();
```

Every socket peer is treated as a trusted proxy. Use this only when the service can never be reached directly, because any client that can open a connection can then choose its own address.

Resolution runs in this order.

1. If a client IP header is configured and holds a plain IP address, that address is the answer.
2. Otherwise each chain header is tried in the configured order, and one hop is picked by [`TrustAllChainIpSelection`].
3. Otherwise the socket peer IP is the answer.

There is no CIDR check here, so the chain is not scanned. If the picked hop carries no usable IP address, or the chain is shorter than the selection needs, the next chain header is tried.

## A worked example

The example below resolves the request from the diagram above without running a server.

```rust
use std::net::IpAddr;

use axum_client_addr::{ClientIpConfig, ClientIpSource, HeaderMap, HeaderName, IpCidr};

let config = ClientIpConfig::builder()
    .trusted_proxies()
    .proxy("10.0.0.0/24".parse::<IpCidr>().unwrap())
    .proxy("198.51.100.0/24".parse::<IpCidr>().unwrap())
    .build()
    .unwrap();

let mut headers = HeaderMap::new();
headers.insert("x-forwarded-for", "203.0.113.10, 198.51.100.7".parse().unwrap());

// The socket peer 10.0.0.2 is trusted, so the chain is scanned from the right.
// 198.51.100.7 is a trusted proxy too, so the scan walks past it.
let client_ip = config.resolve_client_ip(&headers, "10.0.0.2".parse::<IpAddr>().unwrap());

assert_eq!("203.0.113.10".parse::<IpAddr>().unwrap(), client_ip.ip());
assert_eq!(&ClientIpSource::ChainHeader(HeaderName::from_static("x-forwarded-for")), client_ip.source());
```

## Using the extractor

```rust,no_run
use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_addr::{ClientIp, ClientIpConfig, IpCidr};

#[tokio::main]
async fn main() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        // Trust this proxy range and read X-Real-IP only when the socket peer is inside it.
        .proxy_with_x_real_ip("10.0.0.0/24".parse::<IpCidr>().unwrap())
        .build()
        .unwrap();

    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    // ClientIp needs ConnectInfo<SocketAddr>, which this call adds to every request.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}
```

Any state that implements [`ClientIpConfigSource`] works, so the config can live next to the rest of your application state. `Arc<T>` forwards to the inner state, and [`ClientIpConfig`] itself is a valid state.

## Security notes

* A client IP header only means something if the proxy always overwrites it. If the proxy appends instead, the last value wins, because that is the one the client could not write.
* A trusted proxy rule that names a client IP header still falls back to the chain headers when that header is missing, so the proxy should also clear the chain headers it does not set itself. Use `disable_chain_headers` if it cannot.
* In trust-all mode, [`TrustAllChainIpSelection::Leftmost`] returns the part of the chain that a client can write freely. It is safe only when the proxy overwrites the whole header.
*/

mod cidr_merge;
mod config;
mod errors;
mod extractor;
mod headers;

pub use axum::http::{HeaderMap, HeaderName};
pub use cidr::IpCidr;
pub use config::{
    ChainHeader, ClientIpConfig, ClientIpConfigBuilder, ClientIpConfigSource,
    TrustAllChainIpSelection, TrustAllProxiesBuilder, TrustAllProxyMode, TrustedProxiesBuilder,
    TrustedProxyRule,
};
pub use errors::{ClientIpConfigBuildError, ClientIpRejection};
pub use extractor::{ClientIp, ClientIpSource};
