use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_addr::{
    ChainHeader, ClientIp, ClientIpConfig, HeaderName, TrustAllChainIpSelection,
};

#[tokio::main]
async fn main() {
    // Use this setup only when the Rust service cannot be reached directly by clients. For example, the service may listen on a private network and all public traffic must pass through Nginx first.
    //
    // Trust-all mode treats every socket peer as a trusted proxy. That is useful when Nginx is always in front of the service, but its IP address is not stable or not known ahead of time.
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        // X-Real-IP is a single-IP header. If it is present and contains a plain IP address, it wins before any chain header is checked.
        .client_ip_header(HeaderName::from_static("x-real-ip"))
        // X-Forwarded-For is a comma-separated list header.
        .chain_header_order([ChainHeader::x_forwarded_for()])
        // Rightmost is the default, and it is the safe choice here. A client can write anything on the left of X-Forwarded-For, but a proxy that appends always writes the address it received the request from. Use Leftmost only when Nginx overwrites the whole header instead of appending to it.
        .chain_ip_selection(TrustAllChainIpSelection::Rightmost)
        .build();

    // A direct client could spoof X-Real-IP or X-Forwarded-For in this mode. Keep this server behind Nginx, and make Nginx clear or overwrite these headers before forwarding the request.
    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    // The source will usually be ConfiguredHeader("x-real-ip"). If X-Real-IP is missing or invalid, it can become ChainHeader("x-forwarded-for") instead.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source(),)
}
