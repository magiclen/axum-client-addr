use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_addr::{ChainHeader, ClientIp, ClientIpConfig, HeaderName, IpCidr};

#[tokio::main]
async fn main() {
    let x_real_ip = HeaderName::from_static("x-real-ip");

    // Use this setup when you know the addresses your proxies use.
    // The loopback CIDRs below make this a working local demo.
    // In production, replace them with the private address of Nginx, or with your load balancer subnet.
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        // A request from 127.0.0.1 is trusted, and its X-Real-IP may become the answer.
        .proxy_with_client_ip_header("127.0.0.1/32".parse::<IpCidr>().unwrap(), x_real_ip.clone())
        // A request from ::1 is trusted in the same way.
        .proxy_with_client_ip_header("::1/128".parse::<IpCidr>().unwrap(), x_real_ip)
        // X-Forwarded-For is read only after the socket peer turns out to be a trusted proxy.
        // The chain is then scanned from right to left, and the first hop that is not another trusted proxy becomes the client IP.
        .chain_header_order([ChainHeader::x_forwarded_for()])
        .build()
        .unwrap();

    // A request from any address outside those CIDRs resolves to its own socket address.
    // Neither X-Real-IP nor X-Forwarded-For is read for it.
    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    // The source tells you whether the answer came from X-Real-IP, from X-Forwarded-For, or from the socket.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}
