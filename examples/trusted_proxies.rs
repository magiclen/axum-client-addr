use std::net::SocketAddr;

use axum::{Router, http::HeaderName, routing::get};
use axum_client_addr::{ChainHeader, ClientIp, ClientIpConfig, IpCidr};

#[tokio::main]
async fn main() {
    let x_real_ip = HeaderName::from_static("x-real-ip");

    // Use this setup when you know the proxy IP ranges.
    //
    // This example trusts loopback addresses so it works well for a local demo. In production, replace these CIDRs with the real Nginx private IP, subnet, or load-balancer subnet.
    let config = ClientIpConfig::builder()
        // A request from 127.0.0.1 is trusted and may use X-Real-IP.
        .proxy_with_client_ip_header("127.0.0.1/32".parse::<IpCidr>().unwrap(), x_real_ip.clone())
        // A request from ::1 is also trusted and may use X-Real-IP.
        .proxy_with_client_ip_header("::1/128".parse::<IpCidr>().unwrap(), x_real_ip)
        // X-Forwarded-For is used only after the socket peer is trusted. In CIDR mode the chain is scanned from right to left, and the first IP that is not another trusted proxy becomes the client IP.
        .chain_header_order([ChainHeader::x_forwarded_for()])
        .build()
        .unwrap();

    // If a request comes from any socket IP outside the trusted CIDRs above, X-Real-IP and X-Forwarded-For are ignored. The socket IP is returned.
    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    // The source shows whether the result came from X-Real-IP, X-Forwarded-For, or the raw socket address.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source(),)
}
