use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_addr::{ClientIp, ClientIpConfig};

#[tokio::main]
async fn main() {
    // This is the safest and smallest setup.
    // No proxy is trusted, so headers such as X-Real-IP and X-Forwarded-For are ignored.
    // The answer is always the address the TCP connection came from.
    let config = ClientIpConfig::builder().trust_no_proxy();

    // ClientIp needs ConnectInfo<SocketAddr>.
    // The into_make_service_with_connect_info call below is what puts that address into each request.
    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    // The source is always ClientIpSource::Socket here, because no header is trusted.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source())
}
