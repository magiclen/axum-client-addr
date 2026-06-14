use std::net::SocketAddr;

use axum::{Router, routing::get};
use axum_client_addr::{ClientIp, ClientIpConfig};

#[tokio::main]
async fn main() {
    // This is the safest and smallest setup.
    //
    // No proxy is trusted, so request headers like X-Real-IP and X-Forwarded-For are ignored. The result is always the socket peer IP that Axum gets from the TCP connection.
    let config = ClientIpConfig::default();

    // ClientIp needs ConnectInfo<SocketAddr>. The call to into_make_service_with_connect_info below is what makes Axum store that socket address in each request.
    let app = Router::new().route("/", get(handler)).with_state(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp) -> String {
    // In this example the source should be ClientIpSource::Socket, because no proxy headers are trusted.
    format!("client_ip={} source={:?}\n", client_ip.ip(), client_ip.source(),)
}
