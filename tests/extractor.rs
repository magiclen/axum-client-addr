use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{Request, request::Parts},
};
use axum_client_addr::{ClientIp, ClientIpConfig, ClientIpConfigSource, ClientIpSource, IpCidr};

#[derive(Clone)]
struct AppState {
    client_ip_config: ClientIpConfig,
}

impl ClientIpConfigSource for AppState {
    fn client_ip_config(&self) -> &ClientIpConfig {
        &self.client_ip_config
    }
}

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

fn socket(ip: &str) -> SocketAddr {
    SocketAddr::new(ip.parse::<IpAddr>().unwrap(), 12345)
}

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

fn trusted_config() -> ClientIpConfig {
    ClientIpConfig::builder().proxy_with_x_real_ip(cidr("10.0.0.0/24")).build().unwrap()
}

fn request_parts() -> Parts {
    let mut request = Request::builder().header("x-real-ip", "203.0.113.10").body(()).unwrap();
    request.extensions_mut().insert(ConnectInfo(socket("10.0.0.2")));
    request.into_parts().0
}

async fn assert_extracts_real_ip<S: Send + Sync + ClientIpConfigSource>(state: &S) {
    let mut parts = request_parts();

    let client_ip = ClientIp::from_request_parts(&mut parts, state).await.unwrap();

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader("x-real-ip".parse().unwrap()), client_ip.source());
}

#[tokio::test]
async fn extractor_uses_client_ip_config_state() {
    let state = trusted_config();

    assert_extracts_real_ip(&state).await;
}

#[tokio::test]
async fn extractor_uses_custom_state_config_source() {
    let state = AppState {
        client_ip_config: trusted_config()
    };

    assert_extracts_real_ip(&state).await;
}

#[tokio::test]
async fn extractor_uses_arc_state_config_source() {
    let state = Arc::new(AppState {
        client_ip_config: trusted_config()
    });

    assert_extracts_real_ip(&state).await;
}
