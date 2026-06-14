use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, FromRef, FromRequestParts},
    http::Request,
};
use axum_client_addr::{ClientIp, ClientIpConfig, ClientIpSource, IpCidr};

#[derive(Clone)]
struct AppState {
    client_ip_config: ClientIpConfig,
}

impl FromRef<AppState> for ClientIpConfig {
    fn from_ref(state: &AppState) -> Self {
        state.client_ip_config.clone()
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

#[tokio::test]
async fn extractor_uses_connect_info_and_state_config() {
    let state = AppState {
        client_ip_config: ClientIpConfig::builder()
            .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
            .build()
            .unwrap(),
    };
    let mut request = Request::builder().header("x-real-ip", "203.0.113.10").body(()).unwrap();
    request.extensions_mut().insert(ConnectInfo(socket("10.0.0.2")));
    let (mut parts, _) = request.into_parts();

    let client_ip = ClientIp::from_request_parts(&mut parts, &state).await.unwrap();

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader("x-real-ip".parse().unwrap()), client_ip.source());
}
