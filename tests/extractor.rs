//! Tests for the `ClientIp` extractor and how it reads the config out of application state.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{Request, StatusCode, request::Parts},
    response::IntoResponse,
};
use axum_client_addr::{
    ClientIp, ClientIpConfig, ClientIpConfigSource, ClientIpRejection, ClientIpSource, IpCidr,
};

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

fn ip(input: &str) -> IpAddr {
    input.parse().unwrap()
}

/// Trust 10.0.0.0/24, and let it send the client address in X-Real-IP.
fn trusted_config() -> ClientIpConfig {
    ClientIpConfig::builder()
        .trusted_proxies()
        .proxy_with_x_real_ip(cidr("10.0.0.0/24"))
        .build()
        .unwrap()
}

/// A request from the trusted proxy 10.0.0.2, reporting the client 203.0.113.10.
fn request_parts() -> Parts {
    let mut request = Request::builder().header("x-real-ip", "203.0.113.10").body(()).unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip("10.0.0.2"), 12345)));

    request.into_parts().0
}

/// The same request, mounted somewhere that records no socket address.
fn request_parts_without_connect_info() -> Parts {
    Request::builder().header("x-real-ip", "203.0.113.10").body(()).unwrap().into_parts().0
}

async fn assert_extracts_client_ip<S: Send + Sync + ClientIpConfigSource>(state: &S) {
    let mut parts = request_parts();

    let client_ip = ClientIp::from_request_parts(&mut parts, state).await.unwrap();

    assert_eq!(ip("203.0.113.10"), client_ip.ip());
    assert_eq!(&ClientIpSource::ConfiguredHeader("x-real-ip".parse().unwrap()), client_ip.source());
}

// A config is a valid state on its own, so a service that needs nothing else can use it directly.
#[tokio::test]
async fn the_config_works_as_state_on_its_own() {
    assert_extracts_client_ip(&trusted_config()).await;
}

// A custom state keeps the config next to the rest of the application data.
#[tokio::test]
async fn a_custom_state_provides_the_config_through_the_trait() {
    let state = AppState {
        client_ip_config: trusted_config()
    };

    assert_extracts_client_ip(&state).await;
}

// A state behind an Arc forwards to the state inside it.
#[tokio::test]
async fn an_arc_state_forwards_to_the_state_inside() {
    let state = Arc::new(AppState {
        client_ip_config: trusted_config()
    });

    assert_extracts_client_ip(&state).await;
}

// With a socket address in the request, the optional extractor answers just like the plain one.
#[tokio::test]
async fn the_optional_extractor_resolves_when_connect_info_is_present() {
    let state = trusted_config();
    let mut parts = request_parts();

    let client_ip = Option::<ClientIp>::from_request_parts(&mut parts, &state).await.unwrap();

    assert_eq!(Some(ip("203.0.113.10")), client_ip.map(|client_ip| client_ip.ip()));
}

// Without a socket address there is nothing to fall back to, so the optional extractor reports nothing instead of failing the request.
#[tokio::test]
async fn the_optional_extractor_is_none_without_connect_info() {
    let state = trusted_config();
    let mut parts = request_parts_without_connect_info();

    let client_ip = Option::<ClientIp>::from_request_parts(&mut parts, &state).await.unwrap();

    assert_eq!(None, client_ip);
}

// The plain extractor fails instead, and the failure is a server setup mistake rather than a bad request.
#[tokio::test]
async fn the_extractor_rejects_a_request_without_connect_info() {
    let state = trusted_config();
    let mut parts = request_parts_without_connect_info();

    let rejection = ClientIp::from_request_parts(&mut parts, &state).await.unwrap_err();

    assert!(matches!(rejection, ClientIpRejection::MissingConnectInfo));
    assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, rejection.into_response().status());
}

// The resolved address can be read, split apart, printed, or turned into a plain IpAddr.
#[tokio::test]
async fn a_resolved_client_ip_can_be_read_in_several_ways() {
    let state = trusted_config();
    let mut parts = request_parts();

    let client_ip = ClientIp::from_request_parts(&mut parts, &state).await.unwrap();

    assert_eq!("203.0.113.10", client_ip.to_string());
    assert_eq!(ip("203.0.113.10"), IpAddr::from(client_ip.clone()));

    let (address, source) = client_ip.into_parts();

    assert_eq!(ip("203.0.113.10"), address);
    assert_eq!(Some(&"x-real-ip".parse().unwrap()), source.header_name());
}
