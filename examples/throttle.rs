use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};

use axum::{
    Router,
    extract::{FromRef, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use axum_client_addr::{ClientIp, ClientIpConfig};
use governor::{DefaultKeyedRateLimiter, Quota};

#[derive(Clone)]
struct AppState {
    client_ip_config: ClientIpConfig,
    rate_limiter:     Arc<DefaultKeyedRateLimiter<IpAddr>>,
}

impl FromRef<AppState> for ClientIpConfig {
    fn from_ref(state: &AppState) -> Self {
        state.client_ip_config.clone()
    }
}

#[tokio::main]
async fn main() {
    // This keeps the same address resolution behavior as the basic example: proxy headers are ignored, and the socket peer IP is the throttle key.
    let client_ip_config = ClientIpConfig::default();

    // Allow each IP to send a short burst of 3 requests, then replenish one request per second. Governor applies GCRA/token-bucket-style throttling, not fixed-window request counting.
    let quota =
        Quota::per_second(NonZeroU32::new(1).unwrap()).allow_burst(NonZeroU32::new(3).unwrap());

    let state = AppState {
        client_ip_config,
        rate_limiter: Arc::new(DefaultKeyedRateLimiter::keyed(quota)),
    };

    // This is an in-memory, per-process throttle. Use shared storage if the limit must span multiple service instances.
    let app = Router::new().route("/", get(handler)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn handler(client_ip: ClientIp, State(state): State<AppState>) -> impl IntoResponse {
    let ip = client_ip.ip();

    if state.rate_limiter.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, format!("too many requests from {ip}\n"));
    }

    (StatusCode::OK, format!("client_ip={} source={:?}\n", ip, client_ip.source()))
}
