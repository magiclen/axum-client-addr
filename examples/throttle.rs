use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
};

use axum::{
    Extension, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_client_addr::{ClientIp, ClientIpConfig, ClientIpConfigSource};
use governor::{DefaultKeyedRateLimiter, Quota};

#[derive(Clone)]
struct AppState {
    client_ip_config: ClientIpConfig,
    rate_limiter:     Arc<DefaultKeyedRateLimiter<IpAddr>>,
}

// ClientIp reads the config by reference through this trait.
// Using axum's FromRef<AppState> instead would build an owned ClientIpConfig for every request, and clone the proxy rules that the extractor only needs to read.
impl ClientIpConfigSource for AppState {
    #[inline]
    fn client_ip_config(&self) -> &ClientIpConfig {
        &self.client_ip_config
    }
}

#[tokio::main]
async fn main() {
    // This keeps the address behavior of the basic example: no header is read, so the throttle key is the socket address.
    let client_ip_config = ClientIpConfig::builder().trust_no_proxy();

    // Each address may send a burst of 3 requests, and then gets one more request per second.
    // Governor uses GCRA, which behaves like a token bucket rather than a fixed window.
    let quota =
        Quota::per_second(NonZeroU32::new(1).unwrap()).allow_burst(NonZeroU32::new(3).unwrap());

    let state = AppState {
        client_ip_config,
        rate_limiter: Arc::new(DefaultKeyedRateLimiter::keyed(quota)),
    };

    // This throttle lives in memory, inside one process.
    // Use shared storage if the limit has to cover several instances of the service.
    let app = Router::new()
        .route("/", get(handler))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();

    println!("listening on http://{}", listener.local_addr().unwrap());

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn rate_limit(
    State(state): State<AppState>,
    client_ip: ClientIp,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = client_ip.ip();

    if state.rate_limiter.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, format!("too many requests from {ip}\n"))
            .into_response();
    }

    // The handler reuses the address this middleware already resolved, instead of resolving it again.
    request.extensions_mut().insert(client_ip);

    next.run(request).await
}

async fn handler(Extension(client_ip): Extension<ClientIp>) -> impl IntoResponse {
    let ip = client_ip.ip();

    (StatusCode::OK, format!("client_ip={} source={:?}\n", ip, client_ip.source()))
}
