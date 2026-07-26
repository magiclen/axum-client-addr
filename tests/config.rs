use axum_client_addr::{
    ClientIpConfig, ClientIpConfigBuildError, HeaderName, IpCidr, TrustAllChainIpSelection,
    TrustedProxyRule,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

#[test]
fn trust_no_proxy_is_the_default() {
    let config = ClientIpConfig::default();

    assert!(!config.trusts_all_proxies());
    assert!(config.trusted_proxies().is_empty());
    assert!(config.chain_header_order().is_empty());
}

#[test]
fn cidrs_with_the_same_client_ip_header_are_merged() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/25"))
        .proxy(cidr("10.0.0.128/25"))
        .build()
        .unwrap();

    assert_eq!(1, config.trusted_proxies().len());
    assert_eq!("10.0.0.0/24", config.trusted_proxies()[0].cidr().to_string());
}

#[test]
fn overlapping_cidrs_with_different_client_ip_headers_are_rejected() {
    let error = ClientIpConfig::builder()
        .trusted_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .proxy_with_x_real_ip(cidr("10.0.0.0/25"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::OverlappingTrustedProxyRules { .. }));
}

#[test]
fn proxy_rules_can_be_added_in_bulk() {
    let config = ClientIpConfig::builder()
        .trusted_proxies()
        .proxies([
            TrustedProxyRule::with_x_real_ip(cidr("10.0.0.0/24")),
            TrustedProxyRule::new(cidr("198.51.100.0/24")),
        ])
        .build()
        .unwrap();

    assert_eq!(2, config.trusted_proxies().len());
    assert!(config.is_trusted_proxy("10.0.0.2".parse().unwrap()));
    assert!(config.is_trusted_proxy("198.51.100.7".parse().unwrap()));
}

#[test]
fn trust_all_settings_are_kept_in_the_built_config() {
    let config = ClientIpConfig::builder()
        .trust_all_proxies()
        .client_ip_header(HeaderName::from_static("x-client-ip"))
        .chain_ip_selection(TrustAllChainIpSelection::Leftmost)
        .build();

    let mode = config.trust_all_proxy_mode().unwrap();

    assert!(config.trusts_all_proxies());
    assert_eq!(TrustAllChainIpSelection::Leftmost, mode.chain_ip_selection());
    assert_eq!(Some(&HeaderName::from_static("x-client-ip")), mode.client_ip_header());
}

#[test]
fn trust_all_treats_every_ip_as_a_trusted_proxy() {
    let config = ClientIpConfig::builder().trust_all_proxies().build();

    assert!(config.is_trusted_proxy("203.0.113.10".parse().unwrap()));
}
