use axum::http::HeaderName;
use axum_client_addr::{
    ClientIpConfig, ClientIpConfigBuildError, IpCidr, TrustAllChainIpSelection,
};

fn cidr(input: &str) -> IpCidr {
    input.parse().unwrap()
}

#[test]
fn matching_metadata_cidrs_are_merged() {
    let config = ClientIpConfig::builder()
        .proxy(cidr("10.0.0.0/25"))
        .proxy(cidr("10.0.0.128/25"))
        .build()
        .unwrap();

    assert_eq!(1, config.trusted_proxies().len());
    assert_eq!("10.0.0.0/24", config.trusted_proxies()[0].cidr().to_string());
}

#[test]
fn overlapping_cidrs_with_different_metadata_are_rejected() {
    let error = ClientIpConfig::builder()
        .proxy(cidr("10.0.0.0/24"))
        .proxy_with_x_real_ip(cidr("10.0.0.0/25"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::OverlappingTrustedProxyMetadata { .. }));
}

#[test]
fn trust_all_mode_cannot_be_combined_with_trusted_proxy_rules() {
    let error = ClientIpConfig::builder()
        .trust_all_proxies()
        .proxy(cidr("10.0.0.0/24"))
        .build()
        .unwrap_err();

    assert!(matches!(error, ClientIpConfigBuildError::TrustAllProxyModeWithTrustedProxyRules));
}

#[test]
fn trust_all_settings_alone_do_not_enable_trust_all_mode() {
    let error = ClientIpConfig::builder()
        .trust_all_chain_ip_selection(TrustAllChainIpSelection::Rightmost)
        .build()
        .unwrap_err();

    assert!(matches!(
        error,
        ClientIpConfigBuildError::TrustAllProxySettingsWithoutTrustAllProxyMode
    ));
}

#[test]
fn trust_all_settings_apply_once_trust_all_mode_is_enabled() {
    let config = ClientIpConfig::builder()
        .trust_all_chain_ip_selection(TrustAllChainIpSelection::Rightmost)
        .trust_all_proxies_with_client_ip_header(HeaderName::from_static("x-client-ip"))
        .build()
        .unwrap();

    let mode = config.trust_all_proxy_mode().unwrap();

    assert!(config.trust_all_proxies());
    assert_eq!(TrustAllChainIpSelection::Rightmost, mode.chain_ip_selection());
    assert_eq!(Some(&HeaderName::from_static("x-client-ip")), mode.client_ip_header());
}
