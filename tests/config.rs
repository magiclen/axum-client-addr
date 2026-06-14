use axum_client_addr::{ClientIpConfig, IpCidr};

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
