use std::net::IpAddr;

use axum::http::HeaderName;
use cidr::IpCidr;

use crate::{
    ClientIpConfigBuildError,
    cidr_merge::{ensure_no_cross_metadata_overlap, merge_rules_by_metadata},
};

/// Settings used to resolve a client IP from a request.
///
/// In CIDR mode, the resolver first checks whether the socket peer is trusted. Headers are used only after the socket peer matches one of the trusted proxy rules. In trust-all mode, every socket peer is treated as trusted.
///
/// The default config trusts no proxy and disables trust-all mode. It still stores the default chain header order, `X-Forwarded-For` then `Forwarded`, but those headers are not read unless a trusted proxy mode is enabled. With the default config, every request resolves to the socket peer IP.
///
/// When trust-all mode is enabled without extra builder calls, it has no configured single-IP header, checks `X-Forwarded-For` before `Forwarded`, and selects the leftmost valid IP from a chain header.
#[derive(Clone, Debug)]
pub struct ClientIpConfig {
    pub(crate) trusted_proxies:    Vec<TrustedProxyRule>,
    pub(crate) chain_header_order: Vec<ChainHeader>,
    pub(crate) trust_all_mode:     Option<TrustAllProxyMode>,
}

impl ClientIpConfig {
    /// Create a builder with the default chain header order.
    #[inline]
    pub fn builder() -> ClientIpConfigBuilder {
        ClientIpConfigBuilder::default()
    }

    /// Return the trusted proxy rules after build-time merging.
    #[inline]
    pub fn trusted_proxies(&self) -> &[TrustedProxyRule] {
        &self.trusted_proxies
    }

    /// Return the chain headers that are checked after configured headers.
    #[inline]
    pub fn chain_header_order(&self) -> &[ChainHeader] {
        &self.chain_header_order
    }

    /// Return the trust-all proxy mode, if it is enabled.
    #[inline]
    pub fn trust_all_proxy_mode(&self) -> Option<&TrustAllProxyMode> {
        self.trust_all_mode.as_ref()
    }

    /// Check whether trust-all proxy mode is enabled.
    #[inline]
    pub const fn trust_all_proxies(&self) -> bool {
        self.trust_all_mode.is_some()
    }

    /// Check whether an IP address matches any trusted proxy rule.
    #[inline]
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.rule_for(ip).is_some()
    }

    #[inline]
    pub(crate) fn rule_for(&self, ip: IpAddr) -> Option<&TrustedProxyRule> {
        self.trusted_proxies.iter().find(|rule| rule.cidr.contains(&ip))
    }
}

impl Default for ClientIpConfig {
    fn default() -> Self {
        Self {
            trusted_proxies:    Vec::new(),
            chain_header_order: vec![ChainHeader::x_forwarded_for(), ChainHeader::forwarded()],
            trust_all_mode:     None,
        }
    }
}

/// Builder for [`ClientIpConfig`].
///
/// CIDR proxy rules and trust-all proxy mode are separate modes. They cannot be combined in one config.
#[derive(Clone, Debug)]
pub struct ClientIpConfigBuilder {
    rules:              Vec<TrustedProxyRule>,
    chain_header_order: Vec<ChainHeader>,
    trust_all_mode:     Option<TrustAllProxyMode>,
}

impl ClientIpConfigBuilder {
    /// Create a new config builder.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted proxy CIDR without a configured client IP header.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy(mut self, cidr: IpCidr) -> Self {
        self.rules.push(TrustedProxyRule::new(cidr));
        self
    }

    /// Add a trusted proxy CIDR with a configured client IP header.
    ///
    /// Use this when the proxy rewrites the original client address into one plain IP header. Common examples are `X-Real-IP`, `CF-Connecting-IP`, and `True-Client-IP`.
    ///
    /// The header is read only when the socket peer IP is inside this CIDR. If the header is missing or invalid, chain header fallback may still run.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy_with_client_ip_header(mut self, cidr: IpCidr, header: HeaderName) -> Self {
        self.rules.push(TrustedProxyRule::with_client_ip_header(cidr, header));
        self
    }

    /// Add a trusted proxy CIDR that sends the `X-Real-IP` header.
    ///
    /// This is a shortcut for [`Self::proxy_with_client_ip_header`]. It is most useful for Nginx-like setups that pass a normalized client IP in `X-Real-IP`.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn proxy_with_x_real_ip(self, cidr: IpCidr) -> Self {
        self.proxy_with_client_ip_header(cidr, HeaderName::from_static("x-real-ip"))
    }

    /// Set the chain header fallback order.
    ///
    /// Use an empty iterator to disable chain header fallback.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn chain_header_order(mut self, order: impl IntoIterator<Item = ChainHeader>) -> Self {
        self.chain_header_order = order.into_iter().collect();
        self
    }

    /// Disable `X-Forwarded-For` and `Forwarded` fallback.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn disable_chain_headers(self) -> Self {
        self.chain_header_order([])
    }

    /// Enable trust-all proxy mode.
    ///
    /// Use this when the service can only be reached through a proxy, but the proxy IP is not known ahead of time. This mode trusts forwarding headers from any socket peer, so it must not be used on a directly reachable service.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_proxies(mut self) -> Self {
        self.ensure_trust_all_mode();
        self
    }

    /// Enable trust-all proxy mode with a custom single-IP header.
    ///
    /// The header is checked before chain headers. It must contain one plain IP address, such as the value usually sent by `X-Real-IP`.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_proxies_with_client_ip_header(mut self, header: HeaderName) -> Self {
        self.ensure_trust_all_mode().client_ip_header = Some(header);
        self
    }

    /// Set how trust-all mode selects an IP from a chain header.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_chain_ip_selection(mut self, selection: TrustAllChainIpSelection) -> Self {
        self.ensure_trust_all_mode().chain_ip_selection = selection;
        self
    }

    /// Set the chain header order used by trust-all proxy mode.
    ///
    /// Use [`ChainHeader::new`] for a custom comma-separated IP list header.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_chain_header_order(
        mut self,
        order: impl IntoIterator<Item = ChainHeader>,
    ) -> Self {
        self.ensure_trust_all_mode().chain_header_order = order.into_iter().collect();
        self
    }

    /// Build an immutable config.
    ///
    /// CIDRs with the same metadata are merged. CIDRs with different metadata must not overlap, because one socket IP would then imply two policies.
    pub fn build(self) -> Result<ClientIpConfig, ClientIpConfigBuildError> {
        if self.trust_all_mode.is_some() && !self.rules.is_empty() {
            return Err(ClientIpConfigBuildError::TrustAllProxyModeWithTrustedProxyRules);
        }

        ensure_no_cross_metadata_overlap(&self.rules)?;

        let mut trusted_proxies = merge_rules_by_metadata(self.rules);

        // Keep the invariant clear after merging. This should already be true.
        ensure_no_cross_metadata_overlap(&trusted_proxies)?;

        trusted_proxies.sort_by(|a, b| {
            b.cidr
                .network_length()
                .cmp(&a.cidr.network_length())
                .then_with(|| a.cidr.to_string().cmp(&b.cidr.to_string()))
        });

        Ok(ClientIpConfig {
            trusted_proxies,
            chain_header_order: self.chain_header_order,
            trust_all_mode: self.trust_all_mode,
        })
    }

    #[inline]
    fn ensure_trust_all_mode(&mut self) -> &mut TrustAllProxyMode {
        self.trust_all_mode.get_or_insert_with(TrustAllProxyMode::default)
    }
}

impl Default for ClientIpConfigBuilder {
    fn default() -> Self {
        Self {
            rules:              Vec::new(),
            chain_header_order: vec![ChainHeader::x_forwarded_for(), ChainHeader::forwarded()],
            trust_all_mode:     None,
        }
    }
}

/// Settings used when every socket peer is treated as a trusted proxy.
///
/// This mode is useful when the service is always behind a proxy but the proxy IP is not known. It is safe only if direct client access is blocked or the proxy clears untrusted forwarding headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustAllProxyMode {
    pub(crate) client_ip_header:   Option<HeaderName>,
    pub(crate) chain_header_order: Vec<ChainHeader>,
    pub(crate) chain_ip_selection: TrustAllChainIpSelection,
}

impl TrustAllProxyMode {
    /// Return the custom single-IP header checked before chain headers.
    #[inline]
    pub const fn client_ip_header(&self) -> Option<&HeaderName> {
        self.client_ip_header.as_ref()
    }

    /// Return the chain header order for trust-all mode.
    #[inline]
    pub fn chain_header_order(&self) -> &[ChainHeader] {
        &self.chain_header_order
    }

    /// Return how trust-all mode selects an IP from chain headers.
    #[inline]
    pub const fn chain_ip_selection(&self) -> TrustAllChainIpSelection {
        self.chain_ip_selection
    }
}

impl Default for TrustAllProxyMode {
    fn default() -> Self {
        Self {
            client_ip_header:   None,
            chain_header_order: vec![ChainHeader::x_forwarded_for(), ChainHeader::forwarded()],
            chain_ip_selection: TrustAllChainIpSelection::Leftmost,
        }
    }
}

/// How trust-all proxy mode selects an IP from a chain header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrustAllChainIpSelection {
    /// Use the first valid IP in the chain.
    Leftmost,

    /// Use the last valid IP in the chain.
    Rightmost,
}

/// Extra behavior attached to a trusted proxy rule.
///
/// Metadata can name a single header that the trusted proxy uses for the normalized client IP. That header is tied to the CIDR of the same rule.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustedProxyMetadata {
    client_ip_header: Option<HeaderName>,
}

impl TrustedProxyMetadata {
    /// Create metadata without a configured client IP header.
    #[inline]
    pub const fn none() -> Self {
        Self {
            client_ip_header: None
        }
    }

    /// Create metadata for the `X-Real-IP` header.
    #[inline]
    pub const fn x_real_ip() -> Self {
        Self {
            client_ip_header: Some(HeaderName::from_static("x-real-ip"))
        }
    }

    /// Create metadata for a custom configured client IP header.
    ///
    /// The header should be produced by the trusted proxy itself. It should not be a header that untrusted clients can send directly to the application.
    #[inline]
    pub const fn with_client_ip_header(header: HeaderName) -> Self {
        Self {
            client_ip_header: Some(header)
        }
    }

    /// Return the configured client IP header, if one exists.
    #[inline]
    pub const fn client_ip_header(&self) -> Option<&HeaderName> {
        self.client_ip_header.as_ref()
    }
}

/// A trusted proxy CIDR and its proxy-specific metadata.
///
/// The CIDR decides when this rule is active. If the rule has a configured client IP header, that header is checked before chain headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedProxyRule {
    pub(crate) cidr:     IpCidr,
    pub(crate) metadata: TrustedProxyMetadata,
}

impl TrustedProxyRule {
    /// Create a trusted proxy rule without a configured client IP header.
    #[inline]
    pub const fn new(cidr: IpCidr) -> Self {
        Self {
            cidr,
            metadata: TrustedProxyMetadata::none(),
        }
    }

    /// Create a trusted proxy rule with a configured client IP header.
    ///
    /// Use this when this proxy emits a trusted single-value client IP header. The header is read only for socket peers inside this rule's CIDR.
    #[inline]
    pub const fn with_client_ip_header(cidr: IpCidr, header: HeaderName) -> Self {
        Self {
            cidr,
            metadata: TrustedProxyMetadata::with_client_ip_header(header),
        }
    }

    /// Create a trusted proxy rule for the `X-Real-IP` header.
    #[inline]
    pub const fn with_x_real_ip(cidr: IpCidr) -> Self {
        Self {
            cidr,
            metadata: TrustedProxyMetadata::x_real_ip(),
        }
    }

    /// Return the CIDR matched by this trusted proxy rule.
    #[inline]
    pub const fn cidr(&self) -> &IpCidr {
        &self.cidr
    }

    /// Return the metadata attached to this trusted proxy rule.
    #[inline]
    pub const fn metadata(&self) -> &TrustedProxyMetadata {
        &self.metadata
    }

    /// Return the configured client IP header, if one exists.
    #[inline]
    pub const fn client_ip_header(&self) -> Option<&HeaderName> {
        self.metadata.client_ip_header()
    }
}

/// A chain header that may contain client and proxy IP addresses.
///
/// `X-Forwarded-For` is parsed as a comma-separated IP list. `Forwarded` is parsed using the standard `Forwarded` header syntax. Other header names are parsed as custom comma-separated IP list headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChainHeader(HeaderName);

impl ChainHeader {
    /// Create a chain header from a header name.
    ///
    /// Use this for custom headers that contain `X-Forwarded-For` style comma-separated IP lists.
    #[inline]
    pub const fn new(header: HeaderName) -> Self {
        Self(header)
    }

    /// Create the `X-Forwarded-For` chain header.
    #[inline]
    pub const fn x_forwarded_for() -> Self {
        Self(HeaderName::from_static("x-forwarded-for"))
    }

    /// Create the standard `Forwarded` chain header.
    #[inline]
    pub const fn forwarded() -> Self {
        Self(HeaderName::from_static("forwarded"))
    }

    /// Return the wrapped header name.
    #[inline]
    pub const fn as_header_name(&self) -> &HeaderName {
        &self.0
    }

    /// Consume this chain header and return the wrapped header name.
    #[inline]
    pub fn into_header_name(self) -> HeaderName {
        self.0
    }
}
