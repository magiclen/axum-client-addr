use std::{net::IpAddr, sync::Arc};

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

/// Provides borrowed access to [`ClientIpConfig`] from application state.
pub trait ClientIpConfigSource {
    /// Return the config used by the [`crate::ClientIp`] extractor.
    fn client_ip_config(&self) -> &ClientIpConfig;
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
    ///
    /// In trust-all mode this returns the trust-all chain header order, because that is the order actually in use.
    #[inline]
    pub fn chain_header_order(&self) -> &[ChainHeader] {
        match &self.trust_all_mode {
            Some(mode) => &mode.chain_header_order,
            None => &self.chain_header_order,
        }
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

impl ClientIpConfigSource for ClientIpConfig {
    #[inline]
    fn client_ip_config(&self) -> &ClientIpConfig {
        self
    }
}

impl<T> ClientIpConfigSource for Arc<T>
where
    T: ClientIpConfigSource + ?Sized,
{
    #[inline]
    fn client_ip_config(&self) -> &ClientIpConfig {
        self.as_ref().client_ip_config()
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
///
/// Trust-all proxy mode is enabled only by [`Self::trust_all_proxies`] or [`Self::trust_all_proxies_with_client_ip_header`]. The other `trust_all_` methods only adjust its settings.
#[derive(Clone, Debug)]
pub struct ClientIpConfigBuilder {
    rules:              Vec<TrustedProxyRule>,
    chain_header_order: Vec<ChainHeader>,
    trust_all_enabled:  bool,
    trust_all_mode:     TrustAllProxyMode,
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
    /// The header is read only when the socket peer IP is inside this CIDR. If the header is missing or invalid, chain header fallback may still run, so the proxy should also clear or overwrite the chain headers it does not set itself.
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
        self.trust_all_enabled = true;
        self
    }

    /// Enable trust-all proxy mode with a custom single-IP header.
    ///
    /// The header is checked before chain headers. It must contain one plain IP address, such as the value usually sent by `X-Real-IP`.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_proxies_with_client_ip_header(mut self, header: HeaderName) -> Self {
        self.trust_all_enabled = true;
        self.trust_all_mode.client_ip_header = Some(header);
        self
    }

    /// Set how trust-all mode selects an IP from a chain header.
    ///
    /// This only adjusts a setting. Trust-all proxy mode must still be enabled by [`Self::trust_all_proxies`] or [`Self::trust_all_proxies_with_client_ip_header`], otherwise [`Self::build`] fails.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_chain_ip_selection(mut self, selection: TrustAllChainIpSelection) -> Self {
        self.trust_all_mode.chain_ip_selection = selection;
        self
    }

    /// Set the chain header order used by trust-all proxy mode.
    ///
    /// Use [`ChainHeader::new`] for a custom comma-separated IP list header.
    ///
    /// This only adjusts a setting. Trust-all proxy mode must still be enabled by [`Self::trust_all_proxies`] or [`Self::trust_all_proxies_with_client_ip_header`], otherwise [`Self::build`] fails.
    #[must_use = "builder methods return an updated builder and do not mutate in place"]
    #[inline]
    pub fn trust_all_chain_header_order(
        mut self,
        order: impl IntoIterator<Item = ChainHeader>,
    ) -> Self {
        self.trust_all_mode.chain_header_order = order.into_iter().collect();
        self
    }

    /// Build an immutable config.
    ///
    /// CIDRs with the same metadata are merged. CIDRs with different metadata must not overlap, because one socket IP would then imply two policies.
    pub fn build(self) -> Result<ClientIpConfig, ClientIpConfigBuildError> {
        if self.trust_all_enabled {
            if !self.rules.is_empty() {
                return Err(ClientIpConfigBuildError::TrustAllProxyModeWithTrustedProxyRules);
            }
        } else if self.trust_all_mode != TrustAllProxyMode::default() {
            // Silently dropping these settings would hide a mistake in a security-sensitive option.
            return Err(ClientIpConfigBuildError::TrustAllProxySettingsWithoutTrustAllProxyMode);
        }

        ensure_no_cross_metadata_overlap(&self.rules)?;

        let mut trusted_proxies = merge_rules_by_metadata(self.rules);

        // Merging only joins adjacent CIDRs of one metadata group, so it covers exactly the same addresses and cannot create a new cross-metadata overlap.
        debug_assert!(ensure_no_cross_metadata_overlap(&trusted_proxies).is_ok());

        trusted_proxies.sort_by(|a, b| {
            b.cidr
                .network_length()
                .cmp(&a.cidr.network_length())
                .then_with(|| a.cidr.first_address().cmp(&b.cidr.first_address()))
        });

        Ok(ClientIpConfig {
            trusted_proxies,
            chain_header_order: self.chain_header_order,
            trust_all_mode: self.trust_all_enabled.then_some(self.trust_all_mode),
        })
    }
}

impl Default for ClientIpConfigBuilder {
    fn default() -> Self {
        Self {
            rules:              Vec::new(),
            chain_header_order: vec![ChainHeader::x_forwarded_for(), ChainHeader::forwarded()],
            trust_all_enabled:  false,
            trust_all_mode:     TrustAllProxyMode::default(),
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
///
/// Either end can only be trusted as far as the proxy in front of the service is trusted. If the selected hop carries no usable IP address, the chain header is skipped.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TrustAllChainIpSelection {
    /// Use the first hop in the chain.
    ///
    /// This is the usual `X-Forwarded-For` meaning, but the leftmost value is also the part a client can write freely. It is safe only when the proxy in front of the service overwrites or clears the header.
    Leftmost,

    /// Use the last hop in the chain.
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
    /// Use this when this proxy emits a trusted single-value client IP header. The header is read only for socket peers inside this rule's CIDR. If the header is missing or invalid, chain header fallback may still run, so the proxy should also clear or overwrite the chain headers it does not set itself.
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
///
/// The parsing style is decided once, when the chain header is created, from the header name.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ChainHeader {
    name: HeaderName,
    kind: ChainHeaderKind,
}

/// How the value of a chain header is parsed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum ChainHeaderKind {
    XForwardedFor,
    Forwarded,
    List,
}

impl ChainHeader {
    /// Create a chain header from a header name.
    ///
    /// Use this for custom headers that contain `X-Forwarded-For` style comma-separated IP lists. The names `x-forwarded-for` and `forwarded` still get their dedicated parsing.
    #[inline]
    pub fn new(header: HeaderName) -> Self {
        let kind = match header.as_str() {
            "x-forwarded-for" => ChainHeaderKind::XForwardedFor,
            "forwarded" => ChainHeaderKind::Forwarded,
            _ => ChainHeaderKind::List,
        };

        Self {
            name: header,
            kind,
        }
    }

    /// Create the `X-Forwarded-For` chain header.
    #[inline]
    pub const fn x_forwarded_for() -> Self {
        Self {
            name: HeaderName::from_static("x-forwarded-for"),
            kind: ChainHeaderKind::XForwardedFor,
        }
    }

    /// Create the standard `Forwarded` chain header.
    #[inline]
    pub const fn forwarded() -> Self {
        Self {
            name: HeaderName::from_static("forwarded"), kind: ChainHeaderKind::Forwarded
        }
    }

    /// Return the wrapped header name.
    #[inline]
    pub const fn as_header_name(&self) -> &HeaderName {
        &self.name
    }

    /// Consume this chain header and return the wrapped header name.
    #[inline]
    pub fn into_header_name(self) -> HeaderName {
        self.name
    }

    #[inline]
    pub(crate) const fn kind(&self) -> ChainHeaderKind {
        self.kind
    }
}
