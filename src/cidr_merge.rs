use std::collections::HashMap;

use cidr::IpCidr;
use cidr_utils::combiner::{Ipv4CidrCombiner, Ipv6CidrCombiner};

use crate::{ClientIpConfigBuildError, TrustedProxyMetadata, TrustedProxyRule};

pub(crate) fn ensure_no_cross_metadata_overlap(
    rules: &[TrustedProxyRule],
) -> Result<(), ClientIpConfigBuildError> {
    for i in 0..rules.len() {
        for j in (i + 1)..rules.len() {
            let left = &rules[i];
            let right = &rules[j];

            if left.metadata == right.metadata {
                continue;
            }

            if cidrs_overlap(&left.cidr, &right.cidr) {
                return Err(ClientIpConfigBuildError::OverlappingTrustedProxyMetadata {
                    left:  Box::new(left.clone()),
                    right: Box::new(right.clone()),
                });
            }
        }
    }

    Ok(())
}

#[inline]
fn cidrs_overlap(left: &IpCidr, right: &IpCidr) -> bool {
    match (left, right) {
        (IpCidr::V4(_), IpCidr::V6(_)) | (IpCidr::V6(_), IpCidr::V4(_)) => false,
        _ => left.contains(&right.first_address()) || right.contains(&left.first_address()),
    }
}

pub(crate) fn merge_rules_by_metadata(rules: Vec<TrustedProxyRule>) -> Vec<TrustedProxyRule> {
    let mut groups: HashMap<TrustedProxyMetadata, Vec<IpCidr>> = HashMap::new();

    for rule in rules {
        groups.entry(rule.metadata).or_default().push(rule.cidr);
    }

    let mut merged = Vec::new();

    for (metadata, cidrs) in groups {
        for cidr in merge_cidrs(cidrs) {
            merged.push(TrustedProxyRule {
                cidr,
                metadata: metadata.clone(),
            });
        }
    }

    merged
}

fn merge_cidrs(cidrs: Vec<IpCidr>) -> Vec<IpCidr> {
    let mut ipv4 = Ipv4CidrCombiner::new();
    let mut ipv6 = Ipv6CidrCombiner::new();

    for cidr in cidrs {
        match cidr {
            IpCidr::V4(cidr) => ipv4.push(cidr),
            IpCidr::V6(cidr) => ipv6.push(cidr),
        }
    }

    let mut merged = Vec::new();

    for cidr in ipv4.into_ipv4_cidr_vec() {
        merged.push(IpCidr::V4(cidr));
    }

    for cidr in ipv6.into_ipv6_cidr_vec() {
        merged.push(IpCidr::V6(cidr));
    }

    merged
}
