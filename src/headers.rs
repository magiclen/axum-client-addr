use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
};

use axum::http::{HeaderMap, HeaderName};

/// One hop found in a chain header.
pub(crate) enum ChainEntry {
    /// A hop with a usable IP address.
    Ip(IpAddr),

    /// A hop that exists but carries no usable IP address.
    ///
    /// This covers `unknown`, RFC 7239 obfuscated identifiers, unparsable text, and `Forwarded` elements without a `for` parameter. Such a hop cannot be checked against the trusted proxy rules.
    Opaque,
}

pub(crate) fn configured_client_ip_header(
    headers: &HeaderMap,
    header: &HeaderName,
) -> Option<IpAddr> {
    headers
        .get_all(header)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|raw| raw.trim().parse::<IpAddr>().ok())
}

/// Collect the hops of an `X-Forwarded-For` style comma-separated header.
pub(crate) fn list_header_entries(
    headers: &HeaderMap,
    header: &HeaderName,
    entries: &mut Vec<ChainEntry>,
) {
    for value in headers.get_all(header).iter() {
        let Ok(raw) = value.to_str() else {
            // A non-UTF-8 value hides at least one hop.
            entries.push(ChainEntry::Opaque);
            continue;
        };

        for part in raw.split(',') {
            let part = part.trim();

            // An empty part is list punctuation, not a hop.
            if part.is_empty() {
                continue;
            }

            entries.push(chain_entry(part));
        }
    }
}

/// Collect the hops of a standard `Forwarded` header.
pub(crate) fn forwarded_entries(
    headers: &HeaderMap,
    header: &HeaderName,
    entries: &mut Vec<ChainEntry>,
) {
    for value in headers.get_all(header).iter() {
        let Ok(raw) = value.to_str() else {
            entries.push(ChainEntry::Opaque);
            continue;
        };

        for element in SplitQuoted::new(raw, ',') {
            if element.is_empty() {
                continue;
            }

            entries.push(forwarded_element_entry(element));
        }
    }
}

fn forwarded_element_entry(element: &str) -> ChainEntry {
    for pair in SplitQuoted::new(element, ';') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };

        if !name.trim().eq_ignore_ascii_case("for") {
            continue;
        }

        return chain_entry(&unquote_http_quoted_string(value.trim()));
    }

    ChainEntry::Opaque
}

#[inline]
fn chain_entry(raw: &str) -> ChainEntry {
    match parse_ip_like(raw) {
        Some(ip) => ChainEntry::Ip(ip),
        None => ChainEntry::Opaque,
    }
}

/// Split by a delimiter, but ignore delimiters inside HTTP quoted strings.
///
/// Every item is trimmed, and an empty input yields one empty item.
struct SplitQuoted<'a> {
    input:     &'a str,
    delimiter: char,
    start:     Option<usize>,
}

impl<'a> SplitQuoted<'a> {
    #[inline]
    const fn new(input: &'a str, delimiter: char) -> Self {
        Self {
            input,
            delimiter,
            start: Some(0),
        }
    }
}

impl<'a> Iterator for SplitQuoted<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.start?;
        let mut in_quotes = false;
        let mut escaped = false;

        for (offset, ch) in self.input[start..].char_indices() {
            if escaped {
                escaped = false;
                continue;
            }

            if in_quotes && ch == '\\' {
                escaped = true;
                continue;
            }

            if ch == '"' {
                in_quotes = !in_quotes;
                continue;
            }

            if ch == self.delimiter && !in_quotes {
                let end = start + offset;

                self.start = Some(end + ch.len_utf8());

                return Some(self.input[start..end].trim());
            }
        }

        self.start = None;

        Some(self.input[start..].trim())
    }
}

#[inline]
fn unquote_http_quoted_string(input: &str) -> Cow<'_, str> {
    let input = input.trim();

    if input.len() < 2 || !input.starts_with('"') || !input.ends_with('"') {
        return Cow::Borrowed(input);
    }

    let inner = &input[1..input.len() - 1];

    if !inner.contains('\\') {
        return Cow::Borrowed(inner);
    }

    let mut output = String::with_capacity(inner.len());
    let mut escaped = false;

    for ch in inner.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            continue;
        }

        output.push(ch);
    }

    Cow::Owned(output)
}

#[inline]
fn parse_ip_like(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim();

    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") || raw.starts_with('_') {
        return None;
    }

    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Some(rest) = raw.strip_prefix('[') {
        let close_bracket = rest.find(']')?;
        let ip_part = &rest[..close_bracket];
        let tail = &rest[close_bracket + 1..];

        if tail.is_empty() {
            return ip_part.parse::<IpAddr>().ok();
        }

        if let Some(port) = tail.strip_prefix(':') {
            if is_valid_node_port(port) {
                return ip_part.parse::<IpAddr>().ok();
            }
        }

        return None;
    }

    if let Ok(socket_addr) = raw.parse::<SocketAddr>() {
        return Some(socket_addr.ip());
    }

    // IPv4 may use an obfuscated port in a Forwarded header.
    if let Some((host, port)) = raw.rsplit_once(':') {
        if host.parse::<std::net::Ipv4Addr>().is_ok() && is_valid_node_port(port) {
            return host.parse::<IpAddr>().ok();
        }
    }

    None
}

#[inline]
fn is_valid_node_port(port: &str) -> bool {
    if port.is_empty() {
        return false;
    }

    if port.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }

    let Some(obfuscated) = port.strip_prefix('_') else {
        return false;
    };

    !obfuscated.is_empty()
        && obfuscated.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}
