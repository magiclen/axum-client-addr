use std::net::{IpAddr, SocketAddr};

use axum::http::{HeaderMap, HeaderName, HeaderValue};

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const FORWARDED: &str = "forwarded";

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

#[inline]
pub(crate) fn x_forwarded_for_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    ip_list_header_values(headers.get_all(X_FORWARDED_FOR).iter())
}

#[inline]
pub(crate) fn list_header_ips(headers: &HeaderMap, header: &HeaderName) -> Vec<IpAddr> {
    ip_list_header_values(headers.get_all(header).iter())
}

fn ip_list_header_values<'a>(values: impl Iterator<Item = &'a HeaderValue>) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for value in values {
        let Ok(raw) = value.to_str() else {
            continue;
        };

        for part in raw.split(',') {
            if let Some(ip) = parse_ip_like(part) {
                ips.push(ip);
            }
        }
    }

    ips
}

#[inline]
pub(crate) fn forwarded_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for value in headers.get_all(FORWARDED).iter() {
        let Ok(raw) = value.to_str() else {
            continue;
        };

        for element in split_quoted(raw, ',') {
            for pair in split_quoted(element, ';') {
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };

                if !name.trim().eq_ignore_ascii_case("for") {
                    continue;
                }

                let value = unquote_http_quoted_string(value.trim());

                if let Some(ip) = parse_ip_like(&value) {
                    ips.push(ip);
                }

                break;
            }
        }
    }

    ips
}

// Split by a delimiter, but ignore delimiters inside HTTP quoted strings.
#[inline]
fn split_quoted(input: &str, delimiter: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
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

        if ch == delimiter && !in_quotes {
            parts.push(input[start..idx].trim());
            start = idx + ch.len_utf8();
        }
    }

    parts.push(input[start..].trim());
    parts
}

#[inline]
fn unquote_http_quoted_string(input: &str) -> String {
    let input = input.trim();

    if input.len() < 2 || !input.starts_with('"') || !input.ends_with('"') {
        return input.to_string();
    }

    let inner = &input[1..input.len() - 1];
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

    output
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
