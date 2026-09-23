use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

use crate::config::UnknownThreatRouteConfig;

pub fn matching_route<'a>(
    routes: &'a [UnknownThreatRouteConfig],
    path: &str,
) -> Option<&'a UnknownThreatRouteConfig> {
    routes
        .iter()
        .filter(|route| path_matches_route(path, &route.path))
        .max_by_key(|route| route.path.trim_end_matches('/').len())
}

pub fn path_matches_any(path: &str, configured_paths: &[String]) -> bool {
    configured_paths
        .iter()
        .any(|configured_path| path_matches_route(path, configured_path))
}

pub fn path_matches_route(path: &str, route_path: &str) -> bool {
    let route_path = route_path.trim().trim_end_matches('/');
    if route_path.is_empty() {
        return true;
    }

    path == route_path
        || path
            .strip_prefix(route_path)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub fn client_matches_any(client_id: &str, configured_clients: &[String]) -> bool {
    configured_clients
        .iter()
        .any(|configured| client_matches(client_id, configured))
}

pub fn client_matches(client_id: &str, configured: &str) -> bool {
    if configured.trim() == client_id {
        return true;
    }
    let Ok(IpAddr::V4(client_ip)) = client_id.parse::<IpAddr>() else {
        return false;
    };
    ipv4_cidr_contains(configured.trim(), client_ip)
}

pub fn ipv4_cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    u32::from(ip) & mask == u32::from(network) & mask
}

pub fn normalized_content_type(value: &str) -> String {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

pub fn query_parameter_names(query: &str) -> BTreeSet<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('=').map(|(name, _)| name).or(Some(pair)))
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.to_ascii_lowercase())
        .collect()
}

pub fn route_shape(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| {
            if looks_dynamic(segment) {
                ":id"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>();

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

pub fn looks_dynamic(segment: &str) -> bool {
    let compact = segment.replace('-', "");
    (!segment.is_empty() && segment.chars().all(|character| character.is_ascii_digit()))
        || (compact.len() >= 16
            && compact
                .chars()
                .all(|character| character.is_ascii_hexdigit()))
}
