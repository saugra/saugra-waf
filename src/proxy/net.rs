use std::net::{IpAddr, Ipv4Addr};

pub fn ip_matches_proxy_entry(ip: IpAddr, entry: &str) -> bool {
    let entry = entry.trim();
    if entry.eq_ignore_ascii_case("any") {
        return true;
    }

    if let Ok(entry_ip) = entry.parse::<IpAddr>() {
        return entry_ip == ip;
    }

    let IpAddr::V4(ip) = ip else {
        return false;
    };

    ipv4_cidr_contains(entry, ip)
}

pub fn ipv4_cidr_contains(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((network, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let Ok(network) = network.parse::<Ipv4Addr>() else {
        return false;
    };

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(network) & mask) == (u32::from(ip) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_matches_proxy_entry_exact_and_any() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(ip_matches_proxy_entry(ip, "any"));
        assert!(ip_matches_proxy_entry(ip, "ANY"));
        assert!(ip_matches_proxy_entry(ip, "192.168.1.50"));
        assert!(!ip_matches_proxy_entry(ip, "192.168.1.51"));
    }

    #[test]
    fn test_ip_matches_proxy_entry_cidr() {
        let ip: IpAddr = "10.0.1.15".parse().unwrap();
        assert!(ip_matches_proxy_entry(ip, "10.0.0.0/16"));
        assert!(ip_matches_proxy_entry(ip, "10.0.1.0/24"));
        assert!(!ip_matches_proxy_entry(ip, "10.0.2.0/24"));
    }

    #[test]
    fn test_ipv4_cidr_contains() {
        let ip: Ipv4Addr = "172.16.5.10".parse().unwrap();
        assert!(ipv4_cidr_contains("172.16.0.0/12", ip));
        assert!(ipv4_cidr_contains("0.0.0.0/0", ip));
        assert!(!ipv4_cidr_contains("172.17.0.0/16", ip));
        assert!(!ipv4_cidr_contains("invalid_cidr", ip));
        assert!(!ipv4_cidr_contains("172.16.0.0/33", ip));
    }
}
