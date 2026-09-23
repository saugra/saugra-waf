use std::net::{IpAddr, Ipv4Addr};

use crate::config::{errors::ConfigError, BotProtectionLists};

pub fn parse_byte_size(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    let multiplier = match unit.trim() {
        "b" | "" => 1,
        "kb" | "kib" => 1024,
        "mb" | "mib" => 1024 * 1024,
        "gb" | "gib" => 1024 * 1024 * 1024,
        _ => return None,
    };

    number.checked_mul(multiplier)
}

pub fn parse_duration_seconds(value: &str) -> Option<u64> {
    let trimmed = value.trim().to_ascii_lowercase();
    let split_at = trimmed.find(|c: char| !c.is_ascii_digit())?;
    let (number, unit) = trimmed.split_at(split_at);
    let number = number.parse::<u64>().ok()?;
    if number == 0 {
        return None;
    }

    let multiplier = match unit.trim() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hrs" | "hour" | "hours" => 60 * 60,
        "d" | "day" | "days" => 24 * 60 * 60,
        _ => return None,
    };

    number.checked_mul(multiplier)
}

pub fn validate_behavior_thresholds(
    monitor_threshold: u16,
    block_threshold: u16,
) -> Result<(), ConfigError> {
    if monitor_threshold == 0 {
        return Err(ConfigError::InvalidBehaviorMonitorThreshold);
    }

    if block_threshold < monitor_threshold {
        return Err(ConfigError::InvalidBehaviorBlockThreshold);
    }

    Ok(())
}

pub fn validate_optional_behavior_thresholds(
    monitor_threshold: Option<u16>,
    block_threshold: Option<u16>,
    default_monitor_threshold: u16,
    default_block_threshold: u16,
) -> Result<(), ConfigError> {
    let monitor_threshold = monitor_threshold.unwrap_or(default_monitor_threshold);
    let block_threshold = block_threshold.unwrap_or(default_block_threshold);
    validate_behavior_thresholds(monitor_threshold, block_threshold)
}

pub fn validate_bot_protection_thresholds(
    monitor_threshold: u16,
    block_threshold: u16,
) -> Result<(), ConfigError> {
    if monitor_threshold == 0 {
        return Err(ConfigError::InvalidBotProtectionMonitorThreshold);
    }

    if block_threshold < monitor_threshold {
        return Err(ConfigError::InvalidBotProtectionBlockThreshold);
    }

    Ok(())
}

pub fn validate_optional_bot_protection_thresholds(
    monitor_threshold: Option<u16>,
    block_threshold: Option<u16>,
    default_monitor_threshold: u16,
    default_block_threshold: u16,
) -> Result<(), ConfigError> {
    let monitor_threshold = monitor_threshold.unwrap_or(default_monitor_threshold);
    let block_threshold = block_threshold.unwrap_or(default_block_threshold);
    validate_bot_protection_thresholds(monitor_threshold, block_threshold)
}

pub fn bot_list_has_blank(list: &BotProtectionLists) -> bool {
    list.ip_ranges
        .iter()
        .chain(list.user_agents.iter())
        .any(|value| value.trim().is_empty())
}

pub fn is_valid_header_name(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'a'..=b'z'
                    | b'A'..=b'Z'
            )
        })
}

pub fn is_valid_trusted_assertion_header(value: &str) -> bool {
    is_valid_header_name(value)
        && !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-auth-token"
        )
}

pub fn is_valid_ip_or_cidr(value: &str) -> bool {
    let value = value.trim();
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }

    let Some((network, prefix)) = value.split_once('/') else {
        return false;
    };
    network.parse::<Ipv4Addr>().is_ok()
        && prefix
            .parse::<u8>()
            .is_ok_and(|prefix_length| prefix_length <= 32)
}

pub fn is_valid_send_time(value: &str) -> bool {
    let value = value.trim();
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 2 {
        return false;
    }
    let Ok(hours) = parts[0].parse::<u32>() else {
        return false;
    };
    let Ok(minutes) = parts[1].parse::<u32>() else {
        return false;
    };
    hours < 24 && minutes < 60
}

pub fn is_local_http_url(value: &str) -> bool {
    let value = value.trim().trim_end_matches('/');
    let Some(authority) = value.strip_prefix("http://") else {
        return false;
    };
    let authority = authority.split('/').next().unwrap_or_default();
    if matches!(authority, "localhost" | "127.0.0.1" | "[::1]") {
        return true;
    }
    ["localhost:", "127.0.0.1:", "[::1]:"]
        .iter()
        .find_map(|prefix| authority.strip_prefix(prefix))
        .is_some_and(|port| port.parse::<u16>().is_ok())
}

pub fn is_allowlisted_https_url(value: &str, allowlist: &[String]) -> bool {
    let Some(authority) = value.trim().strip_prefix("https://") else {
        return false;
    };
    let host = authority
        .split('/')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default();
    allowlist
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed) || host.ends_with(&format!(".{allowed}")))
}
