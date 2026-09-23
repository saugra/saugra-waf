use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::event_store::SecurityEvent;

pub(super) fn event_unix_seconds(event: &SecurityEvent) -> Option<u64> {
    rfc3339_to_unix_seconds(&event.timestamp)
}

pub fn render_output_path(path: &Path, unix_seconds: u64, timezone: &str) -> PathBuf {
    let rendered = path
        .to_string_lossy()
        .replace("YYYY-MM-DD", &local_date(unix_seconds, timezone));
    PathBuf::from(rendered)
}

pub fn rfc3339_to_unix_seconds(value: &str) -> Option<u64> {
    let date_time = value.trim();
    let (date, time_and_offset) = date_time.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<i32>().ok()?;
    let month = date_parts.next()?.parse::<u32>().ok()?;
    let day = date_parts.next()?.parse::<u32>().ok()?;
    let (time, offset_seconds) = if let Some(time) = time_and_offset.strip_suffix('Z') {
        (time, 0)
    } else {
        let offset_start = time_and_offset.rfind(['+', '-'])?;
        let (time, offset) = time_and_offset.split_at(offset_start);
        (time, parse_offset_seconds(offset)?)
    };
    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u32>().ok()?;
    let minute = time_parts.next()?.parse::<u32>().ok()?;
    let second = time_parts.next()?.parse::<u32>().ok()?;
    let days = days_from_civil(year, month, day)?;
    let local_seconds = days
        .checked_mul(86_400)?
        .checked_add((hour * 3_600 + minute * 60 + second) as i64)?;
    let utc_seconds = local_seconds.checked_sub(offset_seconds as i64)?;
    u64::try_from(utc_seconds).ok()
}

fn parse_offset_seconds(offset: &str) -> Option<i32> {
    if offset.len() != 6 {
        return None;
    }
    let sign = match &offset[0..1] {
        "+" => 1,
        "-" => -1,
        _ => return None,
    };
    if &offset[3..4] != ":" {
        return None;
    }
    let hours = offset[1..3].parse::<i32>().ok()?;
    let minutes = offset[4..6].parse::<i32>().ok()?;
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some(sign * (hours * 3_600 + minutes * 60))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day = day as i64;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    Some(era * 146_097 + day_of_era - 719_468)
}

pub(super) fn local_date(unix_seconds: u64, timezone: &str) -> String {
    let (year, month, day, _, _, _) = local_date_time_parts(unix_seconds, timezone);
    format!("{year:04}-{month:02}-{day:02}")
}

pub(super) fn local_datetime(unix_seconds: u64, timezone: &str) -> String {
    let (year, month, day, hour, minute, second) = local_date_time_parts(unix_seconds, timezone);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn local_date_time_parts(unix_seconds: u64, timezone: &str) -> (i32, u32, u32, u64, u64, u64) {
    let offset = match timezone {
        "Africa/Nairobi" => 3 * 3_600,
        "UTC" | "Etc/UTC" | "Z" => 0,
        value => parse_offset_seconds(value).unwrap_or(0),
    };
    let local_seconds = unix_seconds as i64 + offset as i64;
    let days = local_seconds.div_euclid(86_400);
    let seconds_of_day = local_seconds.rem_euclid(86_400) as u64;
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60,
    )
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let shifted_days = days_since_unix_epoch + 719_468;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let adjusted_year = year + if month <= 2 { 1 } else { 0 };

    (adjusted_year as i32, month as u32, day as u32)
}

pub(super) fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
