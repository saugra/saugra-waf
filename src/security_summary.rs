use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::{
    config::{SaugraConfig, SecuritySummaryChannelConfig},
    decision::WafAction,
    event_store::{self, EventLogRetention, SecurityEvent},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_hostname: Option<String>,
    pub generated_at_unix_seconds: u64,
    pub timezone: String,
    pub lookback_seconds: u64,
    pub window_start_unix_seconds: u64,
    pub window_end_unix_seconds: u64,
    pub total_security_events: usize,
    pub blocked_events: usize,
    pub monitored_events: usize,
    pub allowed_runtime_policy_events: usize,
    pub rate_limit_events: usize,
    pub bot_events: usize,
    pub behavior_threshold_events: usize,
    pub top_attack_categories: Vec<SummaryCount>,
    pub top_matched_rules: Vec<SummaryCount>,
    pub top_source_ips: Vec<SummaryCount>,
    pub top_targeted_paths: Vec<SummaryCount>,
    pub important_blocked_request_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub output_path: Option<PathBuf>,
    pub email_recipients: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SummaryAdminEvent {
    pub timestamp_unix_seconds: u64,
    pub event_type: String,
    pub message: String,
}

pub fn generate_from_config(config: &SaugraConfig) -> anyhow::Result<SecuritySummary> {
    let retention = EventLogRetention {
        max_size_bytes: config.event_log_max_size_bytes()?,
        max_files: config.logging.event_log_max_files,
    };
    let events = event_store::read_all(Path::new(&config.logging.event_log_path), retention)?;
    let mut summary = generate(
        &events,
        config.security_summary.lookback_seconds(),
        unix_seconds_now(),
        &config.security_summary.timezone,
    );
    summary.app_hostname = summary_app_hostname(config);
    Ok(summary)
}

pub fn generate(
    events: &[SecurityEvent],
    lookback_seconds: u64,
    now: u64,
    timezone: &str,
) -> SecuritySummary {
    let window_start = now.saturating_sub(lookback_seconds);
    let mut total_security_events = 0;
    let mut blocked_events = 0;
    let mut monitored_events = 0;
    let mut allowed_runtime_policy_events = 0;
    let mut rate_limit_events = 0;
    let mut bot_events = 0;
    let mut behavior_threshold_events = 0;
    let mut categories = BTreeMap::<String, usize>::new();
    let mut rules = BTreeMap::<String, usize>::new();
    let mut source_ips = BTreeMap::<String, usize>::new();
    let mut paths = BTreeMap::<String, usize>::new();
    let mut important_blocked_request_ids = Vec::new();

    for event in events
        .iter()
        .filter(|event| event_unix_seconds(event).is_some_and(|ts| ts >= window_start && ts <= now))
    {
        total_security_events += 1;
        *source_ips.entry(event.client_ip.clone()).or_default() += 1;
        *paths.entry(event.path.clone()).or_default() += 1;

        match event.decision.action {
            WafAction::Block => {
                blocked_events += 1;
                if important_blocked_request_ids.len() < 10 {
                    important_blocked_request_ids.push(event.decision.request_id.clone());
                }
            }
            WafAction::Monitor => monitored_events += 1,
            WafAction::Allow => {}
        }

        if event.decision.runtime_allowlist.is_some() && event.decision.action == WafAction::Allow {
            allowed_runtime_policy_events += 1;
        }

        if event.decision.bot_protection.is_some() {
            bot_events += 1;
        }

        if event.decision.behavior.is_some() {
            behavior_threshold_events += 1;
        }

        if event.owasp_categories.is_empty() {
            *categories.entry("none".to_string()).or_default() += 1;
        } else {
            for category in &event.owasp_categories {
                *categories.entry(category.clone()).or_default() += 1;
            }
        }

        for rule_match in &event.decision.matched_rules {
            *rules.entry(rule_match.rule_id.clone()).or_default() += 1;
            if matches!(
                rule_match.category.as_str(),
                "rate_limit" | "rate_limit_abuse"
            ) {
                rate_limit_events += 1;
            }
        }
    }

    SecuritySummary {
        app_hostname: None,
        generated_at_unix_seconds: now,
        timezone: timezone.to_string(),
        lookback_seconds,
        window_start_unix_seconds: window_start,
        window_end_unix_seconds: now,
        total_security_events,
        blocked_events,
        monitored_events,
        allowed_runtime_policy_events,
        rate_limit_events,
        bot_events,
        behavior_threshold_events,
        top_attack_categories: top_counts(categories, 10),
        top_matched_rules: top_counts(rules, 10),
        top_source_ips: top_counts(source_ips, 10),
        top_targeted_paths: top_counts(paths, 10),
        important_blocked_request_ids,
    }
}

pub fn send_from_config(config: &SaugraConfig) -> anyhow::Result<DeliveryReport> {
    let summary = generate_from_config(config)?;
    match deliver(config, &summary) {
        Ok(report) => Ok(report),
        Err(error) => {
            error!(%error, "security summary delivery failed");
            let message = error.to_string();
            if let Err(record_error) = append_admin_event(
                &admin_event_path(&config.security_summary.output_path),
                SummaryAdminEvent {
                    timestamp_unix_seconds: unix_seconds_now(),
                    event_type: "security_summary_delivery_failed".to_string(),
                    message,
                },
            ) {
                error!(%record_error, "failed to record security summary admin event");
            }
            Err(error)
        }
    }
}

pub fn deliver(config: &SaugraConfig, summary: &SecuritySummary) -> anyhow::Result<DeliveryReport> {
    let mut output_path = None;
    let mut email_recipients = Vec::new();

    for channel in &config.security_summary.channels {
        match channel.channel_type.as_str() {
            "file" => {
                let path = render_output_path(
                    &config.security_summary.output_path,
                    summary.generated_at_unix_seconds,
                    &config.security_summary.timezone,
                );
                write_summary_file(&path, summary)?;
                info!(path = %path.display(), "wrote security summary");
                output_path = Some(path);
            }
            "email" => {
                send_email(channel, summary).inspect_err(|error| {
                    error!(%error, "failed to deliver security summary email");
                })?;
                email_recipients.extend(channel.to.iter().cloned());
            }
            _ => {}
        }
    }

    Ok(DeliveryReport {
        output_path,
        email_recipients,
    })
}

fn write_summary_file(path: &Path, summary: &SecuritySummary) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(summary)?)?;
    Ok(())
}

fn append_admin_event(path: &Path, event: SummaryAdminEvent) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}

fn admin_event_path(output_path: &Path) -> PathBuf {
    output_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("saugra-waf-security-summary-admin-events.jsonl")
}

fn send_email(
    channel: &SecuritySummaryChannelConfig,
    summary: &SecuritySummary,
) -> anyhow::Result<()> {
    let from = channel
        .from
        .as_deref()
        .unwrap_or("saugra-waf@localhost")
        .trim();
    let subject = summary_email_subject(summary);
    let mut child = Command::new(&channel.sendmail_path)
        .arg("-t")
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start sendmail at {}", channel.sendmail_path))?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open sendmail stdin")?;
    write!(
        stdin,
        "{}",
        build_email_message(from, &channel.to, &subject, summary)
    )?;
    drop(stdin);

    let status = child.wait().context("failed to wait for sendmail")?;
    if !status.success() {
        anyhow::bail!("sendmail exited with status {status}");
    }
    Ok(())
}

fn build_email_message(
    from: &str,
    to: &[String],
    subject: &str,
    summary: &SecuritySummary,
) -> String {
    let boundary = "saugra-waf-security-summary-boundary";
    let text = render_summary_text(summary);
    let html = render_summary_html(summary);

    format!(
        "From: {from}\nTo: {to}\nSubject: {subject}\nMIME-Version: 1.0\nContent-Type: multipart/alternative; boundary=\"{boundary}\"\n\n--{boundary}\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n{text}\n\n--{boundary}\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: 8bit\n\n{html}\n\n--{boundary}--\n",
        to = to.join(", ")
    )
}

fn summary_email_subject(summary: &SecuritySummary) -> String {
    format!(
        "Saugra WAF daily security summary - {} events, {} blocked",
        format_number(summary.total_security_events),
        format_number(summary.blocked_events)
    )
}

fn summary_app_hostname(config: &SaugraConfig) -> Option<String> {
    config
        .upstreams
        .iter()
        .map(|upstream| upstream.host.trim())
        .find(|host| !host.is_empty())
        .map(|host| host.to_ascii_uppercase())
}

fn summary_header_title(summary: &SecuritySummary) -> String {
    match summary.app_hostname.as_deref().map(str::trim) {
        Some(hostname) if !hostname.is_empty() => {
            format!("Saugra WAF - {}", hostname.to_ascii_uppercase())
        }
        _ => "Saugra WAF".to_string(),
    }
}

fn render_summary_text(summary: &SecuritySummary) -> String {
    let mut text = String::new();
    text.push_str(&summary_header_title(summary));
    text.push_str(" Daily Security Summary\n");
    text.push_str(&format!(
        "Window: {} to {} ({})\n\n",
        local_datetime(summary.window_start_unix_seconds, &summary.timezone),
        local_datetime(summary.window_end_unix_seconds, &summary.timezone),
        summary.timezone
    ));
    text.push_str(&format!(
        "Total events: {}\nBlocked: {}\nMonitored: {}\nRuntime policy allowed: {}\nRate-limit events: {}\nBot events: {}\nBehavior threshold events: {}\n\n",
        format_number(summary.total_security_events),
        format_number(summary.blocked_events),
        format_number(summary.monitored_events),
        format_number(summary.allowed_runtime_policy_events),
        format_number(summary.rate_limit_events),
        format_number(summary.bot_events),
        format_number(summary.behavior_threshold_events),
    ));
    append_text_counts(
        &mut text,
        "Top attack categories",
        &summary.top_attack_categories,
    );
    append_text_counts(&mut text, "Top matched rules", &summary.top_matched_rules);
    append_text_counts(&mut text, "Top source IPs", &summary.top_source_ips);
    append_text_counts(&mut text, "Top targeted paths", &summary.top_targeted_paths);
    if !summary.important_blocked_request_ids.is_empty() {
        text.push_str("Important blocked request IDs:\n");
        for request_id in &summary.important_blocked_request_ids {
            text.push_str(&format!("- {request_id}\n"));
        }
    }
    text.push_str(
        "\nExplain a request on the server with: saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml\n",
    );
    text
}

fn append_text_counts(text: &mut String, title: &str, counts: &[SummaryCount]) {
    text.push_str(title);
    text.push('\n');
    if counts.is_empty() {
        text.push_str("- none\n\n");
        return;
    }
    for item in counts {
        text.push_str(&format!("- {}: {}\n", item.name, format_number(item.count)));
    }
    text.push('\n');
}

fn render_summary_html(summary: &SecuritySummary) -> String {
    let block_rate = percentage(summary.blocked_events, summary.total_security_events);
    let monitor_rate = percentage(summary.monitored_events, summary.total_security_events);
    let window_start = local_datetime(summary.window_start_unix_seconds, &summary.timezone);
    let window_end = local_datetime(summary.window_end_unix_seconds, &summary.timezone);
    let generated_at = local_datetime(summary.generated_at_unix_seconds, &summary.timezone);
    let header_title = summary_header_title(summary);
    let status = if summary.blocked_events > 0 {
        "Blocking active"
    } else if summary.monitored_events > 0 {
        "Monitor activity observed"
    } else {
        "No security activity"
    };

    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Saugra WAF Daily Security Summary</title>
</head>
<body style="margin:0;padding:0;background:#f4f6f8;color:#17202a;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f6f8;padding:24px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="760" cellspacing="0" cellpadding="0" style="max-width:760px;width:94%;background:#ffffff;border:1px solid #d9e2ec;border-radius:8px;overflow:hidden;">
          <tr>
            <td align="center" style="background:#111827;color:#ffffff;padding:24px 28px;text-align:center;">
              <div style="font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:#9ca3af;">{header_title}</div>
              <h1 style="margin:8px 0 6px;font-size:24px;line-height:1.25;">Daily Security Summary</h1>
              <div style="font-size:14px;color:#d1d5db;">{window_start} to {window_end} ({timezone})</div>
            </td>
          </tr>
          <tr>
            <td style="padding:22px 28px 10px;">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  {total_card}
                  {blocked_card}
                  {monitored_card}
                </tr>
              </table>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="margin-top:12px;">
                <tr>
                  {bot_card}
                  {behavior_card}
                  {rate_card}
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:8px 28px 18px;">
              <div style="border:1px solid #dbeafe;background:#eff6ff;border-radius:6px;padding:14px 16px;">
                <div style="font-size:14px;font-weight:bold;color:#1e3a8a;">Status: {status}</div>
                <div style="font-size:13px;color:#1f2937;margin-top:4px;">Blocked rate: {block_rate} &middot; Monitor rate: {monitor_rate} &middot; Generated at {generated_at}</div>
              </div>
            </td>
          </tr>
          {categories}
          {rules}
          {ips}
          {paths}
          {blocked_ids}
          <tr>
            <td style="padding:18px 28px 24px;color:#6b7280;font-size:12px;border-top:1px solid #e5e7eb;">
              This report is generated from local Saugra security events. Use <code>saugra-waf explain &lt;request-id&gt; --config /etc/saugra-waf/saugra-waf.yml</code> on the server for detailed analysis of a specific request.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"#,
        timezone = html_escape(&summary.timezone),
        header_title = html_escape(&header_title),
        total_card = metric_card("Total Events", summary.total_security_events, "#111827"),
        blocked_card = metric_card("Blocked", summary.blocked_events, "#b91c1c"),
        monitored_card = metric_card("Monitored", summary.monitored_events, "#b45309"),
        bot_card = metric_card("Bot Events", summary.bot_events, "#4338ca"),
        behavior_card = metric_card(
            "Behavior Events",
            summary.behavior_threshold_events,
            "#047857"
        ),
        rate_card = metric_card("Rate Limits", summary.rate_limit_events, "#0f766e"),
        categories = html_count_section("Top Attack Categories", &summary.top_attack_categories),
        rules = html_count_section("Top Matched Rules", &summary.top_matched_rules),
        ips = html_count_section("Top Source IPs", &summary.top_source_ips),
        paths = html_count_section("Top Targeted Paths", &summary.top_targeted_paths),
        blocked_ids = html_blocked_ids(&summary.important_blocked_request_ids),
    )
}

fn metric_card(label: &str, value: usize, color: &str) -> String {
    format!(
        r#"<td width="33.33%" style="padding:6px;">
          <div style="border:1px solid #e5e7eb;border-radius:6px;padding:14px;background:#ffffff;">
            <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em;">{}</div>
            <div style="font-size:24px;line-height:1.2;font-weight:bold;color:{};margin-top:6px;">{}</div>
          </div>
        </td>"#,
        html_escape(label),
        color,
        format_number(value)
    )
}

fn html_count_section(title: &str, counts: &[SummaryCount]) -> String {
    let rows = if counts.is_empty() {
        r#"<tr><td colspan="3" style="padding:10px;border-top:1px solid #e5e7eb;color:#6b7280;">No data</td></tr>"#.to_string()
    } else {
        counts
            .iter()
            .enumerate()
            .map(|(index, item)| {
                format!(
                    r#"<tr>
              <td style="padding:9px 10px;border-top:1px solid #e5e7eb;color:#6b7280;width:42px;">{}</td>
              <td style="padding:9px 10px;border-top:1px solid #e5e7eb;color:#111827;">{}</td>
              <td align="right" style="padding:9px 10px;border-top:1px solid #e5e7eb;color:#111827;font-weight:bold;width:110px;">{}</td>
            </tr>"#,
                    index + 1,
                    html_escape(&item.name),
                    format_number(item.count)
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    format!(
        r#"<tr>
            <td style="padding:10px 28px 18px;">
              <h2 style="font-size:16px;margin:0 0 8px;color:#111827;">{}</h2>
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="border:1px solid #e5e7eb;border-radius:6px;border-collapse:separate;border-spacing:0;overflow:hidden;">
                {}
              </table>
            </td>
          </tr>"#,
        html_escape(title),
        rows
    )
}

fn html_blocked_ids(request_ids: &[String]) -> String {
    if request_ids.is_empty() {
        return String::new();
    }

    let items = request_ids
        .iter()
        .map(|request_id| {
            format!(
                r#"<li style="margin:4px 0;"><code>{}</code></li>"#,
                html_escape(request_id)
            )
        })
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<tr>
            <td style="padding:10px 28px 18px;">
              <h2 style="font-size:16px;margin:0 0 8px;color:#111827;">Important Blocked Request IDs</h2>
              <div style="border:1px solid #fee2e2;background:#fef2f2;border-radius:6px;padding:12px 16px;">
                <ul style="margin:0;padding-left:18px;color:#7f1d1d;">{items}</ul>
              </div>
            </td>
          </tr>"#
    )
}

fn percentage(part: usize, total: usize) -> String {
    if total == 0 {
        return "0.0%".to_string();
    }
    format!("{:.1}%", (part as f64 / total as f64) * 100.0)
}

fn format_number(value: usize) -> String {
    let value = value.to_string();
    let mut formatted = String::new();
    for (index, character) in value.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            formatted.push(',');
        }
        formatted.push(character);
    }
    formatted.chars().rev().collect()
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn top_counts(counts: BTreeMap<String, usize>, limit: usize) -> Vec<SummaryCount> {
    let mut counts = counts
        .into_iter()
        .map(|(name, count)| SummaryCount { name, count })
        .collect::<Vec<_>>();
    counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    counts.truncate(limit);
    counts
}

fn event_unix_seconds(event: &SecurityEvent) -> Option<u64> {
    rfc3339_to_unix_seconds(&event.timestamp)
}

fn render_output_path(path: &Path, unix_seconds: u64, timezone: &str) -> PathBuf {
    let rendered = path
        .to_string_lossy()
        .replace("YYYY-MM-DD", &local_date(unix_seconds, timezone));
    PathBuf::from(rendered)
}

fn rfc3339_to_unix_seconds(value: &str) -> Option<u64> {
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

fn local_date(unix_seconds: u64, timezone: &str) -> String {
    let (year, month, day, _, _, _) = local_date_time_parts(unix_seconds, timezone);
    format!("{year:04}-{month:02}-{day:02}")
}

fn local_datetime(unix_seconds: u64, timezone: &str) -> String {
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

fn unix_seconds_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        behavior::BehaviorOutcome,
        bot::BotProtectionOutcome,
        decision::{WafAction, WafDecision},
        event_store::SecurityEvent,
        rules::{RuleMatch, RuleSeverity, RuleTarget},
    };

    #[test]
    fn daily_summary_filters_to_lookback_and_aggregates_top_values() {
        let now = rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap();
        let events = vec![
            event(
                "2026-05-22T07:00:00Z",
                "1",
                "203.0.113.10",
                "/login",
                WafAction::Block,
                "SAUGRA-SQLI-001",
                "sql_injection",
            ),
            event(
                "2026-05-22T06:00:00Z",
                "2",
                "203.0.113.10",
                "/login",
                WafAction::Monitor,
                "SAUGRA-RATE-001",
                "rate_limit",
            ),
            event(
                "2026-05-20T06:00:00Z",
                "old",
                "203.0.113.11",
                "/old",
                WafAction::Block,
                "OLD",
                "sql_injection",
            ),
        ];

        let summary = generate(&events, 24 * 60 * 60, now, "UTC");

        assert_eq!(summary.total_security_events, 2);
        assert_eq!(summary.blocked_events, 1);
        assert_eq!(summary.monitored_events, 1);
        assert_eq!(summary.rate_limit_events, 1);
        assert_eq!(summary.top_source_ips[0].name, "203.0.113.10");
        assert_eq!(summary.top_source_ips[0].count, 2);
        assert_eq!(summary.top_targeted_paths[0].name, "/login");
        assert_eq!(summary.important_blocked_request_ids, vec!["1"]);
    }

    #[test]
    fn empty_day_summary_has_zero_counts() {
        let summary = generate(&[], 24 * 60 * 60, 1_779_439_200, "Africa/Nairobi");

        assert_eq!(summary.total_security_events, 0);
        assert!(summary.top_attack_categories.is_empty());
        assert!(summary.important_blocked_request_ids.is_empty());
        assert_eq!(summary.timezone, "Africa/Nairobi");
    }

    #[test]
    fn output_path_replaces_local_date_token() {
        let path = render_output_path(
            Path::new("/tmp/saugra-waf-security-summary-YYYY-MM-DD.json"),
            rfc3339_to_unix_seconds("2026-05-21T22:30:00Z").unwrap(),
            "Africa/Nairobi",
        );

        assert_eq!(
            path,
            PathBuf::from("/tmp/saugra-waf-security-summary-2026-05-22.json")
        );
    }

    #[test]
    fn email_message_uses_html_body_instead_of_json_attachment_style() {
        let summary = SecuritySummary {
            app_hostname: Some("example.com".to_string()),
            generated_at_unix_seconds: rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap(),
            timezone: "Africa/Nairobi".to_string(),
            lookback_seconds: 86_400,
            window_start_unix_seconds: rfc3339_to_unix_seconds("2026-05-21T08:00:00Z").unwrap(),
            window_end_unix_seconds: rfc3339_to_unix_seconds("2026-05-22T08:00:00Z").unwrap(),
            total_security_events: 41_408,
            blocked_events: 0,
            monitored_events: 29_498,
            allowed_runtime_policy_events: 0,
            rate_limit_events: 0,
            bot_events: 41_408,
            behavior_threshold_events: 41_408,
            top_attack_categories: vec![SummaryCount {
                name: "A06:2025-Insecure Design".to_string(),
                count: 29_493,
            }],
            top_matched_rules: vec![SummaryCount {
                name: "SAUGRA-BOT-PROTECTION-001".to_string(),
                count: 29_469,
            }],
            top_source_ips: vec![SummaryCount {
                name: "62.164.177.222".to_string(),
                count: 4_218,
            }],
            top_targeted_paths: vec![SummaryCount {
                name: "/altcha/challenge/".to_string(),
                count: 4_969,
            }],
            important_blocked_request_ids: Vec::new(),
        };

        let message = build_email_message(
            "saugra-waf@example.com",
            &["security@example.com".to_string()],
            &summary_email_subject(&summary),
            &summary,
        );

        assert!(message.contains("Content-Type: multipart/alternative"));
        assert!(message.contains("Content-Type: text/html; charset=UTF-8"));
        assert!(message.contains("Saugra WAF - EXAMPLE.COM"));
        assert!(message.contains("text-align:center"));
        assert!(message.contains(
            "saugra-waf explain &lt;request-id&gt; --config /etc/saugra-waf/saugra-waf.yml"
        ));
        assert!(message
            .contains("saugra-waf explain <request-id> --config /etc/saugra-waf/saugra-waf.yml"));
        assert!(message.contains("41,408"));
        assert!(message.contains("SAUGRA-BOT-PROTECTION-001"));
        assert!(!message.contains("Content-Type: application/json"));
        assert!(!message.contains("\"generated_at_unix_seconds\""));
    }

    #[test]
    fn delivery_failure_records_local_admin_event() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = SaugraConfig {
            server: crate::config::ServerConfig {
                listen: "127.0.0.1:0".to_string(),
                mode: crate::config::WafMode::Monitor,
            },
            upstreams: vec![crate::config::UpstreamConfig {
                name: "app".to_string(),
                host: "example.com".to_string(),
                target: "http://127.0.0.1:8000".to_string(),
            }],
            routes: Vec::new(),
            security: Default::default(),
            forwarded_headers: Default::default(),
            rate_limit: Default::default(),
            behavior: Default::default(),
            bot_protection: Default::default(),
            runtime_policy: Default::default(),
            rules: Default::default(),
            ai: Default::default(),
            logging: crate::config::LoggingConfig {
                event_log_path: temp_dir.path().join("events.jsonl").display().to_string(),
                ..Default::default()
            },
            websocket: Default::default(),
            posture: Default::default(),
            reports: Default::default(),
            standards: Default::default(),
            security_summary: crate::config::SecuritySummaryConfig {
                output_path: temp_dir.path().join("summary.json"),
                channels: vec![crate::config::SecuritySummaryChannelConfig {
                    channel_type: "email".to_string(),
                    to: vec!["security@example.com".to_string()],
                    from: Some("saugra-waf@example.com".to_string()),
                    sendmail_path: temp_dir
                        .path()
                        .join("missing-sendmail")
                        .display()
                        .to_string(),
                }],
                ..Default::default()
            },
            storage_cleanup: Default::default(),
        };

        assert!(send_from_config(&config).is_err());
        let admin_events = fs::read_to_string(
            temp_dir
                .path()
                .join("saugra-waf-security-summary-admin-events.jsonl"),
        )
        .unwrap();

        assert!(admin_events.contains("security_summary_delivery_failed"));
    }

    fn event(
        timestamp: &str,
        request_id: &str,
        client_ip: &str,
        path: &str,
        action: WafAction,
        rule_id: &str,
        category: &str,
    ) -> SecurityEvent {
        let decision = WafDecision {
            request_id: request_id.to_string(),
            action,
            matched_rules: vec![RuleMatch {
                rule_id: rule_id.to_string(),
                rule_name: rule_id.to_string(),
                category: category.to_string(),
                severity: RuleSeverity::High,
                matched_target: RuleTarget::Headers,
                paranoia_level: 1,
                explanation: "test".to_string(),
                owasp_category: Some("A06:2025-Insecure Design".to_string()),
            }],
            severity: "high".to_string(),
            risk_score: 80,
            anomaly_score: 5,
            blocking_anomaly_score: 5,
            anomaly_threshold: 5,
            blocking_paranoia_level: 1,
            explanation: "test".to_string(),
            owasp_category: Some("A06:2025-Insecure Design".to_string()),
            owasp_categories: vec!["A06:2025-Insecure Design".to_string()],
            behavior: if category == "behavior_abuse" {
                Some(BehaviorOutcome {
                    enabled: true,
                    action,
                    score: 80,
                    monitor_threshold: 40,
                    block_threshold: 80,
                    score_window_seconds: 600,
                    decay_window_seconds: 1_800,
                    storage_backend: "local".to_string(),
                    contributors: Vec::new(),
                })
            } else {
                None
            },
            bot_protection: if category == "bot_protection" {
                Some(BotProtectionOutcome {
                    enabled: true,
                    action,
                    score: 80,
                    monitor_threshold: 40,
                    block_threshold: 80,
                    score_window_seconds: 600,
                    temporary_block_duration_seconds: 900,
                    temporary_blocked_until: None,
                    storage_backend: "local".to_string(),
                    allowlisted: false,
                    blocklisted: false,
                    contributors: Vec::new(),
                })
            } else {
                None
            },
            runtime_allowlist: None,
        };

        SecurityEvent {
            timestamp: timestamp.to_string(),
            client_ip: client_ip.to_string(),
            method: "GET".to_string(),
            path: path.to_string(),
            query: String::new(),
            owasp_categories: decision.owasp_categories.clone(),
            upstream: None,
            websocket: None,
            decision,
        }
    }
}
