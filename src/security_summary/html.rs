use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::Context;
use tracing::{error, info};

use super::{
    date::{local_datetime, render_output_path, unix_seconds_now},
    SecuritySummary, SummaryAdminEvent, SummaryCount,
};
use crate::config::{SaugraConfig, SecuritySummaryChannelConfig};

pub(super) fn send_from_config_internal(
    config: &SaugraConfig,
) -> anyhow::Result<super::DeliveryReport> {
    let summary = super::generate_from_config(config)?;
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

pub(super) fn deliver(
    config: &SaugraConfig,
    summary: &SecuritySummary,
) -> anyhow::Result<super::DeliveryReport> {
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

    Ok(super::DeliveryReport {
        output_path,
        email_recipients,
    })
}

pub(super) fn admin_event_path(output_path: &Path) -> PathBuf {
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
    use std::io::Write;
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

pub fn build_email_message(
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

pub fn summary_email_subject(summary: &SecuritySummary) -> String {
    format!(
        "Saugra WAF daily security summary - {} events, {} blocked",
        format_number(summary.total_security_events),
        format_number(summary.blocked_events)
    )
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
    text.push_str("\nExplain a request on the server with:\n");
    text.push_str("  saugra-waf explain <request-id>\n");
    text.push_str("Warning: ");
    text.push_str(&summary_retention_text(summary));
    text.push('\n');
    text
}

pub(super) fn summary_retention_text(summary: &SecuritySummary) -> String {
    match (
        summary.event_log_max_size.as_deref(),
        summary.event_log_max_files,
    ) {
        (Some(max_size), Some(max_files)) => format!(
            "Request IDs remain explainable only while their events are in the active log or {max_files} retained rotated files of up to {max_size} each. Retention is volume-based, not a fixed number of days."
        ),
        _ => "Request IDs remain explainable only while their events are in the active or retained rotated logs. Retention is volume-based, not a fixed number of days.".to_string(),
    }
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
              <div>This report is generated from local Saugra security events. Use the following command on the server for detailed analysis of a specific request:</div>
              <div style="margin:10px 0 12px;">
                <code style="display:inline-block;padding:7px 10px;border:1px solid #d1d5db;border-radius:4px;background:#f3f4f6;color:#111827;font-family:'Courier New',Courier,monospace;font-size:12px;">saugra-waf explain &lt;request-id&gt;</code>
              </div>
              <div style="padding:9px 11px;border-left:3px solid #d97706;background:#fffbeb;color:#92400e;">
                <strong>Warning:</strong> {retention_text}
              </div>
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
        retention_text = html_escape(&summary_retention_text(summary)),
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

pub(super) fn write_summary_file(path: &Path, summary: &SecuritySummary) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_vec_pretty(summary)?)?;
    Ok(())
}

fn append_admin_event(path: &Path, event: SummaryAdminEvent) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    use std::io::Write;
    writeln!(file, "{}", serde_json::to_string(&event)?)?;
    Ok(())
}
