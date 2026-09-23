use std::process::Stdio;

use anyhow::Context;
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncWriteExt;

use super::prompts::*;
use crate::ai::types::{ExplanationInput, ProviderOutput};

#[derive(Debug, Deserialize)]
pub(super) struct OllamaGenerateResponse {
    pub(super) response: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatCompletionResponse {
    pub(super) choices: Vec<ChatCompletionChoice>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatCompletionChoice {
    pub(super) message: ChatCompletionMessage,
}

#[derive(Debug, Deserialize)]
pub(super) struct ChatCompletionMessage {
    pub(super) content: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct GeminiGenerateResponse {
    pub(super) candidates: Vec<GeminiCandidate>,
}

#[derive(Debug, Deserialize)]
pub(super) struct GeminiCandidate {
    pub(super) content: GeminiContent,
}

#[derive(Debug, Deserialize)]
pub(super) struct GeminiContent {
    pub(super) parts: Vec<GeminiPart>,
}

#[derive(Debug, Deserialize)]
pub(super) struct GeminiPart {
    pub(super) text: String,
}

pub(crate) fn ollama_request_payload(
    model: &str,
    input: &ExplanationInput,
) -> anyhow::Result<serde_json::Value> {
    Ok(json!({
        "model": model,
        "system": explanation_system_prompt(),
        "prompt": explanation_user_prompt(input)?,
        "stream": false,
        "think": false,
        "format": explanation_output_schema(),
        "options": {
            "temperature": 0,
            "num_predict": 256
        }
    }))
}

pub(crate) fn llama_cpp_request_payload(
    model: &str,
    input: &ExplanationInput,
) -> anyhow::Result<serde_json::Value> {
    Ok(json!({
        "model": model,
        "messages": [
            {"role": "system", "content": explanation_system_prompt()},
            {"role": "user", "content": explanation_user_prompt(input)?}
        ],
        "stream": false,
        "temperature": 0.1,
        "max_tokens": 256,
        "chat_template_kwargs": {
            "enable_thinking": false
        },
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "saugra_explanation",
                "strict": true,
                "schema": explanation_output_schema()
            }
        }
    }))
}

pub(crate) fn openai_compatible_request_payload(
    model: &str,
    input: &ExplanationInput,
) -> anyhow::Result<serde_json::Value> {
    Ok(json!({
        "model": model,
        "messages": [
            {"role": "system", "content": explanation_system_prompt()},
            {"role": "user", "content": explanation_user_prompt(input)?}
        ],
        "temperature": 0,
        "max_tokens": 256,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "saugra_explanation",
                "strict": true,
                "schema": explanation_output_schema()
            }
        }
    }))
}

pub(crate) fn gemini_request_payload(
    input: &ExplanationInput,
) -> anyhow::Result<serde_json::Value> {
    Ok(json!({
        "systemInstruction": {
            "parts": [{"text": explanation_system_prompt()}]
        },
        "contents": [{
            "role": "user",
            "parts": [{"text": explanation_user_prompt(input)?}]
        }],
        "generationConfig": {
            "temperature": 0,
            "maxOutputTokens": 256,
            "responseMimeType": "application/json",
            "responseJsonSchema": explanation_output_schema()
        }
    }))
}

pub(crate) fn ollama_generate_url(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/api") {
        format!("{base_url}/generate")
    } else {
        format!("{base_url}/api/generate")
    }
}

pub(crate) fn llama_cpp_chat_completions_url(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/v1") {
        format!("{base_url}/chat/completions")
    } else {
        format!("{base_url}/v1/chat/completions")
    }
}

pub(crate) fn parse_ollama_response(body: &[u8]) -> anyhow::Result<ProviderOutput> {
    let response: OllamaGenerateResponse =
        serde_json::from_slice(body).context("Ollama response must be valid JSON")?;
    let output: ProviderOutput = serde_json::from_str(&response.response)
        .context("Ollama generated response must match the explanation JSON schema")?;
    Ok(output)
}

pub(crate) fn parse_chat_completion_response(
    body: &[u8],
    provider_name: &str,
) -> anyhow::Result<ProviderOutput> {
    let response: ChatCompletionResponse = serde_json::from_slice(body)
        .with_context(|| format!("{provider_name} response must be valid JSON"))?;
    let content = response
        .choices
        .first()
        .map(|choice| choice.message.content.as_str())
        .filter(|content| !content.trim().is_empty())
        .with_context(|| format!("{provider_name} response must contain assistant content"))?;
    serde_json::from_str(json_content(content)).with_context(|| {
        format!("{provider_name} generated response must match the explanation JSON schema")
    })
}

fn json_content(content: &str) -> &str {
    let trimmed = content.trim();
    let Some(fenced) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let fenced = fenced
        .strip_prefix("json")
        .or_else(|| fenced.strip_prefix("JSON"))
        .unwrap_or(fenced)
        .trim_start();
    fenced
        .strip_suffix("```")
        .map(str::trim_end)
        .unwrap_or(fenced)
}

pub(crate) fn parse_gemini_response(body: &[u8]) -> anyhow::Result<ProviderOutput> {
    let response: GeminiGenerateResponse =
        serde_json::from_slice(body).context("Gemini response must be valid JSON")?;
    let content = response
        .candidates
        .first()
        .and_then(|candidate| candidate.content.parts.first())
        .map(|part| part.text.as_str())
        .filter(|content| !content.trim().is_empty())
        .context("Gemini response must contain candidate text")?;
    serde_json::from_str(content)
        .context("Gemini generated response must match the explanation JSON schema")
}

pub(crate) fn ensure_remote_success(
    status: u16,
    body: &[u8],
    provider: &str,
) -> anyhow::Result<()> {
    if status == 429 {
        anyhow::bail!("{provider} rate limit exceeded (HTTP 429)");
    }
    if !(200..300).contains(&status) {
        anyhow::bail!(
            "{provider} returned HTTP {status}: {}",
            String::from_utf8_lossy(body)
        );
    }
    Ok(())
}

pub(super) async fn run_provider_command(
    program: &str,
    args: &[String],
    input: &[u8],
) -> anyhow::Result<ProviderOutput> {
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to start AI provider command {program}"))?;
    child
        .stdin
        .take()
        .context("AI provider stdin unavailable")?
        .write_all(input)
        .await?;
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "AI provider exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).context("AI provider output must be valid JSON")
}
