mod payloads;
mod prompts;

use anyhow::Context;
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header, Request, StatusCode},
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};

use crate::{
    ai::provider::ExplanationProvider,
    ai::types::{ExplanationInput, ProviderOutput},
    config::AiConfig,
};

pub(crate) use payloads::*;

pub(crate) struct LocalExplanationProvider {
    pub(crate) model: String,
}

#[async_trait]
impl ExplanationProvider for LocalExplanationProvider {
    fn name(&self) -> &str {
        "local"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        Ok(ProviderOutput {
            explanation: input.deterministic_explanation.clone(),
            tuning_suggestions: input.deterministic_tuning_suggestions.clone(),
        })
    }
}

pub(crate) struct CommandExplanationProvider {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) model: String,
}

pub(crate) struct OllamaExplanationProvider {
    pub(crate) base_url: String,
    pub(crate) model: String,
}

pub(crate) struct LlamaCppExplanationProvider {
    pub(crate) base_url: String,
    pub(crate) model: String,
}

pub(crate) struct OpenAiCompatibleExplanationProvider {
    pub(crate) endpoint: String,
    pub(crate) api_key_env: String,
    pub(crate) model: String,
}

pub(crate) struct GeminiExplanationProvider {
    pub(crate) endpoint: String,
    pub(crate) api_key_env: String,
    pub(crate) model: String,
}

#[async_trait]
impl ExplanationProvider for OpenAiCompatibleExplanationProvider {
    fn name(&self) -> &str {
        "openai_compatible"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let api_key = std::env::var(&self.api_key_env)
            .with_context(|| format!("AI secret reference {} is unavailable", self.api_key_env))?;
        let response = reqwest::Client::new()
            .post(&self.endpoint)
            .bearer_auth(api_key)
            .json(&openai_compatible_request_payload(&self.model, input)?)
            .send()
            .await
            .context("failed to connect to OpenAI-compatible provider")?;
        let status = response.status();
        let body = response.bytes().await?;
        ensure_remote_success(status.as_u16(), &body, "OpenAI-compatible")?;
        parse_chat_completion_response(&body, "OpenAI-compatible")
    }
}

#[async_trait]
impl ExplanationProvider for GeminiExplanationProvider {
    fn name(&self) -> &str {
        "gemini"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let api_key = std::env::var(&self.api_key_env)
            .with_context(|| format!("AI secret reference {} is unavailable", self.api_key_env))?;
        let endpoint = self.endpoint.replace("{model}", &self.model);
        let response = reqwest::Client::new()
            .post(endpoint)
            .header("x-goog-api-key", api_key)
            .json(&gemini_request_payload(input)?)
            .send()
            .await
            .context("failed to connect to Gemini provider")?;
        let status = response.status();
        let body = response.bytes().await?;
        ensure_remote_success(status.as_u16(), &body, "Gemini")?;
        parse_gemini_response(&body)
    }
}

#[async_trait]
impl ExplanationProvider for LlamaCppExplanationProvider {
    fn name(&self) -> &str {
        "llama_cpp"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let payload = llama_cpp_request_payload(&self.model, input)?;
        let uri = llama_cpp_chat_completions_url(&self.base_url);
        let request = Request::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&payload)?))
            .context("failed to build llama.cpp request")?;
        let client: Client<HttpConnector, Body> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        let response = client
            .request(request)
            .await
            .context("failed to connect to local llama.cpp server")?;
        let status = response.status();
        let body = to_bytes(response.map(Body::new).into_body(), 1024 * 1024)
            .await
            .context("failed to read llama.cpp response")?;
        if status != StatusCode::OK {
            return Err(anyhow::anyhow!(
                "llama.cpp returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        parse_chat_completion_response(&body, "llama.cpp")
    }
}

#[async_trait]
impl ExplanationProvider for OllamaExplanationProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let payload = ollama_request_payload(&self.model, input)?;
        let uri = ollama_generate_url(&self.base_url);
        let request = Request::post(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&payload)?))
            .context("failed to build Ollama request")?;
        let client: Client<HttpConnector, Body> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        let response = client
            .request(request)
            .await
            .context("failed to connect to local Ollama")?;
        let status = response.status();
        let body = to_bytes(response.map(Body::new).into_body(), 1024 * 1024)
            .await
            .context("failed to read Ollama response")?;
        if status != StatusCode::OK {
            return Err(anyhow::anyhow!(
                "Ollama returned HTTP {}: {}",
                status,
                String::from_utf8_lossy(&body)
            ));
        }
        parse_ollama_response(&body)
    }
}

#[async_trait]
impl ExplanationProvider for CommandExplanationProvider {
    fn name(&self) -> &str {
        "command"
    }

    fn model(&self) -> &str {
        &self.model
    }

    async fn explain(&self, input: &ExplanationInput) -> anyhow::Result<ProviderOutput> {
        let encoded = serde_json::to_vec(input)?;
        run_provider_command(&self.program, &self.args, &encoded).await
    }
}

pub(crate) fn build_provider(config: &AiConfig) -> Box<dyn ExplanationProvider> {
    if config.enabled {
        match config.provider.as_str() {
            "llama_cpp" => {
                return Box::new(LlamaCppExplanationProvider {
                    base_url: config.llama_cpp_url.clone(),
                    model: config.model.clone(),
                });
            }
            "ollama" => {
                return Box::new(OllamaExplanationProvider {
                    base_url: config.ollama_url.clone(),
                    model: config.model.clone(),
                });
            }
            "openai_compatible" => {
                return Box::new(OpenAiCompatibleExplanationProvider {
                    endpoint: config.endpoint.clone().unwrap_or_default(),
                    api_key_env: config.api_key_env.clone().unwrap_or_default(),
                    model: config.model.clone(),
                });
            }
            "gemini" => {
                return Box::new(GeminiExplanationProvider {
                    endpoint: config.endpoint.clone().unwrap_or_default(),
                    api_key_env: config.api_key_env.clone().unwrap_or_default(),
                    model: config.model.clone(),
                });
            }
            "command" => {
                return Box::new(CommandExplanationProvider {
                    program: config.command.clone().unwrap_or_default(),
                    args: config.command_args.clone(),
                    model: config.model.clone(),
                });
            }
            _ => {}
        }
    }
    Box::new(LocalExplanationProvider {
        model: "deterministic-local".to_string(),
    })
}

pub(crate) fn local_output(input: &ExplanationInput) -> ProviderOutput {
    ProviderOutput {
        explanation: input.deterministic_explanation.clone(),
        tuning_suggestions: input.deterministic_tuning_suggestions.clone(),
    }
}
