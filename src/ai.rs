use crate::types::AiPlan;
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::time::Duration;

/// OpenAI-compatible client for the NVIDIA NIM API (https://integrate.api.nvidia.com/v1).
#[derive(Clone)]
pub struct NvClient {
    http: reqwest::Client,
    base_url: String,
    key: String,
    pub model: String,
}

/// Pull the assistant text out of an OpenAI/NIM completion message.
/// Modern reasoning models (GLM, GPT-OSS, Nemotron reasoning variants) put
/// their thinking into `reasoning_content` and may leave `content` null —
/// handle both.
pub fn message_text(msg: &Value) -> Option<String> {
    let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
    let reasoning = msg
        .get("reasoning_content")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let joined = match (content.trim().is_empty(), reasoning.trim().is_empty()) {
        (false, false) => format!("{}\n{}", content, reasoning),
        (false, true) => content.to_string(),
        (true, false) => reasoning.to_string(),
        (true, true) => String::new(),
    };
    if joined.trim().is_empty() {
        None
    } else {
        Some(joined)
    }
}

impl NvClient {
    pub fn new(base_url: &str, key: &str, model: &str) -> Self {
        NvClient {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(600))
                .connect_timeout(Duration::from_secs(20))
                .build()
                .expect("reqwest client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            key: key.to_string(),
            model: model.to_string(),
        }
    }

    pub async fn list_models(&self) -> Result<Vec<String>> {
        let url = format!("{}/models", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.key)
            .send()
            .await
            .context("NVIDIA /models request failed")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("NVIDIA API HTTP {}: {}", status, api_error_detail(&body)));
        }
        let v: Value = resp.json().await.context("bad /models JSON")?;
        let mut out = Vec::new();
        if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
            for m in data {
                if let Some(id) = m.get("id").and_then(|i| i.as_str()) {
                    out.push(id.to_string());
                }
            }
        }
        Ok(out)
    }

    /// List models, then find one that actually completes a chat (the account
    /// may only have access to some families; listed models may be EOL).
    /// Updates `self.model` to the verified working model.
    /// Returns (full model list, verification note).
    pub async fn connect_and_select(
        &mut self,
        preferred: Option<String>,
    ) -> Result<(Vec<String>, String)> {
        let models = self.list_models().await?;
        let (model, note) = self
            .auto_select(&models, preferred.clone())
            .await
            .map_err(|e| anyhow!("models listed ({}) but none usable: {}", models.len(), e))?;
        self.model = model;
        Ok((models, note))
    }

    /// Try the preferred model first, then ranked candidates from the list,
    /// pinging each until one actually responds. EOL models (HTTP 410),
    /// access-denied models, and dead listings are skipped with a note.
    async fn auto_select(&self, models: &[String], preferred: Option<String>) -> Result<(String, String)> {
        let mut tried: Vec<String> = Vec::new();
        let mut last_err = String::new();

        for cand in candidates(models, preferred.clone()) {
            if tried.iter().any(|t| t == &cand) {
                continue;
            }
            tried.push(cand.clone());
            match tokio::time::timeout(Duration::from_secs(90), self.ping(&cand)).await {
                Ok(Ok(())) => {
                    let is_preferred = preferred.as_deref() == Some(cand.as_str());
                    let note = if is_preferred {
                        format!("chat verified against {}", cand)
                    } else {
                        format!("chat verified against {} (auto-selected)", cand)
                    };
                    return Ok((cand, note));
                }
                Ok(Err(e)) => last_err = format!("{}: {}", cand, e),
                Err(_) => last_err = format!("{}: ping timed out", cand),
            }
        }
        Err(anyhow!(
            "no usable chat model among {} candidates ({})",
            tried.len(),
            last_err
        ))
    }

    /// Health check: verifies the key can actually run a completion against
    /// the given model. Reasoning models need token headroom, so this uses
    /// a generous budget.
    pub async fn ping(&self, model: &str) -> Result<()> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = serde_json::json!({
            "model": model,
            "messages": [
                {"role": "user", "content": "Reply with exactly: OK"}
            ],
            "temperature": 0.0,
            "max_tokens": 2048,
        });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.key)
            .json(&body)
            .send()
            .await
            .context("chat ping request failed")?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "chat ping failed (HTTP {}): {}",
                status,
                api_error_detail(&text)
            ));
        }
        let v: Value = resp.json().await.context("bad ping JSON")?;
        if let Some(text) = v
            .pointer("/choices/0/message")
            .and_then(message_text)
        {
            return Ok(());
        }
        Err(anyhow!("chat ping returned no content for {}", model))
    }

    /// Core chat call with retry/backoff on 429, 5xx, and network errors.
    pub async fn chat(&self, system: &str, user: &str, temperature: f32, max_tokens: u32) -> Result<String> {
        self.chat_with_timeout(system, user, temperature, max_tokens, Duration::from_secs(600)).await
    }

    /// Like `chat`, but with a per-request timeout override (long reports on
    /// slow/free tiers can legitimately exceed the default budget).
    pub async fn chat_with_timeout(
        &self,
        system: &str,
        user: &str,
        temperature: f32,
        max_tokens: u32,
        timeout: Duration,
    ) -> Result<String> {
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            "temperature": temperature,
            "top_p": 0.9,
            "max_tokens": max_tokens,
        });

        let url = format!("{}/chat/completions", self.base_url);
        const MAX_ATTEMPTS: u32 = 4;
        let backoffs = [4u64, 10, 20];

        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let resp = match self
                .http
                .post(&url)
                .bearer_auth(&self.key)
                .timeout(timeout)
                .json(&body)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if attempt < MAX_ATTEMPTS {
                        let wait = backoffs[(attempt - 1) as usize % backoffs.len()];
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        continue;
                    }
                    return Err(anyhow!("NVIDIA chat request failed after {} attempts: {}", attempt, e));
                }
            };

            let status = resp.status();
            if status.is_success() {
                let v: Value = resp.json().await.context("bad chat JSON")?;
                let content = v
                    .pointer("/choices/0/message")
                    .and_then(message_text)
                    .ok_or_else(|| anyhow!("no content in response: {}", truncate_value(&v)))?;
                return Ok(content);
            }

            let err_body = resp.text().await.unwrap_or_default();
            let code = status.as_u16();
            let retryable = code == 429 || code == 408 || code >= 500;
            if retryable && attempt < MAX_ATTEMPTS {
                let wait = backoffs[(attempt - 1) as usize % backoffs.len()];
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            return Err(anyhow!(
                "NVIDIA API HTTP {}: {}",
                code,
                api_error_detail(&err_body)
            ));
        }
    }

    /// Legacy decision API kept for compatibility: module plan.
    pub async fn plan(&self, snapshot: &Value) -> Result<AiPlan> {
        let plan = crate::agent::plan_modules(self, snapshot).await?;
        Ok(AiPlan {
            modules: plan.modules,
            priorities: plan.priorities,
            rationale: plan.rationale,
            model: self.model.clone(),
        })
    }
}

/// Model candidate ordering for auto-selection: preferred first, then the
/// best chat models we can find in the account's list.
fn candidates(models: &[String], preferred: Option<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(p) = preferred {
        if !p.is_empty() {
            out.push(p);
        }
    }

    let is_chat_model = |id: &str| {
        let l = id.to_ascii_lowercase();
        !(l.contains("embed")
            || l.contains("rerank")
            || l.contains("reranker")
            || l.contains("guard")
            || l.contains("safety")
            || l.contains("reward")
            || l.contains("vision")
            || l.contains("vlm")
            || l.contains("ocr")
            || l.contains("deplot")
            || l.contains("nvclip")
            || l.contains("neva")
            || l.contains("vila")
            || l.contains("cosmos")
            || l.contains("riva")
            || l.contains("parse")
            || l.contains("translate")
            || l.contains("detector")
            || l.contains("muse")
            || l.contains("diffusion")
            || l.contains("starcoder")
            || l.contains("codegemma")
            || l.contains("recurrentgemma")
            || l.contains("fuyu")
            || l.contains("kosmos")
            || l.contains("gemma-2b"))
    };

    let score = |id: &str| {
        let l = id.to_ascii_lowercase();
        let mut s = 0i32;
        // fast + capable agent defaults first (2026 NVIDIA lineup)
        if l.contains("glm") && l.contains("flash") { s += 130; }
        else if l.contains("glm") { s += 120; }
        if l.contains("gemma-4") { s += 105; }
        else if l.contains("gemma-3") { s += 95; }
        if l.contains("nemotron") && (l.contains("super") || l.contains("lightning")) { s += 90; }
        else if l.contains("nemotron") && l.contains("instruct") { s += 75; }
        if l.contains("kimi") { s += 80; }
        if l.contains("gpt-oss") { s += 78; }
        if l.contains("qwen") { s += 70; }
        if l.contains("llama-3.1-nemotron") { s += 68; }
        if l.contains("llama-3.3") || l.contains("llama-3.1") { s += 55; }
        if l.contains("mistral-large") { s += 50; }
        if l.contains("mixtral") { s += 40; }
        if l.contains("jamba") { s += 35; }
        if l.contains("yi-large") { s += 30; }
        if l.contains("dbrx") { s += 28; }
        if l.contains("palmyra") { s += 10; } // domain-tuned, low preference
        // chat-capable markers
        if l.contains("instruct") || l.contains("-it") || l.contains("chat") { s += 15; }
        // penalize mega MoE / ultra sizes (slow on free tier)
        if l.contains("550b") || l.contains("340b") || l.contains("253b") || l.contains("ultra") {
            s -= 30;
        }
        s
    };

    let mut ranked: Vec<(i32, String)> = models
        .iter()
        .filter(|m| is_chat_model(m))
        .map(|m| (score(m), m.clone()))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));

    for (_, m) in ranked.into_iter().take(8) {
        out.push(m);
    }
    out
}

/// Pull a human-readable error message out of OpenAI/NIM error bodies.
fn api_error_detail(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        for path in [
            "/error/message",
            "/error",
            "/detail",
            "/message",
            "/title",
        ] {
            if let Some(s) = v.pointer(path).and_then(|x| x.as_str()) {
                if !s.is_empty() {
                    return s.chars().take(300).collect();
                }
            }
        }
        if let Some(obj) = v.as_object() {
            let compact = serde_json::to_string(obj).unwrap_or_default();
            return compact.chars().take(300).collect();
        }
    }
    body.chars().take(300).collect()
}

fn truncate_value(v: &Value) -> String {
    let s = v.to_string();
    s.chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_text_prefers_content() {
        let v: Value = serde_json::from_str(
            r#"{"content": "{\"ports\": \"top\"}", "reasoning_content": "thinking..."}"#,
        )
        .unwrap();
        assert_eq!(message_text(&v).unwrap(), "{\"ports\": \"top\"}\nthinking...");
    }

    #[test]
    fn message_text_handles_null_content() {
        let v: Value =
            serde_json::from_str(r#"{"content": null, "reasoning_content": "the answer"}"#).unwrap();
        assert_eq!(message_text(&v).unwrap(), "the answer");
    }

    #[test]
    fn message_text_empty_is_none() {
        let v: Value = serde_json::from_str(r#"{"content": null}"#).unwrap();
        assert!(message_text(&v).is_none());
    }

    #[test]
    fn candidate_ranking_prefers_fast_chat_models() {
        let models = vec![
            "nvidia/nemotron-3-embed-1b".to_string(),
            "nvidia/llama-3.1-nemoguard-8b-content-safety".to_string(),
            "meta/llama-3.3-70b-instruct".to_string(),
            "z-ai/glm-5.3-flash".to_string(),
            "z-ai/glm-5.3".to_string(),
            "google/gemma-2b".to_string(),
            "nvidia/nemotron-3-ultra-550b-a55b".to_string(),
        ];
        let cands = candidates(&models, None);
        assert_eq!(cands[0], "z-ai/glm-5.3-flash");
        assert_eq!(cands[1], "z-ai/glm-5.3");
        assert!(!cands.iter().any(|c| c.contains("embed")));
        assert!(!cands.iter().any(|c| c.contains("guard")));
    }

    #[test]
    fn preferred_model_tried_first_even_if_unlisted() {
        let cands = candidates(&[], Some("my/custom-model".into()));
        assert_eq!(cands[0], "my/custom-model");
    }
}
