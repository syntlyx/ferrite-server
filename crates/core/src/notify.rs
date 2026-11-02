//! Webhook delivery, shared by every kind of notification (tunnel alerts, new
//! devices, the panel's test button). Best-effort by design: a failed POST is
//! logged by the caller and dropped — the log line is the fallback channel.

use std::time::Duration;

use serde::Serialize;

/// How long one delivery may take before it is given up on.
pub const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// A client for webhook deliveries. Callers build one and reuse it.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .build()
        // Falls back to default settings; only fails on broken TLS backends.
        .unwrap_or_default()
}

/// POST `event` as JSON to `url`. `Err` says what went wrong in words fit for
/// a log line or the panel: an HTTP status the receiver answered with, or why
/// it couldn't be reached.
pub async fn post(
    client: &reqwest::Client,
    url: &str,
    event: &impl Serialize,
) -> Result<(), String> {
    match client.post(url).json(event).send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => Err(format!("the webhook answered {}", resp.status())),
        Err(e) => Err(format!("the webhook could not be reached: {e}")),
    }
}

/// Is `url` something a webhook can be: http(s) with a host.
pub fn valid_webhook(url: &str) -> bool {
    let url = url.trim();
    (url.starts_with("http://") || url.starts_with("https://"))
        && reqwest::Url::parse(url).is_ok_and(|u| u.host_str().is_some_and(|h| !h.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_urls() {
        assert!(valid_webhook("https://ntfy.sh/ferrite"));
        assert!(valid_webhook(" http://10.0.0.5:8123/api/webhook/x "));
        assert!(!valid_webhook("ftp://example.com"));
        assert!(!valid_webhook("https://"));
        assert!(!valid_webhook("ntfy.sh/ferrite"));
    }
}
