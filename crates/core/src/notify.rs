//! Webhook delivery, shared by every kind of notification (tunnel alerts, new
//! devices, the panel's test button). Best-effort by design: a failed POST is
//! logged by the caller and dropped — the log line is the fallback channel.
//!
//! Each notification carries a title and a line of text for receivers that
//! show messages (ntfy, Discord, Slack, Telegram, Gotify) and the event's own
//! fields for receivers that read JSON. [`WebhookFormat`] picks which body the
//! configured URL gets.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::config::{NotificationsConfig, WebhookFormat};

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

/// Where notifications go and in what shape — the delivery half of
/// `[notifications]`, snapshotted so no config lock is held across a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub url: String,
    pub format: WebhookFormat,
    pub chat_id: Option<String>,
}

impl Target {
    /// The configured target, if a webhook is set.
    pub fn from_config(cfg: &NotificationsConfig) -> Option<Target> {
        cfg.webhook.as_ref().map(|url| Target {
            url: url.clone(),
            format: cfg.format,
            chat_id: cfg.chat_id.clone(),
        })
    }

    /// Why this target can't work, in words for the panel; `None` when it can.
    pub fn problem(&self) -> Option<&'static str> {
        if !valid_webhook(&self.url) {
            return Some("the webhook must be an http(s) URL");
        }
        match self.format {
            WebhookFormat::Ntfy if ntfy_split(&self.url).is_none() => {
                Some("an ntfy URL ends in the topic, like https://ntfy.sh/my-topic")
            }
            WebhookFormat::Telegram if self.chat_id.is_none() => {
                Some("Telegram needs the chat id to post to")
            }
            _ => None,
        }
    }
}

/// How much a notification matters — sets ntfy/Gotify priority and the
/// Discord colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
}

/// One notification: the words for people, the event for machines.
pub struct Notice<E> {
    pub title: String,
    pub message: String,
    pub level: Level,
    /// ntfy tags — emoji short codes such as `warning`.
    pub tags: &'static [&'static str],
    /// The JSON body for `format = "json"` — the event's own fields.
    pub event: E,
}

/// Deliver `notice` to `target`. `Err` says what went wrong in words fit for a
/// log line or the panel: an HTTP status the receiver answered with, or why it
/// couldn't be reached.
pub async fn send<E: Serialize>(
    client: &reqwest::Client,
    target: &Target,
    notice: &Notice<E>,
) -> Result<(), String> {
    let (url, body) = request(target, notice)?;
    match client.post(url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => Ok(()),
        Ok(resp) => Err(format!("the webhook answered {}", resp.status())),
        Err(e) => Err(format!("the webhook could not be reached: {e}")),
    }
}

/// The URL to POST to and the JSON body, for `target`'s format.
fn request<E: Serialize>(target: &Target, n: &Notice<E>) -> Result<(String, Value), String> {
    let warn = n.level == Level::Warning;
    Ok(match target.format {
        WebhookFormat::Json => (
            target.url.clone(),
            serde_json::to_value(&n.event).map_err(|e| e.to_string())?,
        ),
        WebhookFormat::Ntfy => {
            // JSON publishing goes to the server root with the topic in the
            // body; that is what lets a title carry non-ASCII device names.
            let (base, topic) = ntfy_split(&target.url).ok_or("an ntfy URL ends in the topic")?;
            (
                base,
                json!({
                    "topic": topic,
                    "title": n.title,
                    "message": n.message,
                    "tags": n.tags,
                    "priority": if warn { 4 } else { 3 },
                }),
            )
        }
        WebhookFormat::Discord => (
            target.url.clone(),
            json!({
                "username": "ferrite",
                "embeds": [{
                    "title": n.title,
                    "description": n.message,
                    "color": if warn { 0xE5_53_4B } else { 0x3F_B9_50 },
                }],
            }),
        ),
        WebhookFormat::Slack => (
            target.url.clone(),
            json!({ "text": format!("*{}*\n{}", slack_escape(&n.title), slack_escape(&n.message)) }),
        ),
        WebhookFormat::Telegram => (
            target.url.clone(),
            json!({
                "chat_id": target.chat_id.as_deref().ok_or("Telegram needs the chat id")?,
                "text": format!("<b>{}</b>\n{}", html_escape(&n.title), html_escape(&n.message)),
                "parse_mode": "HTML",
                "disable_web_page_preview": true,
            }),
        ),
        WebhookFormat::Gotify => (
            target.url.clone(),
            json!({
                "title": n.title,
                "message": n.message,
                "priority": if warn { 8 } else { 5 },
            }),
        ),
    })
}

/// Split an ntfy topic URL into the server URL to publish to and the topic.
/// The query string (an `?auth=` token) stays on the server URL.
fn ntfy_split(url: &str) -> Option<(String, String)> {
    let mut parsed = reqwest::Url::parse(url.trim()).ok()?;
    let mut segments: Vec<String> = parsed
        .path_segments()?
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let topic = segments.pop()?;
    parsed.set_path(&format!("/{}", segments.join("/")));
    Some((parsed.to_string(), topic))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Slack's message text treats `&`, `<` and `>` as markup.
fn slack_escape(s: &str) -> String {
    html_escape(s)
}

/// A duration for a message: `45s`, `12 min`, `3 h 5 min`.
pub fn human_duration(secs: u64) -> String {
    match secs {
        0..90 => format!("{secs}s"),
        90..5400 => format!("{} min", (secs + 30) / 60),
        _ => {
            let mins = (secs + 30) / 60;
            match mins % 60 {
                0 => format!("{} h", mins / 60),
                m => format!("{} h {m} min", mins / 60),
            }
        }
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

    fn target(url: &str, format: WebhookFormat) -> Target {
        Target {
            url: url.into(),
            format,
            chat_id: Some("42".into()),
        }
    }

    fn notice(level: Level) -> Notice<Value> {
        Notice {
            title: "New device: pixel <8>".into(),
            message: "pixel & co joined".into(),
            level,
            tags: &["new"],
            event: json!({ "event": "new_device", "message": "pixel & co joined" }),
        }
    }

    #[test]
    fn durations_read_like_words() {
        assert_eq!(human_duration(45), "45s");
        assert_eq!(human_duration(600), "10 min");
        assert_eq!(human_duration(3600 * 3 + 300), "3 h 5 min");
        assert_eq!(human_duration(7200), "2 h");
    }

    #[test]
    fn webhook_urls() {
        assert!(valid_webhook("https://ntfy.sh/ferrite"));
        assert!(valid_webhook(" http://10.0.0.5:8123/api/webhook/x "));
        assert!(!valid_webhook("ftp://example.com"));
        assert!(!valid_webhook("https://"));
        assert!(!valid_webhook("ntfy.sh/ferrite"));
    }

    #[test]
    fn json_sends_the_event_unchanged() {
        let (url, body) = request(
            &target("https://ha.lan/api/webhook/x", WebhookFormat::Json),
            &notice(Level::Info),
        )
        .unwrap();
        assert_eq!(url, "https://ha.lan/api/webhook/x");
        assert_eq!(body["event"], "new_device");
        assert!(body.get("title").is_none());
    }

    #[test]
    fn ntfy_publishes_to_the_root_with_the_topic_in_the_body() {
        let (url, body) = request(
            &target("https://ntfy.sh/ferrite-home", WebhookFormat::Ntfy),
            &notice(Level::Warning),
        )
        .unwrap();
        assert_eq!(url, "https://ntfy.sh/");
        assert_eq!(body["topic"], "ferrite-home");
        assert_eq!(body["title"], "New device: pixel <8>");
        assert_eq!(body["priority"], 4);
        assert_eq!(body["tags"][0], "new");

        // A server under a path keeps it, and an auth query survives.
        let (base, topic) = ntfy_split("https://box.lan/ntfy/alerts?auth=abc").unwrap();
        assert_eq!(base, "https://box.lan/ntfy?auth=abc");
        assert_eq!(topic, "alerts");
        assert!(ntfy_split("https://ntfy.sh/").is_none());
    }

    #[test]
    fn chat_formats_escape_their_markup() {
        let (_, tg) = request(
            &target(
                "https://api.telegram.org/bot1:x/sendMessage",
                WebhookFormat::Telegram,
            ),
            &notice(Level::Info),
        )
        .unwrap();
        assert_eq!(tg["chat_id"], "42");
        assert_eq!(tg["parse_mode"], "HTML");
        assert_eq!(
            tg["text"],
            "<b>New device: pixel &lt;8&gt;</b>\npixel &amp; co joined"
        );

        let (_, slack) = request(
            &target("https://hooks.slack.com/x", WebhookFormat::Slack),
            &notice(Level::Info),
        )
        .unwrap();
        assert_eq!(
            slack["text"],
            "*New device: pixel &lt;8&gt;*\npixel &amp; co joined"
        );

        let (_, discord) = request(
            &target(
                "https://discord.com/api/webhooks/1/x",
                WebhookFormat::Discord,
            ),
            &notice(Level::Warning),
        )
        .unwrap();
        assert_eq!(discord["embeds"][0]["title"], "New device: pixel <8>");
        assert_eq!(discord["embeds"][0]["color"], 0xE5534B);

        let (_, gotify) = request(
            &target("https://gotify.lan/message?token=t", WebhookFormat::Gotify),
            &notice(Level::Info),
        )
        .unwrap();
        assert_eq!(gotify["priority"], 5);
    }

    #[test]
    fn problems_are_named() {
        assert!(
            target("https://ntfy.sh/x", WebhookFormat::Ntfy)
                .problem()
                .is_none()
        );
        assert!(
            target("https://ntfy.sh/", WebhookFormat::Ntfy)
                .problem()
                .is_some()
        );
        let mut tg = target(
            "https://api.telegram.org/bot1:x/sendMessage",
            WebhookFormat::Telegram,
        );
        assert!(tg.problem().is_none());
        tg.chat_id = None;
        assert!(tg.problem().is_some());
        assert!(target("ntfy.sh/x", WebhookFormat::Json).problem().is_some());
    }
}
