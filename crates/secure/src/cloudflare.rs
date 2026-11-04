//! The little of Cloudflare's API that DNS-01 needs: find the zone a name is
//! in, add a TXT record, remove it again. A token made from the "Edit zone
//! DNS" template is enough for all three.

use std::time::Duration;

use serde_json::{Value, json};

const API: &str = "https://api.cloudflare.com/client/v4";
/// How ferrite's own records are told apart from the zone's others.
const MARK: &str = "ferrite:";

pub(crate) struct Cloudflare {
    http: reqwest::Client,
    token: String,
}

/// The zone a name lives in.
#[derive(Debug, Clone)]
pub(crate) struct Zone {
    pub id: String,
    pub name: String,
    /// Its authoritative servers — where a new record shows up first.
    pub name_servers: Vec<String>,
}

/// `dns.home.example.com` → `dns.home.example.com`, `home.example.com`,
/// `example.com`: the names its zone could be, longest first.
pub(crate) fn zone_candidates(host: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = host;
    while rest.contains('.') {
        out.push(rest);
        rest = match rest.split_once('.') {
            Some((_, r)) => r,
            None => break,
        };
    }
    out
}

/// What Cloudflare said went wrong, from its `errors` list — the most
/// specific message of each, which sits at the end of its chain.
fn api_error(body: &Value) -> Option<String> {
    let msgs: Vec<String> = body["errors"]
        .as_array()?
        .iter()
        .filter_map(|e| {
            e["error_chain"]
                .as_array()
                .and_then(|c| c.last())
                .unwrap_or(e)["message"]
                .as_str()
                .map(str::to_owned)
        })
        .collect();
    (!msgs.is_empty()).then(|| msgs.join("; "))
}

/// Cloudflare's codes for a token that is no token at all.
fn bad_token(body: &Value) -> bool {
    let codes = |e: &Value| {
        let mut c = vec![e["code"].as_u64().unwrap_or(0)];
        if let Some(chain) = e["error_chain"].as_array() {
            c.extend(chain.iter().filter_map(|x| x["code"].as_u64()));
        }
        c
    };
    body["errors"].as_array().is_some_and(|errs| {
        errs.iter()
            .flat_map(codes)
            .any(|c| matches!(c, 1000 | 6111 | 9106 | 9109 | 10000))
    })
}

impl Cloudflare {
    pub fn new(token: &str) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent(concat!("ferrite/", env!("CARGO_PKG_VERSION")))
                .build()
                .unwrap_or_default(),
            token: token.trim().to_string(),
        }
    }

    async fn call(&self, req: reqwest::RequestBuilder) -> Result<Value, String> {
        let rsp = req
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| format!("couldn't reach Cloudflare: {e}"))?;
        let status = rsp.status();
        let body: Value = rsp.json().await.unwrap_or(Value::Null);
        if status.is_success() && body["success"].as_bool() != Some(false) {
            return Ok(body);
        }
        let why = api_error(&body).unwrap_or_else(|| status.to_string());
        Err(if bad_token(&body) {
            format!("Cloudflare didn't accept the token: {why}")
        } else if matches!(status.as_u16(), 401 | 403) {
            format!("the Cloudflare token may not do this: {why}")
        } else {
            format!("Cloudflare: {why}")
        })
    }

    /// The zone `host` is in, as far as the token can see.
    pub async fn zone_for(&self, host: &str) -> Result<Zone, String> {
        for name in zone_candidates(host) {
            let body = self
                .call(
                    // Host names need no escaping in a query string.
                    self.http
                        .get(format!("{API}/zones?name={name}&status=active")),
                )
                .await?;
            if let Some(z) = body["result"].as_array().and_then(|a| a.first()) {
                return Ok(Zone {
                    id: z["id"].as_str().unwrap_or_default().to_string(),
                    name: z["name"].as_str().unwrap_or(name).to_string(),
                    name_servers: z["name_servers"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|n| n.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                });
            }
        }
        Err(format!(
            "the token sees no Cloudflare zone for {host} — give it access to that zone"
        ))
    }

    /// Add a TXT record; its id, to remove it with.
    pub async fn add_txt(&self, zone: &Zone, name: &str, value: &str) -> Result<String, String> {
        let body = self
            .call(
                self.http
                    .post(format!("{API}/zones/{}/dns_records", zone.id))
                    .json(&json!({
                        "type": "TXT",
                        "name": name,
                        "content": value,
                        "ttl": 60,
                        "comment": format!("{MARK} Let's Encrypt challenge, removed by itself"),
                    })),
            )
            .await?;
        body["result"]["id"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "Cloudflare added the record but didn't say its id".into())
    }

    /// The ids of challenge records ferrite left at `name` — a renewal cut
    /// short (the setting changed mid-way, a restart) doesn't remove its own.
    pub async fn leftovers(&self, zone: &Zone, name: &str) -> Result<Vec<String>, String> {
        let body = self
            .call(self.http.get(format!(
                "{API}/zones/{}/dns_records?type=TXT&name={name}",
                zone.id
            )))
            .await?;
        Ok(body["result"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|r| r["comment"].as_str().is_some_and(|c| c.starts_with(MARK)))
                    .filter_map(|r| r["id"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn delete(&self, zone: &Zone, id: &str) -> Result<(), String> {
        self.call(
            self.http
                .delete(format!("{API}/zones/{}/dns_records/{id}", zone.id)),
        )
        .await
        .map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_could_be_in_any_zone_above_it() {
        assert_eq!(
            zone_candidates("dns.home.example.com"),
            vec!["dns.home.example.com", "home.example.com", "example.com"]
        );
        assert_eq!(zone_candidates("example.com"), vec!["example.com"]);
        assert!(zone_candidates("localhost").is_empty());
    }

    #[test]
    fn errors_are_read_from_the_body() {
        // What Cloudflare answers a token that is wrong, and one that is junk.
        let wrong = json!({"success": false, "errors": [{"code": 9109, "message": "Invalid access token"}]});
        assert_eq!(api_error(&wrong).as_deref(), Some("Invalid access token"));
        assert!(bad_token(&wrong));
        let junk = json!({"success": false, "errors": [{"code": 6003, "message": "Invalid request headers",
            "error_chain": [{"code": 6111, "message": "Invalid format for Authorization header"}]}]});
        assert_eq!(
            api_error(&junk).as_deref(),
            Some("Invalid format for Authorization header")
        );
        assert!(bad_token(&junk));
        let other = json!({"errors": [{"code": 81057, "message": "Record already exists."}]});
        assert!(!bad_token(&other));
        assert_eq!(api_error(&json!({"errors": []})), None);
    }
}
