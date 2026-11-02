//! `/api/mcp` — a Model Context Protocol server over Streamable HTTP, so an AI
//! assistant (Claude Code, Claude Desktop, …) can ask ferrite what it is doing
//! and, when `[mcp] allow_changes` is on, change it.
//!
//! The server is deliberately small: every request is answered with one JSON
//! body (no SSE streams, no sessions), which the transport allows. It speaks
//! `initialize`, `ping`, `tools/list` and `tools/call`; the tools themselves are
//! thin adapters over the REST handlers ([`tools`]), so validation, persistence
//! and logging stay in one place. Authentication is the API's own — the route
//! sits behind the same middleware, so an assistant connects with the API key.

mod tools;

use axum::{
    Json,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

use ferrite_app::AppState;
use ferrite_core::config::McpConfig;

/// Protocol versions this server speaks, newest first. Nothing it uses
/// differs between them.
const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];

/// What the assistant is told about this server when it connects.
const INSTRUCTIONS: &str = "ferrite is the home network's DNS filter and router. Every device \
asks it for names; it blocks ads, trackers and chosen services (network-wide or per device \
profile), enforces SafeSearch, and can route chosen domains through tunnels. To explain why a \
site doesn't load, call check_domain (pass the device's IP to see its profile's decision) and \
search_queries for what the device actually asked. Changes (blocking, allowing, pausing) are \
only offered when the owner has allowed them.";

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;

/// POST /api/mcp — one JSON-RPC message (or, from 2025-03-26 clients, a batch).
pub async fn post(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if !state.live_config.read().mcp.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "MCP is turned off — Settings → Access" })),
        )
            .into_response();
    }
    if !origin_allowed(&headers) {
        return (
            StatusCode::FORBIDDEN,
            Json(rpc_error(
                Value::Null,
                INVALID_REQUEST,
                "origin not allowed",
            )),
        )
            .into_response();
    }
    if let Some(v) = headers
        .get("mcp-protocol-version")
        .and_then(|v| v.to_str().ok())
        && !SUPPORTED_VERSIONS.contains(&v)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(rpc_error(
                Value::Null,
                INVALID_REQUEST,
                &format!("unsupported protocol version {v}"),
            )),
        )
            .into_response();
    }

    let message: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(rpc_error(Value::Null, PARSE_ERROR, &e.to_string())),
            )
                .into_response();
        }
    };

    match message {
        Value::Array(batch) => {
            let mut replies = Vec::new();
            for m in batch {
                if let Some(reply) = handle_message(&state, m).await {
                    replies.push(reply);
                }
            }
            if replies.is_empty() {
                StatusCode::ACCEPTED.into_response()
            } else {
                Json(Value::Array(replies)).into_response()
            }
        }
        m => match handle_message(&state, m).await {
            Some(reply) => Json(reply).into_response(),
            // A notification or a response: accepted, nothing to say.
            None => StatusCode::ACCEPTED.into_response(),
        },
    }
}

/// GET /api/mcp — this server opens no server-to-client stream.
pub async fn get() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

/// Browsers send `Origin`; MCP clients don't. A browser origin other than this
/// server's own host is a page trying to reach the box through DNS rebinding.
fn origin_allowed(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return true;
    };
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let origin_host = origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .trim_end_matches('/');
    !host.is_empty() && origin_host.eq_ignore_ascii_case(host)
}

/// The reply to one message, or `None` for a notification or a response.
async fn handle_message(state: &AppState, message: Value) -> Option<Value> {
    let Some(obj) = message.as_object() else {
        return Some(rpc_error(
            Value::Null,
            INVALID_REQUEST,
            "not a JSON-RPC message",
        ));
    };
    let method = obj.get("method").and_then(Value::as_str)?;
    // No id: a notification (`notifications/initialized`, cancellations…).
    let id = obj.get("id")?.clone();
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    Some(match method {
        "initialize" => rpc_result(id, initialize(&params)),
        "ping" => rpc_result(id, json!({})),
        "tools/list" => {
            let allow_changes = state.live_config.read().mcp.allow_changes;
            rpc_result(id, json!({ "tools": tools::definitions(allow_changes) }))
        }
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(
                    id,
                    INVALID_PARAMS,
                    "tools/call needs a tool name",
                ));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            match tools::call(state, name, args).await {
                tools::Outcome::Unknown => {
                    rpc_error(id, INVALID_PARAMS, &format!("unknown tool: {name}"))
                }
                tools::Outcome::Done(value) => rpc_result(id, tool_result(value, false)),
                tools::Outcome::Failed(msg) => rpc_result(id, tool_result(json!(msg), true)),
            }
        }
        other => rpc_error(id, METHOD_NOT_FOUND, &format!("method not found: {other}")),
    })
}

fn initialize(params: &Value) -> Value {
    // Answer in the client's version when it is one of ours, else our newest.
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked
        .filter(|v| SUPPORTED_VERSIONS.contains(v))
        .unwrap_or(SUPPORTED_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": { "listChanged": false } },
        "serverInfo": {
            "name": "ferrite",
            "title": "ferrite",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": INSTRUCTIONS,
    })
}

/// GET /api/settings/mcp — whether the endpoint is on and may change things.
pub async fn get_settings(State(state): State<AppState>) -> Json<McpConfig> {
    Json(state.live_config.read().mcp.clone())
}

/// PUT /api/settings/mcp — live at once (the next request sees it), persisted.
pub async fn put_settings(
    State(state): State<AppState>,
    Json(body): Json<McpConfig>,
) -> Json<Value> {
    tracing::info!(
        "MCP endpoint: enabled={} allow_changes={}",
        body.enabled,
        body.allow_changes
    );
    state.live_config.write().mcp = body;
    let saved_to = state.persist_config().await;
    Json(json!({ "status": "ok", "persisted": saved_to.is_some(), "saved_to": saved_to }))
}

/// A tool's answer: readable JSON text for every client, and the same value
/// as `structuredContent` (an object) for the clients that read it.
fn tool_result(value: Value, is_error: bool) -> Value {
    let text = match &value {
        Value::String(s) => s.clone(),
        v => serde_json::to_string_pretty(v).unwrap_or_default(),
    };
    let mut result = json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error,
    });
    if !is_error {
        let structured = if value.is_object() {
            value
        } else {
            json!({ "result": value })
        };
        result["structuredContent"] = structured;
    }
    result
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests;
