use super::*;
use axum::http::HeaderValue;
use ferrite_app::test_support;

async fn send(state: &AppState, headers: HeaderMap, body: Value) -> (StatusCode, Value) {
    let resp = post(State(state.clone()), headers, Bytes::from(body.to_string())).await;
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

fn call(id: u64, name: &str, args: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": name, "arguments": args } })
}

async fn enabled_state(name: &str, allow_changes: bool) -> (AppState, std::path::PathBuf) {
    let (state, db) = test_support::app_state(name).await;
    {
        let mut cfg = state.live_config.write();
        cfg.mcp.enabled = true;
        cfg.mcp.allow_changes = allow_changes;
    }
    (state, db)
}

#[tokio::test]
async fn off_by_default_and_hidden_behind_a_404() {
    let (state, db) = test_support::app_state("mcp-off").await;
    let (status, _) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn initialize_negotiates_and_notifications_are_accepted() {
    let (state, db) = enabled_state("mcp-init", false).await;
    let (status, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["id"], 1);
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(v["result"]["serverInfo"]["name"], "ferrite");
    assert!(v["result"]["capabilities"]["tools"].is_object());

    // An unknown version is answered with ours.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}),
    )
    .await;
    assert_eq!(v["result"]["protocolVersion"], SUPPORTED_VERSIONS[0]);

    let (status, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(v.is_null());

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":3,"method":"nope"}),
    )
    .await;
    assert_eq!(v["error"]["code"], METHOD_NOT_FOUND);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn foreign_origins_and_unknown_versions_are_refused() {
    let (state, db) = enabled_state("mcp-origin", false).await;
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});

    let mut h = HeaderMap::new();
    h.insert(header::HOST, HeaderValue::from_static("192.168.1.10"));
    h.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://evil.example"),
    );
    assert_eq!(send(&state, h, ping.clone()).await.0, StatusCode::FORBIDDEN);

    // The panel's own origin is fine.
    let mut h = HeaderMap::new();
    h.insert(header::HOST, HeaderValue::from_static("192.168.1.10"));
    h.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://192.168.1.10"),
    );
    assert_eq!(send(&state, h, ping.clone()).await.0, StatusCode::OK);

    let mut h = HeaderMap::new();
    h.insert(
        "mcp-protocol-version",
        HeaderValue::from_static("2020-01-01"),
    );
    assert_eq!(send(&state, h, ping).await.0, StatusCode::BAD_REQUEST);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn read_tools_answer_and_change_tools_need_permission() {
    let (state, db) = enabled_state("mcp-tools", false).await;

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    let names: Vec<&str> = v["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"check_domain") && names.contains(&"search_queries"));
    assert!(
        !names.contains(&"block_domain"),
        "changes are off: {names:?}"
    );

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(2, "check_domain", json!({"domain": "Example.COM"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], false);
    assert_eq!(v["result"]["structuredContent"]["domain"], "example.com");
    assert_eq!(v["result"]["structuredContent"]["blocked"], false);

    let (_, v) = send(&state, HeaderMap::new(), call(3, "get_status", json!({}))).await;
    assert_eq!(
        v["result"]["structuredContent"]["filtering"]["enabled"],
        true
    );

    // A change tool is refused while changes are off — as a tool error the
    // assistant can read, not a protocol failure.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(4, "block_domain", json!({"domain": "ads.test"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    assert!(!state.inner.blocklist.should_block_for("ads.test", None));

    let (_, v) = send(&state, HeaderMap::new(), call(5, "no_such_tool", json!({}))).await;
    assert_eq!(v["error"]["code"], INVALID_PARAMS);
    drop(state);
    test_support::cleanup_sqlite(&db);
}

#[tokio::test]
async fn change_tools_act_like_the_panel_when_allowed() {
    let (state, db) = enabled_state("mcp-changes", true).await;

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(1, "block_domain", json!({"domain": "ads.test"})),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert!(state.inner.blocklist.should_block_for("www.ads.test", None));
    assert!(
        state
            .live_config
            .read()
            .blocklist
            .domains
            .contains(&"ads.test".to_string())
    );

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            2,
            "set_service_blocked",
            json!({"service": "tiktok", "blocked": true}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], false, "{v}");
    assert_eq!(state.inner.blocklist.blocked_services(), vec!["tiktok"]);

    // A device's own decision: the check names the client's view.
    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            3,
            "check_domain",
            json!({"domain": "www.tiktok.com", "client": "10.0.0.7"}),
        ),
    )
    .await;
    let r = &v["result"]["structuredContent"];
    assert_eq!(r["blocked"], true);
    assert_eq!(r["for_client"]["blocked"], true);
    assert_eq!(r["sources"][0]["kind"], "service");

    let (_, v) = send(
        &state,
        HeaderMap::new(),
        call(
            4,
            "set_service_blocked",
            json!({"service": "tiktok", "blocked": true, "profile": "ghost"}),
        ),
    )
    .await;
    assert_eq!(v["result"]["isError"], true);
    drop(state);
    test_support::cleanup_sqlite(&db);
}
