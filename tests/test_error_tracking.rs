use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use saugra_waf::error_tracking::{ErrorEventPayload, ErrorTracker, ERROR_TRACKING_DSN_ENV};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct MockSinkState {
    received_events: Arc<Mutex<Vec<ErrorEventPayload>>>,
}

async fn handle_mock_event(
    State(state): State<MockSinkState>,
    Json(payload): Json<ErrorEventPayload>,
) -> &'static str {
    state.received_events.lock().unwrap().push(payload);
    "OK"
}

static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[tokio::test]
async fn test_error_tracking_posts_event_to_mock_dsn_sink() {
    let state = MockSinkState::default();
    let app = Router::new()
        .route("/api/error-events", post(handle_mock_event))
        .with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let mock_dsn = format!("http://{addr}/api/error-events");
    let tracker = {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(ERROR_TRACKING_DSN_ENV, &mock_dsn);
        ErrorTracker::from_env()
    };
    assert!(tracker.is_enabled());

    let dispatched = tracker
        .dispatch_event("integration test error event", "error")
        .await
        .unwrap();
    assert!(dispatched);

    let events = state.received_events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message, "integration test error event");
    assert_eq!(events[0].level, "error");
    assert_eq!(events[0].service, "saugra-waf");

    {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
    }
    server_handle.abort();
}

#[tokio::test]
async fn test_error_tracking_disabled_when_dsn_unconfigured() {
    let tracker = {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(ERROR_TRACKING_DSN_ENV);
        ErrorTracker::from_env()
    };
    assert!(!tracker.is_enabled());

    let dispatched = tracker
        .dispatch_event("should not send", "error")
        .await
        .unwrap();
    assert!(!dispatched);
}
