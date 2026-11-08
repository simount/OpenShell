// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Protocol-aware bidirectional relay with L7 inspection.
//!
//! Replaces `copy_bidirectional` for endpoints with L7 configuration.
//! Parses each request within the tunnel, evaluates it against OPA policy,
//! and either forwards or denies the request.

use crate::l7::provider::{L7Provider, L7Request, RelayOutcome};
use crate::l7::{EnforcementMode, L7EndpointConfig, L7Protocol, L7RequestInfo};
use crate::secrets::{self, SecretResolver};
use miette::{IntoDiagnostic, Result, miette};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest,
    NetworkActivityBuilder, SeverityId, Url as OcsfUrl, ocsf_emit,
};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, info, warn};

/// Context for L7 request policy evaluation.
pub struct L7EvalContext {
    /// Host from the CONNECT request.
    pub host: String,
    /// Port from the CONNECT request.
    pub port: u16,
    /// Matched policy name from L4 evaluation.
    pub policy_name: String,
    /// Binary path (for cross-layer Rego evaluation).
    pub binary_path: String,
    /// Ancestor paths.
    pub ancestors: Vec<String>,
    /// Cmdline paths.
    pub cmdline_paths: Vec<String>,
    /// Supervisor-only placeholder resolver for outbound headers.
    pub(crate) secret_resolver: Option<Arc<SecretResolver>>,
}

/// Run protocol-aware L7 inspection on a tunnel.
///
/// This replaces `copy_bidirectional` for L7-enabled endpoints.
/// Protocol detection (peek) is the caller's responsibility — this function
/// assumes the streams are already proven to carry the expected protocol.
/// For TLS-terminated connections, ALPN proves HTTP; for plaintext, the
/// caller peeks on the raw `TcpStream` before calling this.
pub async fn relay_with_inspection<C, U>(
    config: &L7EndpointConfig,
    engine: Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    match config.protocol {
        L7Protocol::Rest => relay_rest(config, &engine, client, upstream, ctx).await,
        L7Protocol::Sql => {
            // SQL provider is Phase 3 — fall through to passthrough with warning
            {
                let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                    .activity(ActivityId::Other)
                    .severity(SeverityId::Low)
                    .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                    .message("SQL L7 provider not yet implemented, falling back to passthrough")
                    .build();
                ocsf_emit!(event);
            }
            tokio::io::copy_bidirectional(client, upstream)
                .await
                .into_diagnostic()?;
            Ok(())
        }
    }
}

/// Handle an upgraded connection (101 Switching Protocols).
///
/// Forwards any overflow bytes from the upgrade response to the client, then
/// switches to raw bidirectional TCP copy for the upgraded protocol (WebSocket,
/// HTTP/2, etc.). L7 policy enforcement does not apply after the upgrade —
/// the initial HTTP request was already evaluated.
async fn handle_upgrade<C, U>(
    client: &mut C,
    upstream: &mut U,
    overflow: Vec<u8>,
    host: &str,
    port: u16,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    ocsf_emit!(
        NetworkActivityBuilder::new(crate::ocsf_ctx())
            .activity(ActivityId::Other)
            .activity_name("Upgrade")
            .severity(SeverityId::Informational)
            .dst_endpoint(Endpoint::from_domain(host, port))
            .message(format!(
                "101 Switching Protocols — raw bidirectional relay (L7 enforcement no longer active) \
                 [host:{host} port:{port} overflow_bytes:{}]",
                overflow.len()
            ))
            .build()
    );
    if !overflow.is_empty() {
        client.write_all(&overflow).await.into_diagnostic()?;
        client.flush().await.into_diagnostic()?;
    }
    tokio::io::copy_bidirectional(client, upstream)
        .await
        .into_diagnostic()?;
    Ok(())
}

/// REST relay loop: parse request -> evaluate -> allow/deny -> relay response -> repeat.
async fn relay_rest<C, U>(
    config: &L7EndpointConfig,
    engine: &Mutex<regorus::Engine>,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    loop {
        // Parse one HTTP request from client
        let Some(parsed) = next_request_unless_upstream_closed(
            &crate::l7::rest::RestProvider,
            client,
            upstream,
            ctx,
        )
        .await
        else {
            return Ok(());
        };
        let req = match parsed {
            Ok(Some(req)) => req,
            Ok(None) => return Ok(()), // Client closed connection
            Err(e) => {
                if is_benign_connection_error(&e) {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "L7 connection closed"
                    );
                } else {
                    let event = NetworkActivityBuilder::new(crate::ocsf_ctx())
                        .activity(ActivityId::Fail)
                        .severity(SeverityId::Low)
                        .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                        .message(format!("HTTP parse error in L7 relay: {e}"))
                        .build();
                    ocsf_emit!(event);
                }
                return Ok(()); // Close connection on parse error
            }
        };

        // Rewrite credential placeholders in the request target BEFORE OPA
        // evaluation. OPA sees the redacted path; the resolved path goes only
        // to the upstream write.
        let (eval_target, redacted_target) = if let Some(ref resolver) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, resolver) {
                Ok(result) => (result.resolved, result.redacted),
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            (req.target.clone(), req.target.clone())
        };

        let request_info = L7RequestInfo {
            action: req.action.clone(),
            target: redacted_target.clone(),
            query_params: req.query_params.clone(),
        };

        // Evaluate L7 policy via Rego (using redacted target)
        let (allowed, reason) = evaluate_l7_request(engine, ctx, &request_info)?;

        // Check if this is an upgrade request for logging purposes.
        let header_end = req
            .raw_header
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map_or(req.raw_header.len(), |p| p + 4);
        let is_upgrade_request = {
            let h = String::from_utf8_lossy(&req.raw_header[..header_end]);
            h.lines()
                .skip(1)
                .any(|l| l.to_ascii_lowercase().starts_with("upgrade:"))
        };

        let decision_str = match (allowed, config.enforcement, is_upgrade_request) {
            (true, _, true) => "allow_upgrade",
            (true, _, false) => "allow",
            (false, EnforcementMode::Audit, _) => "audit",
            (false, EnforcementMode::Enforce, _) => "deny",
        };

        // Log every L7 decision as an OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        {
            let (action_id, disposition_id, severity) = match decision_str {
                "allow" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                "deny" => (ActionId::Denied, DispositionId::Blocked, SeverityId::Medium),
                "audit" => (
                    ActionId::Allowed,
                    DispositionId::Allowed,
                    SeverityId::Informational,
                ),
                _ => (
                    ActionId::Other,
                    DispositionId::Other,
                    SeverityId::Informational,
                ),
            };
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(action_id)
                .disposition(disposition_id)
                .severity(severity)
                .http_request(HttpRequest::new(
                    &request_info.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .firewall_rule(&ctx.policy_name, "l7")
                .message(format!(
                    "L7_REQUEST {decision_str} {} {}:{}{} reason={}",
                    request_info.action, ctx.host, ctx.port, redacted_target, reason,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Store the resolved target for the deny response redaction
        let _ = &eval_target;

        if allowed || config.enforcement == EnforcementMode::Audit {
            // Forward request to upstream and relay response
            let outcome = crate::l7::rest::relay_http_request_with_resolver(
                &req,
                client,
                upstream,
                ctx.secret_resolver.as_deref(),
            )
            .await?;
            match outcome {
                RelayOutcome::Reusable => {} // continue loop
                RelayOutcome::Consumed => {
                    debug!(
                        host = %ctx.host,
                        port = ctx.port,
                        "Upstream connection not reusable, closing L7 relay"
                    );
                    return Ok(());
                }
                RelayOutcome::Upgraded { overflow } => {
                    return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
                }
            }
        } else {
            // Enforce mode: deny with 403 and close connection (use redacted target)
            crate::l7::rest::RestProvider
                .deny_with_redacted_target(
                    &req,
                    &ctx.policy_name,
                    &reason,
                    client,
                    Some(&redacted_target),
                )
                .await?;
            return Ok(());
        }
    }
}

/// Wait for the client's next request on a keep-alive tunnel while watching
/// the idle upstream.
///
/// Returns `None` when the upstream can no longer carry a request; the caller
/// then ends the relay, which closes the client side too. An HTTP/1.1 server
/// sends nothing between responses, so any read result on the idle upstream
/// (EOF, an error, or unsolicited bytes such as a final `408` before closing)
/// counts as closed. Without this, a client whose pooled connection outlives
/// the server's keep-alive timeout writes its next request into a dead
/// upstream and gets the connection dropped with no response (Go's
/// `net/http` reports `EOF` and does not retry a POST). Closing the client
/// side as soon as the upstream closes lets the client drop the connection
/// from its pool and open a new one, as it would without the proxy.
async fn next_request_unless_upstream_closed<P, C, U>(
    provider: &P,
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Option<Result<Option<L7Request>>>
where
    P: L7Provider,
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + Unpin,
{
    let mut probe = [0u8; 1];
    tokio::select! {
        parsed = provider.parse_request(client) => Some(parsed),
        read = upstream.read(&mut probe) => {
            let reason = match read {
                Ok(0) => "eof".to_string(),
                Ok(n) => format!("{n} unsolicited byte(s)"),
                Err(e) => e.to_string(),
            };
            debug!(
                host = %ctx.host,
                port = ctx.port,
                reason = %reason,
                "Upstream closed idle connection, closing L7 relay"
            );
            None
        }
    }
}

/// Check if a miette error represents a benign connection close.
///
/// TLS handshake EOF, missing `close_notify`, connection resets, and broken
/// pipes are all normal lifecycle events for proxied connections — not worth
/// a WARN that interrupts the user's terminal.
fn is_benign_connection_error(err: &miette::Report) -> bool {
    const BENIGN: &[&str] = &[
        "close_notify",
        "tls handshake eof",
        "connection reset",
        "broken pipe",
        "unexpected eof",
        "client disconnected mid-request",
    ];
    let msg = err.to_string().to_ascii_lowercase();
    BENIGN.iter().any(|pat| msg.contains(pat))
}

/// Evaluate an L7 request against the OPA engine.
///
/// Returns `(allowed, deny_reason)`.
pub fn evaluate_l7_request(
    engine: &Mutex<regorus::Engine>,
    ctx: &L7EvalContext,
    request: &L7RequestInfo,
) -> Result<(bool, String)> {
    let input_json = serde_json::json!({
        "network": {
            "host": ctx.host,
            "port": ctx.port,
        },
        "exec": {
            "path": ctx.binary_path,
            "ancestors": ctx.ancestors,
            "cmdline_paths": ctx.cmdline_paths,
        },
        "request": {
            "method": request.action,
            "path": request.target,
            "query_params": request.query_params.clone(),
        }
    });

    let mut engine = engine
        .lock()
        .map_err(|_| miette!("OPA engine lock poisoned"))?;

    engine
        .set_input_json(&input_json.to_string())
        .map_err(|e| miette!("{e}"))?;

    let allowed = engine
        .eval_rule("data.openshell.sandbox.allow_request".into())
        .map_err(|e| miette!("{e}"))?;
    let allowed = allowed == regorus::Value::from(true);

    let reason = if allowed {
        String::new()
    } else {
        let val = engine
            .eval_rule("data.openshell.sandbox.request_deny_reason".into())
            .map_err(|e| miette!("{e}"))?;
        match val {
            regorus::Value::String(s) => s.to_string(),
            regorus::Value::Undefined => "request denied by policy".to_string(),
            other => other.to_string(),
        }
    };

    Ok((allowed, reason))
}

/// Relay HTTP traffic with credential injection only (no L7 OPA evaluation).
///
/// Used when TLS is auto-terminated but no L7 policy (`protocol` + `access`/`rules`)
/// is configured. Parses HTTP requests minimally to rewrite credential
/// placeholders and log requests for observability, then forwards everything.
pub async fn relay_passthrough_with_credentials<C, U>(
    client: &mut C,
    upstream: &mut U,
    ctx: &L7EvalContext,
) -> Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
    U: AsyncRead + AsyncWrite + Unpin + Send,
{
    let provider = crate::l7::rest::RestProvider;
    let mut request_count: u64 = 0;
    let resolver = ctx.secret_resolver.as_deref();

    loop {
        // Read next request from client.
        let Some(parsed) =
            next_request_unless_upstream_closed(&provider, client, upstream, ctx).await
        else {
            break;
        };
        let req = match parsed {
            Ok(Some(req)) => req,
            Ok(None) => break, // Client closed connection.
            Err(e) => {
                if is_benign_connection_error(&e) {
                    break;
                }
                return Err(e);
            }
        };

        request_count += 1;

        // Resolve and redact the target for logging.
        let redacted_target = if let Some(ref res) = ctx.secret_resolver {
            match secrets::rewrite_target_for_eval(&req.target, res) {
                Ok(result) => result.redacted,
                Err(e) => {
                    warn!(
                        host = %ctx.host,
                        port = ctx.port,
                        error = %e,
                        "credential resolution failed in request target, rejecting"
                    );
                    let response = b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    client.write_all(response).await.into_diagnostic()?;
                    client.flush().await.into_diagnostic()?;
                    return Ok(());
                }
            }
        } else {
            req.target.clone()
        };

        // Log for observability via OCSF HTTP Activity event.
        // Uses redacted_target (path only, no query params) to avoid logging secrets.
        let has_creds = resolver.is_some();
        {
            let event = HttpActivityBuilder::new(crate::ocsf_ctx())
                .activity(ActivityId::Other)
                .action(ActionId::Allowed)
                .disposition(DispositionId::Allowed)
                .severity(SeverityId::Informational)
                .http_request(HttpRequest::new(
                    &req.action,
                    OcsfUrl::new("http", &ctx.host, &redacted_target, ctx.port),
                ))
                .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
                .message(format!(
                    "HTTP_REQUEST {} {}:{}{} credentials_injected={has_creds} request_num={request_count}",
                    req.action, ctx.host, ctx.port, redacted_target,
                ))
                .build();
            ocsf_emit!(event);
        }

        // Forward request with credential rewriting and relay the response.
        // relay_http_request_with_resolver handles both directions: it sends
        // the request upstream and reads the response back to the client.
        let outcome =
            crate::l7::rest::relay_http_request_with_resolver(&req, client, upstream, resolver)
                .await?;

        match outcome {
            RelayOutcome::Reusable => {} // continue loop
            RelayOutcome::Consumed => break,
            RelayOutcome::Upgraded { overflow } => {
                return handle_upgrade(client, upstream, overflow, &ctx.host, ctx.port).await;
            }
        }
    }

    debug!(
        host = %ctx.host,
        port = ctx.port,
        total_requests = request_count,
        "Credential injection relay completed"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::{EnforcementMode, L7Protocol, TlsMode};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, DuplexStream};
    use tokio::task::JoinHandle;

    const STEP: Duration = Duration::from_secs(5);

    fn test_ctx() -> L7EvalContext {
        L7EvalContext {
            host: "api.example.com".into(),
            port: 443,
            policy_name: "test".into(),
            binary_path: "/usr/bin/test".into(),
            ancestors: vec![],
            cmdline_paths: vec![],
            secret_resolver: None,
        }
    }

    fn allow_all_engine() -> Mutex<regorus::Engine> {
        let mut engine = regorus::Engine::new();
        engine
            .add_policy(
                "allow.rego".into(),
                "package openshell.sandbox\nallow_request := true\n".into(),
            )
            .unwrap();
        Mutex::new(engine)
    }

    /// Streams seen by the test: the client application side and the upstream
    /// server side. The relay task owns the proxy-side halves, so they are
    /// dropped (closed) as soon as the relay returns.
    fn spawn_relay(inspect: bool) -> (DuplexStream, DuplexStream, JoinHandle<Result<()>>) {
        let (client, mut client_proxy) = tokio::io::duplex(8192);
        let (mut upstream_proxy, upstream) = tokio::io::duplex(8192);
        let relay = tokio::spawn(async move {
            let ctx = test_ctx();
            if inspect {
                let config = L7EndpointConfig {
                    protocol: L7Protocol::Rest,
                    tls: TlsMode::Auto,
                    enforcement: EnforcementMode::Enforce,
                };
                relay_with_inspection(
                    &config,
                    allow_all_engine(),
                    &mut client_proxy,
                    &mut upstream_proxy,
                    &ctx,
                )
                .await
            } else {
                relay_passthrough_with_credentials(&mut client_proxy, &mut upstream_proxy, &ctx)
                    .await
            }
        });
        (client, upstream, relay)
    }

    async fn read_until(stream: &mut DuplexStream, needle: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(needle.len()).any(|w| w == needle) {
            let n = tokio::time::timeout(STEP, stream.read(&mut chunk))
                .await
                .expect("read timed out")
                .unwrap();
            assert_ne!(n, 0, "stream closed before the expected bytes arrived");
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    }

    async fn round_trip(client: &mut DuplexStream, upstream: &mut DuplexStream, path: &str) {
        client
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: api.example.com\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let req = read_until(upstream, b"\r\n\r\n").await;
        assert!(req.starts_with(format!("GET {path} HTTP/1.1").as_bytes()));
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        let resp = read_until(client, b"\r\n\r\nok").await;
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
    }

    async fn assert_relay_ends_and_client_closed(
        mut client: DuplexStream,
        relay: JoinHandle<Result<()>>,
    ) {
        tokio::time::timeout(STEP, relay)
            .await
            .expect("relay must end once the idle upstream is gone")
            .unwrap()
            .unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(STEP, client.read(&mut buf))
            .await
            .expect("client side must be closed")
            .unwrap();
        assert_eq!(n, 0, "client must see EOF, not further bytes");
    }

    #[tokio::test]
    async fn rest_relay_closes_client_when_idle_upstream_closes() {
        let (mut client, mut upstream, relay) = spawn_relay(true);
        round_trip(&mut client, &mut upstream, "/first").await;
        round_trip(&mut client, &mut upstream, "/second").await;
        drop(upstream);
        assert_relay_ends_and_client_closed(client, relay).await;
    }

    #[tokio::test]
    async fn passthrough_relay_closes_client_when_idle_upstream_closes() {
        let (mut client, mut upstream, relay) = spawn_relay(false);
        round_trip(&mut client, &mut upstream, "/first").await;
        round_trip(&mut client, &mut upstream, "/second").await;
        drop(upstream);
        assert_relay_ends_and_client_closed(client, relay).await;
    }

    #[tokio::test]
    async fn relay_closes_client_on_unsolicited_upstream_bytes() {
        let (mut client, mut upstream, relay) = spawn_relay(true);
        round_trip(&mut client, &mut upstream, "/first").await;
        upstream
            .write_all(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_relay_ends_and_client_closed(client, relay).await;
        drop(upstream);
    }
}
