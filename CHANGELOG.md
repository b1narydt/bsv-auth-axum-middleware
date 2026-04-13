# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-04-12

### Fixed
- Emit `x-bsv-auth-message-type` header on non-general responses
  (initialResponse, certificateRequest, certificateResponse). Matches
  `auth-express-middleware` `send()` behavior; required by
  `SimplifiedFetchTransport` to route `certificateRequest` responses
  (otherwise they fall through as `general` and the cert exchange breaks).
- Certificate branch of `/.well-known/auth` now awaits a signed outgoing
  `AuthMessage` from `Peer` (500ms timeout) and returns it with the full
  signed-header set, instead of a bare `{"status":"ok"}` ack with no auth
  headers. Short-timeout fallback preserves today's behavior while
  [bsv-rust-sdk#19](https://github.com/b1narydt/bsv-rust-sdk/issues/19)
  is open.
- Emit `x-bsv-auth-requested-certificates` (JSON) on both non-general and
  general response paths when the outgoing `AuthMessage` carries
  `requested_certificates`.

### Added
- `build_non_general_signed_response` unified builder for initialResponse,
  certificateRequest, and certificateResponse replies, so all three share
  the exact TS-parity header set.
- `message_type_header_value` helper pinning the TS-literal strings
  (`initialRequest` / `initialResponse` / `certificateRequest` /
  `certificateResponse` / `general`) to prevent silent drift from serde
  renames.
- 3 tests pinning non-general header set, requested-certificates header
  emission, and message-type string literals.

## [0.1.0] - 2026-04-12

### Added
- Initial release of `bsv-auth-axum-middleware`.
- Port of `bsv-auth-actix-middleware` v0.2.0 to axum 0.8 + tower 0.5.
- `AuthMiddlewareConfig` + `AuthMiddlewareConfigBuilder` with `wallet`,
  `allow_unauthenticated`, `certificates_to_request`, `session_manager`,
  `on_certificates_received`, and `log_level` options.
- `AuthLayer::from_config(config, peer, transport).await` factory that wires
  certificate lifecycle via `certificate_listener_task` and a `CertificateGate`.
- `AuthLayer::new(peer, transport, allow_unauthenticated)` convenience for the
  no-certificate case.
- `Authenticated` extractor (`FromRequestParts`) exposing the peer identity key.
- `ActixTransport` with `DEFAULT_PENDING_TIMEOUT` (30s) and per-entry abort-handle
  cleanup, matching TS `openNextHandlerTimeouts` semantics.
- `AuthMiddlewareError` variants `Unauthorized`, `CertificateTimeout`, and
  `ResponseSigningFailed`; `IntoResponse` emits TS-exact wire bodies:
  - 401 `{"status":"error","code":"UNAUTHORIZED","message":"Mutual-authentication failed!"}`
  - 408 `{"status":"error","code":"CERTIFICATE_TIMEOUT","message":"Certificate request timed out"}`
  - 500 `{"status":"error","code":"ERR_RESPONSE_SIGNING_FAILED","description":"<reason>"}`
- Empty-certificate guard on `certificateResponse`: returns
  `400 {"status":"No certificates provided"}`.
- Integration tests (20) ported from actix v0.2.0: every HTTP method,
  content-type (JSON, urlencoded, text, binary), query params, custom headers,
  edge cases (missing Content-Type, empty body, object body), server restart,
  charset injection, stale session recovery, concurrent requests, and
  unauthenticated TS parity.
- Certificate exchange tests (4): protected endpoint, empty/missing certs
  responses, full cert request flow.
- Round-trip serde parity check for `bsv::wallet::interfaces::Certificate`
  against TS wire format.
- Runnable `examples/basic_auth_server.rs`.

[0.1.1]: https://github.com/b1narydt/bsv-auth-axum-middleware/releases/tag/v0.1.1
[0.1.0]: https://github.com/b1narydt/bsv-auth-axum-middleware/releases/tag/v0.1.0
