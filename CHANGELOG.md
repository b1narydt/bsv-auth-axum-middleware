## 0.5.0 — blocking certificate authorization (#552)

- Add mandatory async `CertificateAuthorizer` policy decisions for every
  certificate-gated configuration. `trusted_certifiers` without an authorizer
  now fails construction instead of returning an ungated layer.
- Remove the unused public `AuthLayer::with_certificate_gate` escape hatch;
  `AuthLayer::from_config` is the sole certificate-gated constructor. The
  no-certificate `AuthLayer::new` constructor is now fallible and rejects a
  preconfigured certificate-requesting SDK peer; request-time checks require
  the exact sealed SDK configuration captured by construction.
- Atomically configure and seal the SDK certificate request and authorizer at
  construction, capturing an exact monotonic generation. Same-shape request or
  authorizer replacement is rejected, eliminating the check/dispatch race.
  Rejected constructors validate before conditional sealing, leaving a
  caller-owned `Peer` mutable and recoverable for a compatible retry.
- Install authorization before SDK certificate admission. Keep
  `on_certificates_received` as post-admission observation only, and remove the
  one-shot certificate-request observer from gate construction.
- Stage the locally validated exact-session batch inside the blocking SDK
  authorizer, then promote it through the SDK's atomic admission commit hook.
  SDK authority cannot precede the HTTP gate, while cancellation before
  terminal acceptance rolls back the exact provisional owner and remains
  retryable. Explicit rejection and authorizer timeout remain terminal.
- Return signed `403 ERR_CERTIFICATE_REJECTED` and signed
  `408 CERTIFICATE_TIMEOUT` only for signature-verified general requests using
  the SDK's one-use refusal capability. Invalid requests remain unsigned.
- Bound the compatibility-only identity `pending` and `validated` maps to 1024
  entries each with a 15-minute idle TTL; neither map is HTTP authority.
- Bound the post-admission observer queue to 1024 events. Overflow is dropped
  as non-authoritative observation only; callbacks run sequentially without
  spawned tasks and are cancelled after 30 seconds.
- Cover authorizer accept, reject, pending and terminal timeout, missing
  authorizer, pre-taken observer, unsigned invalid requests, and observer-map
  capacity/expiry.

## 0.4.1 — session-bound HTTP certificate batches (#529)

- Bind HTTP certificate authority to the exact authenticated local BRC session,
  not the wallet identity shared by concurrent sessions.
- Enforce exact retained disclosure fields, including rejecting missing,
  substituted or extra valid keys; preserve empty-field/empty-keyring proofs.
- Prune session batches on admission and periodically against SDK active
  sessions, honoring cap eviction and idle expiry without an SDK API change.
- Await SDK proof validation and retained-request checks before recording the
  first immutable session batch; replacement credentials require reconnect.
- Preserve `Authenticated` and legacy identity observation APIs; expose separate
  `AuthenticatedSession` and read-only session batch lookup.
- Consume the maintained 0.8.1 SDK source and cover both certificate orders,
  concurrent/reused HTTP, zero/nonempty disclosure and hostile frames.

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
