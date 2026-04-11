//! Shared test infrastructure for BRC-31 axum auth middleware integration tests.
//!
//! Exposes:
//! - [`test_server::spawn_test_server`] — spawn an in-process axum server wrapped
//!   with `AuthLayer` on a random `127.0.0.1` port; returns a [`test_server::TestServer`]
//!   handle containing the base URL and the shared server `Peer`.
//! - [`test_server::TestWallet`] — `Clone`-able wrapper around `ProtoWallet` that
//!   implements `WalletInterface` so it satisfies `AuthLayer`'s `W: Clone` bound.
//! - [`test_server::init_tracing`] — idempotent `tracing_subscriber` init for test logs.
//!
//! These tests run against real `bsv_sdk::auth::Peer` state machines on both the
//! server (via `AuthLayer`) and the client (via `bsv_sdk::auth::clients::AuthFetch`).
//! No mocks — the only layer shimmed is the `WalletInterface` wrapper to satisfy
//! trait bounds.

pub mod test_server;
