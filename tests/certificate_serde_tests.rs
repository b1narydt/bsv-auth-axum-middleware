//! Parity check: `bsv::wallet::interfaces::Certificate` must round-trip through
//! the TS `auth-express-middleware` wire format (camelCase field names) without
//! loss. Guards against silent snake_case leaks that would break wire compat
//! with TS peers.

use bsv::wallet::interfaces::Certificate;

// Both public keys are valid secp256k1 compressed points used in the SDK's own
// test vectors.  Using real curve points ensures PublicKey::from_string()
// succeeds during deserialization.
//
// subject  = generator point G (private key 0x01)
// certifier = point for private key 0xFF (both well-known SDK test vectors)
//
// The other values are deliberately minimal:
//   type / serialNumber : base64-encoded 32-byte payloads
//   revocationOutpoint  : free-form "txid.vout" string
//   fields              : arbitrary key-value pairs
//   signature           : hex-encoded bytes
const TS_CERTIFICATE_JSON: &str = r#"{
    "type": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "serialNumber": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
    "subject": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "certifier": "02d8096af8a11e0b80037e1ee68246b5dcbb0aeb1cf1244fd767db80f3fa27da2b",
    "revocationOutpoint": "a0a1a2a3a4a5a6a7a8a9b0b1b2b3b4b5b6b7b8b9c0c1c2c3c4c5c6c7c8c9d0d1.0",
    "fields": {
        "name": "QWxpY2U=",
        "age": "MzA="
    },
    "signature": "3045022100abcdef"
}"#;

#[test]
fn test_certificate_deserializes_from_ts_camelcase() {
    let cert: Result<Certificate, _> = serde_json::from_str(TS_CERTIFICATE_JSON);
    assert!(
        cert.is_ok(),
        "Certificate must deserialize from TS wire format: {:?}",
        cert.err()
    );
}

#[test]
fn test_certificate_reserializes_to_ts_camelcase() {
    let cert: Certificate =
        serde_json::from_str(TS_CERTIFICATE_JSON).expect("deserialize from TS shape");
    let out = serde_json::to_value(&cert).expect("serialize back to JSON");

    // Must contain camelCase keys (TS contract).
    assert!(
        out.get("type").is_some(),
        "missing 'type' key; got: {}",
        out
    );
    assert!(
        out.get("serialNumber").is_some(),
        "missing 'serialNumber' key; got: {}",
        out
    );
    assert!(
        out.get("subject").is_some(),
        "missing 'subject' key; got: {}",
        out
    );
    assert!(
        out.get("certifier").is_some(),
        "missing 'certifier' key; got: {}",
        out
    );
    assert!(
        out.get("revocationOutpoint").is_some(),
        "missing 'revocationOutpoint' key; got: {}",
        out
    );

    // Must NOT contain snake_case leaks.
    assert!(
        out.get("serial_number").is_none(),
        "snake_case key leaked: serial_number"
    );
    assert!(
        out.get("revocation_outpoint").is_none(),
        "snake_case key leaked: revocation_outpoint"
    );
    assert!(
        out.get("cert_type").is_none(),
        "snake_case key leaked: cert_type"
    );
}
