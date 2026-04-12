//! Request and response payload serialization for BRC-31 authentication.
//!
//! Provides a two-layer API:
//! - **Pure layer:** Generic functions accepting `&str`, `&[u8]`, `&[(String, String)]`
//!   for testability without framework dependencies.
//! - **HTTP wrapper layer:** Thin wrappers that extract data from `http` crate types
//!   and delegate to the pure functions.

use axum::http::{HeaderMap, StatusCode};

// ---------------------------------------------------------------------------
// Varint encoding (matching bsv-rust-sdk auth_fetch.rs exactly)
// ---------------------------------------------------------------------------

/// Write a signed Bitcoin-style varint.
pub(crate) fn write_varint_num(buf: &mut Vec<u8>, val: i64) {
    if val < 0 {
        let uval = val as u64;
        buf.push(0xff);
        buf.extend_from_slice(&uval.to_le_bytes());
        return;
    }
    let val = val as u64;
    if val < 0xfd {
        buf.push(val as u8);
    } else if val <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(val as u16).to_le_bytes());
    } else if val <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(val as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&val.to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// Header filtering (pure layer)
// ---------------------------------------------------------------------------

/// Filter and sort request headers according to BRC-31 signing rules.
pub fn filter_and_sort_request_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut included: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.to_lowercase();
            if key.starts_with("x-bsv-auth") {
                return None;
            }
            if key.starts_with("x-bsv-") || key == "content-type" || key == "authorization" {
                let value = if key == "content-type" {
                    v.split(';').next().unwrap_or("").trim().to_string()
                } else {
                    v.clone()
                };
                Some((key, value))
            } else {
                None
            }
        })
        .collect();
    included.sort_by(|(a, _), (b, _)| a.cmp(b));
    included
}

/// Filter and sort response headers according to BRC-31 signing rules.
pub fn filter_and_sort_response_headers(headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut included: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            let key = k.to_lowercase();
            if key.starts_with("x-bsv-auth") {
                return None;
            }
            if key.starts_with("x-bsv-") || key == "authorization" {
                Some((key, v.clone()))
            } else {
                None
            }
        })
        .collect();
    included.sort_by(|(a, _), (b, _)| a.cmp(b));
    included
}

// ---------------------------------------------------------------------------
// Payload serialization (pure layer)
// ---------------------------------------------------------------------------

/// Serialize a request payload for BRC-31 signature verification.
pub fn serialize_request_payload(
    request_nonce: &[u8],
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request_nonce);

    let method_bytes = method.as_bytes();
    write_varint_num(&mut buf, method_bytes.len() as i64);
    buf.extend_from_slice(method_bytes);

    if !path.is_empty() {
        let path_bytes = path.as_bytes();
        write_varint_num(&mut buf, path_bytes.len() as i64);
        buf.extend_from_slice(path_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    if !query.is_empty() {
        let query_bytes = query.as_bytes();
        write_varint_num(&mut buf, query_bytes.len() as i64);
        buf.extend_from_slice(query_bytes);
    } else {
        write_varint_num(&mut buf, -1);
    }

    write_varint_num(&mut buf, headers.len() as i64);
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);
        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    match body {
        Some(b) if !b.is_empty() => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        _ => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

/// Serialize a response payload for BRC-31 signature verification.
pub fn serialize_response_payload(
    request_nonce: &[u8],
    status_code: u16,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(request_nonce);

    write_varint_num(&mut buf, status_code as i64);

    write_varint_num(&mut buf, headers.len() as i64);
    for (key, value) in headers {
        let key_bytes = key.as_bytes();
        write_varint_num(&mut buf, key_bytes.len() as i64);
        buf.extend_from_slice(key_bytes);
        let value_bytes = value.as_bytes();
        write_varint_num(&mut buf, value_bytes.len() as i64);
        buf.extend_from_slice(value_bytes);
    }

    match body {
        Some(b) if !b.is_empty() => {
            write_varint_num(&mut buf, b.len() as i64);
            buf.extend_from_slice(b);
        }
        _ => {
            write_varint_num(&mut buf, -1);
        }
    }

    buf
}

// ---------------------------------------------------------------------------
// HTTP wrapper layer (axum/http types)
// ---------------------------------------------------------------------------

/// Extract headers from an `http::HeaderMap` as `(String, String)` pairs.
pub fn headers_from_map(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect()
}

/// Serialize a response payload from status code, headers, and body bytes.
pub fn serialize_from_http_response(
    request_nonce: &[u8],
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> Vec<u8> {
    let raw_headers = headers_from_map(headers);
    let filtered_headers = filter_and_sort_response_headers(&raw_headers);
    serialize_response_payload(
        request_nonce,
        status.as_u16(),
        &filtered_headers,
        if body.is_empty() { None } else { Some(body) },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_neg1() -> Vec<u8> {
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    }

    #[test]
    fn test_varint_negative_writes_twos_complement_u64() {
        let mut buf = Vec::new();
        write_varint_num(&mut buf, -1);
        assert_eq!(
            buf,
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
        );
    }

    #[test]
    fn test_serialize_request_payload_fixture() {
        let nonce = [0x01, 0x02, 0x03, 0x04];
        let headers = vec![("x-bsv-topic".to_string(), "hello".to_string())];
        let result = serialize_request_payload(&nonce, "GET", "/test", "", &headers, None);

        let mut expected = Vec::new();
        expected.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        expected.push(0x03);
        expected.extend_from_slice(b"GET");
        expected.push(0x05);
        expected.extend_from_slice(b"/test");
        expected.extend_from_slice(&varint_neg1());
        expected.push(0x01);
        expected.push(0x0B);
        expected.extend_from_slice(b"x-bsv-topic");
        expected.push(0x05);
        expected.extend_from_slice(b"hello");
        expected.extend_from_slice(&varint_neg1());

        assert_eq!(result, expected);
    }

    #[test]
    fn test_request_headers_exclude_x_bsv_auth() {
        let headers = vec![
            ("x-bsv-auth-version".to_string(), "0.1".to_string()),
            ("x-bsv-topic".to_string(), "hello".to_string()),
        ];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "x-bsv-topic");
    }

    #[test]
    fn test_request_headers_include_content_type_normalized() {
        let headers = vec![(
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        )];
        let result = filter_and_sort_request_headers(&headers);
        assert_eq!(result[0].1, "application/json");
    }
}
