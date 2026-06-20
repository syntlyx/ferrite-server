//! Minimal HTTP/1.x `Host`-header peeker for the plain-HTTP (:80) proxy path.
//!
//! Reads the request head to learn which host the client is talking to, then
//! the connection is spliced through the chosen egress unchanged. Bounds- and
//! UTF-8-checked; malformed input yields `NotFound`.

/// Outcome of attempting to read the Host from a (possibly partial) request.
#[derive(Debug, PartialEq, Eq)]
pub enum HostResult {
    /// Host found (lowercased, port stripped, no trailing dot).
    Found(String),
    /// Headers not fully received yet — read more.
    Incomplete,
    /// Not a parseable HTTP request, or no Host header.
    NotFound,
}

const MAX_HEAD: usize = 8 * 1024;

pub fn parse_http_host(buf: &[u8]) -> HostResult {
    let head_end = match find_subsequence(buf, b"\r\n\r\n") {
        Some(i) => i,
        None => {
            return if buf.len() > MAX_HEAD {
                HostResult::NotFound
            } else {
                HostResult::Incomplete
            };
        }
    };

    let head = match std::str::from_utf8(&buf[..head_end]) {
        Ok(t) => t,
        Err(_) => return HostResult::NotFound,
    };

    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    if !looks_like_http(request_line) {
        return HostResult::NotFound;
    }

    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("host") {
                let host = host_without_port(value);
                if host.is_empty() {
                    return HostResult::NotFound;
                }
                return HostResult::Found(host);
            }
        }
    }
    HostResult::NotFound
}

/// A request line looks like `METHOD target HTTP/1.x`.
fn looks_like_http(line: &str) -> bool {
    line.rsplit(' ')
        .next()
        .is_some_and(|v| v.starts_with("HTTP/"))
        && line.split(' ').count() == 3
}

fn host_without_port(value: &str) -> String {
    let h = value.trim();
    let bare = if let Some(rest) = h.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        rest.split(']').next().unwrap_or(rest)
    } else if let Some((host, port)) = h.rsplit_once(':') {
        if !port.is_empty() && port.bytes().all(|c| c.is_ascii_digit()) {
            host
        } else {
            h
        }
    } else {
        h
    };
    bare.trim_end_matches('.').to_ascii_lowercase()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host() {
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            HostResult::Found("example.com".to_string())
        );
    }

    #[test]
    fn strips_port_and_lowercases_case_insensitive_header() {
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nhOsT: Example.COM:8080\r\n\r\n"),
            HostResult::Found("example.com".to_string())
        );
    }

    #[test]
    fn absolute_form_request_uses_host_header() {
        assert_eq!(
            parse_http_host(b"GET http://x.test/p HTTP/1.1\r\nHost: x.test\r\n\r\n"),
            HostResult::Found("x.test".to_string())
        );
    }

    #[test]
    fn incomplete_until_blank_line() {
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            HostResult::Incomplete
        );
    }

    #[test]
    fn non_http_is_not_found() {
        // A TLS ClientHello arriving on :80, or random bytes.
        assert_eq!(parse_http_host(b"\x16\x03\x01\x00\x10rubbish\r\n\r\n"), HostResult::NotFound);
    }

    #[test]
    fn missing_host_header_is_not_found() {
        assert_eq!(
            parse_http_host(b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n"),
            HostResult::NotFound
        );
    }
}
