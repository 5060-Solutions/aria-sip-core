//! SIP message parsing utilities.
//!
//! Extracts headers, status codes, methods, URIs, and tags from raw SIP messages.

/// Extract a header value from a raw SIP message (case-insensitive).
pub fn extract_header(msg: &str, name: &str) -> Option<String> {
    let search = format!("{}:", name.to_lowercase());
    for line in msg.lines() {
        if line.to_lowercase().starts_with(&search) {
            let value = &line[name.len() + 1..];
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Extract all values for a given header (e.g., multiple Record-Route lines).
pub fn extract_all_headers(msg: &str, name: &str) -> Vec<String> {
    let search = format!("{}:", name.to_lowercase());
    let mut results = Vec::new();
    for line in msg.lines() {
        if line.to_lowercase().starts_with(&search) {
            let value = &line[name.len() + 1..];
            results.push(value.trim().to_string());
        }
    }
    results
}

/// Parse status code from a SIP response first line.
pub fn parse_status_code(msg: &str) -> Option<u16> {
    let first_line = msg.lines().next()?;
    if first_line.starts_with("SIP/2.0 ") {
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    None
}

/// Check if a raw SIP message is a request (not a response).
pub fn is_request(msg: &str) -> bool {
    let first_line = msg.lines().next().unwrap_or("");
    !first_line.starts_with("SIP/2.0")
}

/// Extract the method from a SIP request's first line.
pub fn extract_method(msg: &str) -> Option<String> {
    let first_line = msg.lines().next()?;
    if first_line.starts_with("SIP/2.0") {
        return None;
    }
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[0].to_string())
    } else {
        None
    }
}

/// Extract the CSeq method from a SIP message.
pub fn extract_cseq_method(msg: &str) -> Option<String> {
    let cseq = extract_header(msg, "CSeq")?;
    cseq.split_whitespace().last().map(|s| s.to_string())
}

/// Extract the From header's user and domain from a `sip:user@domain` URI.
pub fn extract_from_uri(msg: &str) -> Option<(String, String)> {
    let from = extract_header(msg, "From")?;
    extract_sip_uri(&from)
}

/// Extract user and domain from a `sip:user@domain` URI in a header value.
pub fn extract_sip_uri(header_value: &str) -> Option<(String, String)> {
    let sip_pos = header_value.find("sip:")?;
    let rest = &header_value[sip_pos + 4..];
    let end = rest.find(['>', ';', ' ']).unwrap_or(rest.len());
    let uri = &rest[..end];
    let parts: Vec<&str> = uri.splitn(2, '@').collect();
    if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string()))
    } else {
        None
    }
}

/// Extract caller display name from a From header value.
///
/// Handles the format: `"Display Name" <sip:user@domain>`
pub fn extract_display_name(msg: &str) -> Option<String> {
    let from = extract_header(msg, "From")?;
    extract_display_name_from_value(&from)
}

/// Extract display name from a raw header value (e.g., `"Alice" <sip:alice@example.com>`).
pub fn extract_display_name_from_value(value: &str) -> Option<String> {
    if let Some(start) = value.find('"') {
        let rest = &value[start + 1..];
        if let Some(end) = rest.find('"') {
            let name = rest[..end].trim().to_string();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

/// Extract the To tag from a SIP message.
pub fn extract_to_tag(msg: &str) -> Option<String> {
    let to = extract_header(msg, "To")?;
    extract_tag_from_value(&to)
}

/// Extract the From tag from a SIP message.
pub fn extract_from_tag(msg: &str) -> Option<String> {
    let from = extract_header(msg, "From")?;
    extract_tag_from_value(&from)
}

/// Extract a `tag=` parameter from a header value.
fn extract_tag_from_value(value: &str) -> Option<String> {
    let tag_pos = value.find("tag=")?;
    let tag_start = tag_pos + 4;
    let tag_end = value[tag_start..]
        .find([';', '>', ' '])
        .map(|p| tag_start + p)
        .unwrap_or(value.len());
    Some(value[tag_start..tag_end].to_string())
}

/// Extract the Via branch parameter from a SIP message.
pub fn extract_via_branch(msg: &str) -> Option<String> {
    let via = extract_header(msg, "Via")?;
    let branch_pos = via.find("branch=")?;
    let start = branch_pos + 7;
    let end = via[start..]
        .find([';', ',', ' '])
        .map(|p| start + p)
        .unwrap_or(via.len());
    Some(via[start..end].to_string())
}

/// Extract `received` and `rport` parameters from the Via header of a SIP response.
pub fn extract_via_received(msg: &str) -> Option<(String, u16)> {
    let via = extract_header(msg, "Via")?;
    let received = via.find("received=").map(|p| {
        let start = p + 9;
        let end = via[start..]
            .find([';', ',', ' '])
            .map(|e| start + e)
            .unwrap_or(via.len());
        via[start..end].to_string()
    })?;
    let rport = via.find("rport=").and_then(|p| {
        let start = p + 6;
        let end = via[start..]
            .find([';', ',', ' '])
            .map(|e| start + e)
            .unwrap_or(via.len());
        via[start..end].parse::<u16>().ok()
    })?;
    Some((received, rport))
}

/// Parse SDP to extract remote RTP connection address and port.
pub fn parse_sdp_connection(sdp: &str) -> Option<(String, u16)> {
    let mut ip = None;
    let mut port = None;

    for line in sdp.lines() {
        if let Some(addr) = line.strip_prefix("c=IN IP4 ") {
            ip = Some(addr.trim().to_string());
        }
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
        }
    }

    match (ip, port) {
        (Some(i), Some(p)) => Some((i, p)),
        _ => None,
    }
}

/// Parse a sipfrag body to extract the status code (e.g., "SIP/2.0 200 OK" -> 200).
pub fn parse_sipfrag_status(body: &str) -> Option<u16> {
    let line = body.lines().next()?;
    if line.starts_with("SIP/2.0 ") {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].parse().ok();
        }
    }
    None
}

/// Parse a Replaces header value: `"call-id;to-tag=xxx;from-tag=yyy"`.
///
/// Returns `(call_id, to_tag, from_tag)`.
pub fn parse_replaces_header(header_value: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = header_value.splitn(2, ';').collect();
    if parts.len() < 2 {
        return None;
    }
    let replaces_call_id = parts[0].trim().to_string();
    let params = parts[1];

    let mut to_tag = String::new();
    let mut from_tag = String::new();

    for param in params.split(';') {
        let param = param.trim();
        if let Some(val) = param.strip_prefix("to-tag=") {
            to_tag = val.to_string();
        } else if let Some(val) = param.strip_prefix("from-tag=") {
            from_tag = val.to_string();
        }
    }

    if to_tag.is_empty() || from_tag.is_empty() {
        return None;
    }

    Some((replaces_call_id, to_tag, from_tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REGISTER_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc;rport=5060;received=203.0.113.1\r\n\
From: <sip:alice@example.com>;tag=abc123\r\n\
To: <sip:alice@example.com>;tag=def456\r\n\
Call-ID: unique-call-id-123\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@10.0.0.1:5060>\r\n\
Content-Length: 0\r\n\r\n";

    const INVITE_REQ: &str = "\
INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-xyz\r\n\
From: \"Alice Smith\" <sip:alice@example.com>;tag=aaa111\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: invite-call-id-456\r\n\
CSeq: 1 INVITE\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 0\r\n\r\n";

    #[test]
    fn test_extract_header() {
        assert_eq!(
            extract_header(REGISTER_200, "Call-ID"),
            Some("unique-call-id-123".to_string())
        );
        assert_eq!(
            extract_header(REGISTER_200, "CSeq"),
            Some("1 REGISTER".to_string())
        );
    }

    #[test]
    fn test_extract_header_case_insensitive() {
        assert_eq!(
            extract_header(REGISTER_200, "call-id"),
            Some("unique-call-id-123".to_string())
        );
        assert_eq!(
            extract_header(REGISTER_200, "CALL-ID"),
            Some("unique-call-id-123".to_string())
        );
    }

    #[test]
    fn test_extract_header_missing() {
        assert_eq!(extract_header(REGISTER_200, "Route"), None);
    }

    #[test]
    fn test_parse_status_code() {
        assert_eq!(parse_status_code(REGISTER_200), Some(200));
        assert_eq!(parse_status_code(INVITE_REQ), None);
        assert_eq!(
            parse_status_code("SIP/2.0 401 Unauthorized\r\n"),
            Some(401)
        );
    }

    #[test]
    fn test_is_request() {
        assert!(!is_request(REGISTER_200));
        assert!(is_request(INVITE_REQ));
    }

    #[test]
    fn test_extract_method() {
        assert_eq!(extract_method(INVITE_REQ), Some("INVITE".to_string()));
        assert_eq!(extract_method(REGISTER_200), None);
    }

    #[test]
    fn test_extract_cseq_method() {
        assert_eq!(
            extract_cseq_method(REGISTER_200),
            Some("REGISTER".to_string())
        );
        assert_eq!(
            extract_cseq_method(INVITE_REQ),
            Some("INVITE".to_string())
        );
    }

    #[test]
    fn test_extract_from_uri() {
        assert_eq!(
            extract_from_uri(INVITE_REQ),
            Some(("alice".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn test_extract_display_name() {
        assert_eq!(
            extract_display_name(INVITE_REQ),
            Some("Alice Smith".to_string())
        );
        // No display name in REGISTER 200
        assert_eq!(extract_display_name(REGISTER_200), None);
    }

    #[test]
    fn test_extract_to_tag() {
        assert_eq!(
            extract_to_tag(REGISTER_200),
            Some("def456".to_string())
        );
        // INVITE request has no To tag
        assert_eq!(extract_to_tag(INVITE_REQ), None);
    }

    #[test]
    fn test_extract_from_tag() {
        assert_eq!(
            extract_from_tag(REGISTER_200),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_from_tag(INVITE_REQ),
            Some("aaa111".to_string())
        );
    }

    #[test]
    fn test_extract_via_branch() {
        assert_eq!(
            extract_via_branch(REGISTER_200),
            Some("z9hG4bK-abc".to_string())
        );
    }

    #[test]
    fn test_extract_via_received() {
        let (ip, port) = extract_via_received(REGISTER_200).unwrap();
        assert_eq!(ip, "203.0.113.1");
        assert_eq!(port, 5060);
    }

    #[test]
    fn test_parse_sdp_connection() {
        let sdp = "v=0\r\no=- 123 456 IN IP4 10.0.0.1\r\nc=IN IP4 192.168.1.100\r\nm=audio 8000 RTP/AVP 0\r\n";
        let (ip, port) = parse_sdp_connection(sdp).unwrap();
        assert_eq!(ip, "192.168.1.100");
        assert_eq!(port, 8000);
    }

    #[test]
    fn test_parse_sipfrag_status() {
        assert_eq!(parse_sipfrag_status("SIP/2.0 200 OK\r\n"), Some(200));
        assert_eq!(parse_sipfrag_status("SIP/2.0 100 Trying\r\n"), Some(100));
        assert_eq!(parse_sipfrag_status("garbage"), None);
    }

    #[test]
    fn test_parse_replaces_header() {
        let val = "abc123;to-tag=tt;from-tag=ft";
        let (cid, to, from) = parse_replaces_header(val).unwrap();
        assert_eq!(cid, "abc123");
        assert_eq!(to, "tt");
        assert_eq!(from, "ft");
    }

    #[test]
    fn test_parse_replaces_header_missing_tags() {
        assert_eq!(parse_replaces_header("abc123"), None);
        assert_eq!(parse_replaces_header("abc123;to-tag=tt"), None);
    }

    #[test]
    fn test_extract_sip_uri() {
        assert_eq!(
            extract_sip_uri("<sip:bob@example.com>"),
            Some(("bob".to_string(), "example.com".to_string()))
        );
        assert_eq!(
            extract_sip_uri("\"Bob\" <sip:bob@example.com>;tag=xyz"),
            Some(("bob".to_string(), "example.com".to_string()))
        );
    }

    #[test]
    fn test_extract_all_headers() {
        let msg = "\
SIP/2.0 200 OK\r\n\
Record-Route: <sip:proxy1.example.com;lr>\r\n\
Record-Route: <sip:proxy2.example.com;lr>\r\n\
From: <sip:alice@example.com>\r\n\
Content-Length: 0\r\n\r\n";
        let routes = extract_all_headers(msg, "Record-Route");
        assert_eq!(routes.len(), 2);
        assert!(routes[0].contains("proxy1"));
        assert!(routes[1].contains("proxy2"));
    }
}
