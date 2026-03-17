//! SIP Digest Authentication (RFC 2617 / RFC 7616).
//!
//! Computes MD5 or SHA-256 digest responses for SIP authentication challenges.
//! Supports optional realm override for FreeSwitch compatibility.

use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha2Digest, Sha256};

/// SIP Digest Authentication state.
pub struct DigestAuth {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub method: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub nc: u32,
    pub cnonce: String,
}

impl DigestAuth {
    /// Parse a WWW-Authenticate/Proxy-Authenticate challenge and build auth.
    pub fn from_challenge(
        www_auth: &str,
        username: &str,
        password: &str,
        uri: &str,
        method: &str,
    ) -> Option<Self> {
        Self::from_challenge_with_realm(www_auth, username, password, uri, method, None)
    }

    /// Create digest auth from a challenge, optionally overriding the realm.
    ///
    /// When `realm_override` is `Some`, it is used instead of the realm from the
    /// server's challenge header. This is needed for FreeSwitch deployments
    /// where the challenge realm doesn't match the realm used for HA1 verification.
    pub fn from_challenge_with_realm(
        www_auth: &str,
        username: &str,
        password: &str,
        uri: &str,
        method: &str,
        realm_override: Option<&str>,
    ) -> Option<Self> {
        let challenge_realm = extract_param(www_auth, "realm")?;
        let realm = match realm_override {
            Some(r) if !r.is_empty() => {
                log::info!(
                    "Auth realm override: challenge had '{}', using '{}' instead",
                    challenge_realm, r
                );
                r.to_string()
            }
            _ => {
                log::info!("Using challenge realm: '{}'", challenge_realm);
                challenge_realm
            }
        };
        let nonce = extract_param(www_auth, "nonce")?;
        let algorithm = extract_param(www_auth, "algorithm").unwrap_or_else(|| "MD5".to_string());
        let qop = extract_param(www_auth, "qop");
        let cnonce = format!("{:08x}", rand::random::<u32>());

        Some(Self {
            username: username.to_string(),
            password: password.to_string(),
            realm,
            nonce,
            uri: uri.to_string(),
            method: method.to_string(),
            algorithm,
            qop,
            nc: 1,
            cnonce,
        })
    }

    /// Compute the digest response hash.
    pub fn response(&self) -> String {
        let hash_fn: fn(&str) -> String = if self.algorithm.eq_ignore_ascii_case("SHA-256") {
            sha256_hex
        } else {
            md5_hex
        };

        let ha1 = hash_fn(&format!("{}:{}:{}", self.username, self.realm, self.password));
        let ha2 = hash_fn(&format!("{}:{}", self.method, self.uri));

        if let Some(ref qop) = self.qop {
            if qop.contains("auth") {
                let nc = format!("{:08x}", self.nc);
                return hash_fn(&format!(
                    "{}:{}:{}:{}:auth:{}",
                    ha1, self.nonce, nc, self.cnonce, ha2
                ));
            }
        }

        hash_fn(&format!("{}:{}:{}", ha1, self.nonce, ha2))
    }

    /// Format as a SIP Authorization header value.
    pub fn to_header(&self) -> String {
        let response = self.response();
        let mut header = format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", response=\"{}\"",
            self.username, self.realm, self.nonce, self.uri, response
        );

        if self.algorithm != "MD5" {
            header.push_str(&format!(", algorithm={}", self.algorithm));
        }

        if self.qop.is_some() {
            header.push_str(&format!(
                ", qop=auth, nc={:08x}, cnonce=\"{}\"",
                self.nc, self.cnonce
            ));
        }

        header
    }
}

/// Extract the realm from a WWW-Authenticate/Proxy-Authenticate challenge header.
pub fn extract_challenge_realm(header: &str) -> Option<String> {
    extract_param(header, "realm")
}

/// Extract a named parameter from a digest challenge header.
///
/// Handles both quoted (`realm="example.com"`) and unquoted (`algorithm=MD5`) values.
pub fn extract_param(header: &str, name: &str) -> Option<String> {
    let search = format!("{name}=");
    // Find the parameter, ensuring we match a whole word boundary
    // (e.g., searching for "nonce=" must not match "cnonce=").
    let pos = header
        .match_indices(&search)
        .find(|&(i, _)| i == 0 || !header.as_bytes()[i - 1].is_ascii_alphanumeric())?
        .0;
    let rest = &header[pos + search.len()..];

    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn md5_hex(input: &str) -> String {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input.as_bytes());
    hex::encode(Md5Digest::finalize(hasher))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    Sha2Digest::update(&mut hasher, input.as_bytes());
    hex::encode(Sha2Digest::finalize(hasher))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_md5_response_length() {
        let auth = DigestAuth {
            username: "bob".to_string(),
            password: "zanzibar".to_string(),
            realm: "biloxi.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            uri: "sip:bob@biloxi.com".to_string(),
            method: "REGISTER".to_string(),
            algorithm: "MD5".to_string(),
            qop: None,
            nc: 1,
            cnonce: "0a4f113b".to_string(),
        };
        assert_eq!(auth.response().len(), 32);
    }

    #[test]
    fn test_digest_md5_with_qop() {
        let auth = DigestAuth {
            username: "alice".to_string(),
            password: "secret".to_string(),
            realm: "atlanta.com".to_string(),
            nonce: "ea9c8e88df84f1cec4341ae6cbe5a359".to_string(),
            uri: "sip:atlanta.com".to_string(),
            method: "REGISTER".to_string(),
            algorithm: "MD5".to_string(),
            qop: Some("auth".to_string()),
            nc: 1,
            cnonce: "0a4f113b".to_string(),
        };
        let resp = auth.response();
        assert_eq!(resp.len(), 32);

        // Verify header format includes qop fields
        let header = auth.to_header();
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("cnonce=\"0a4f113b\""));
    }

    #[test]
    fn test_digest_sha256() {
        let auth = DigestAuth {
            username: "bob".to_string(),
            password: "zanzibar".to_string(),
            realm: "biloxi.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            uri: "sip:bob@biloxi.com".to_string(),
            method: "REGISTER".to_string(),
            algorithm: "SHA-256".to_string(),
            qop: None,
            nc: 1,
            cnonce: "0a4f113b".to_string(),
        };
        // SHA-256 produces 64-char hex
        assert_eq!(auth.response().len(), 64);
        let header = auth.to_header();
        assert!(header.contains("algorithm=SHA-256"));
    }

    #[test]
    fn test_from_challenge() {
        let challenge = r#"Digest realm="biloxi.com", nonce="abc123", algorithm=MD5, qop="auth""#;
        let auth = DigestAuth::from_challenge(
            challenge, "bob", "zanzibar", "sip:biloxi.com", "REGISTER",
        ).unwrap();
        assert_eq!(auth.realm, "biloxi.com");
        assert_eq!(auth.nonce, "abc123");
        assert_eq!(auth.algorithm, "MD5");
        assert_eq!(auth.qop, Some("auth".to_string()));
    }

    #[test]
    fn test_from_challenge_with_realm_override() {
        let challenge = r#"Digest realm="biloxi.com", nonce="abc123""#;
        let auth = DigestAuth::from_challenge_with_realm(
            challenge, "bob", "zanzibar", "sip:biloxi.com", "REGISTER",
            Some("override.com"),
        ).unwrap();
        assert_eq!(auth.realm, "override.com");
    }

    #[test]
    fn test_from_challenge_empty_realm_override_uses_challenge() {
        let challenge = r#"Digest realm="biloxi.com", nonce="abc123""#;
        let auth = DigestAuth::from_challenge_with_realm(
            challenge, "bob", "zanzibar", "sip:biloxi.com", "REGISTER",
            Some(""),
        ).unwrap();
        assert_eq!(auth.realm, "biloxi.com");
    }

    #[test]
    fn test_extract_param_quoted() {
        let header = r#"Digest realm="example.com", nonce="abc""#;
        assert_eq!(extract_param(header, "realm"), Some("example.com".into()));
        assert_eq!(extract_param(header, "nonce"), Some("abc".into()));
    }

    #[test]
    fn test_extract_param_unquoted() {
        let header = "Digest algorithm=SHA-256, qop=\"auth\"";
        assert_eq!(extract_param(header, "algorithm"), Some("SHA-256".into()));
    }

    #[test]
    fn test_extract_param_missing() {
        let header = r#"Digest realm="example.com""#;
        assert_eq!(extract_param(header, "nonce"), None);
    }

    #[test]
    fn test_extract_param_nonce_not_confused_with_cnonce() {
        // SIPp sends cnonce before nonce — extract_param("nonce") must not
        // match the "nonce=" substring inside "cnonce=".
        let header = r#"Digest username="1002",realm="lyonscomm.com",cnonce="1eb20305",nc=00000001,qop=auth,uri="sip:lyonscomm.com",nonce="1ca945e55e9c3f28a8e7249aa2adbe41",response="de4b28e1",algorithm=MD5"#;
        assert_eq!(
            extract_param(header, "nonce"),
            Some("1ca945e55e9c3f28a8e7249aa2adbe41".into()),
            "nonce must not match cnonce"
        );
        assert_eq!(
            extract_param(header, "cnonce"),
            Some("1eb20305".into()),
        );
        assert_eq!(
            extract_param(header, "nc"),
            Some("00000001".into()),
            "nc must not match cnonce"
        );
    }

    #[test]
    fn test_extract_challenge_realm() {
        let header = r#"Digest realm="sip.example.com", nonce="xyz""#;
        assert_eq!(extract_challenge_realm(header), Some("sip.example.com".into()));
    }

    #[test]
    fn test_to_header_format() {
        let auth = DigestAuth {
            username: "alice".to_string(),
            password: "secret".to_string(),
            realm: "atlanta.com".to_string(),
            nonce: "ea9c8e88".to_string(),
            uri: "sip:atlanta.com".to_string(),
            method: "REGISTER".to_string(),
            algorithm: "MD5".to_string(),
            qop: None,
            nc: 1,
            cnonce: "0a4f113b".to_string(),
        };
        let header = auth.to_header();
        assert!(header.starts_with("Digest username=\"alice\""));
        assert!(header.contains("realm=\"atlanta.com\""));
        assert!(header.contains("response=\""));
        assert!(!header.contains("algorithm=")); // MD5 is default, omitted
    }
}
