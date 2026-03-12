//! Shared SIP protocol utilities for the Aria ecosystem.
//!
//! This crate provides common SIP building blocks used by both the Aria
//! desktop softphone and the Aria push gateway:
//!
//! - **Digest authentication** (RFC 2617 / RFC 7616)
//! - **SIP message parsing** (header extraction, status codes, URI parsing)
//! - **ID generation** (Via branch, From/To tags, Call-ID)

pub mod auth;
pub mod parser;

/// Generate a unique Via branch parameter (RFC 3261 magic cookie prefix).
pub fn generate_branch() -> String {
    format!("z9hG4bK-{}", uuid::Uuid::new_v4().as_simple())
}

/// Generate a unique tag for From/To headers.
pub fn generate_tag() -> String {
    format!("{:08x}", rand::random::<u32>())
}

/// Generate a unique Call-ID.
pub fn generate_call_id() -> String {
    format!("{}", uuid::Uuid::new_v4().as_simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_has_magic_cookie() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK-"));
        assert!(branch.len() > 10);
    }

    #[test]
    fn tag_is_hex() {
        let tag = generate_tag();
        assert_eq!(tag.len(), 8);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn call_id_is_nonempty() {
        let cid = generate_call_id();
        assert!(cid.len() > 20);
    }
}
