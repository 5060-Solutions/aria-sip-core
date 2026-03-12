# Aria SIP Core

Shared SIP protocol utilities for the Aria ecosystem. Used by both the [Aria desktop softphone](https://github.com/5060-Solutions/aria) and the [Aria push gateway](https://github.com/5060-Solutions/aria-push-gateway).

## Features

- **Digest authentication** (RFC 2617 / RFC 7616) -- compute and verify SIP digest auth responses
- **SIP message parsing** -- extract headers, status codes, URIs, display names, tags, branches
- **ID generation** -- RFC 3261 compliant Via branch, From/To tags, Call-ID

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
aria-sip-core = { path = "../aria-sip-core" }
```

### Parsing

```rust
use aria_sip_core::parser::*;

let status = parse_status_code(response);
let method = extract_method(request);
let call_id = extract_header(msg, "Call-ID");
let from_tag = extract_from_tag(msg);
let to_tag = extract_to_tag(msg);
```

### Auth

```rust
use aria_sip_core::auth::compute_digest_response;

let response = compute_digest_response(
    username, password, realm, nonce, uri, method, nc, cnonce, qop,
);
```

### IDs

```rust
use aria_sip_core::{generate_branch, generate_tag, generate_call_id};

let branch = generate_branch();   // z9hG4bK-<uuid>
let tag = generate_tag();          // 8-char hex
let call_id = generate_call_id();  // uuid
```

## Testing

```bash
cargo test
```

## Ecosystem

| Crate | Role |
|-------|------|
| [aria](https://github.com/5060-Solutions/aria) | Desktop softphone (Tauri + Rust) |
| [rtp-engine](https://github.com/5060-Solutions/rtp-engine) | RTP media engine |
| **aria-sip-core** | Shared SIP protocol library |
| [aria-push-gateway](https://github.com/5060-Solutions/aria-push-gateway) | SIP push notification gateway |
| [aria-mobile-core](https://github.com/5060-Solutions/aria-mobile-core) | Shared Rust engine for mobile |
| [aria-ios](https://github.com/5060-Solutions/aria-ios) | iOS native softphone |
| [aria-android](https://github.com/5060-Solutions/aria-android) | Android native softphone |

## License

MIT
