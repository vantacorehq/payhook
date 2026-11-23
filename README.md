# payhook

**Webhook engine for Stripe / Crypto / TON / USDT.**

HMAC verification · Replay protection · Guaranteed retries · Pure Rust · Zero dependencies

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## The problem

When servers crash or webhooks are retried:

- Payments are lost
- Payments are applied twice
- Replay attacks succeed
- No reliable retry queue

## Features

| Feature | Description |
|---------|-------------|
| Strict HMAC | Stripe-style + custom secrets |
| Replay protection | Timestamp + nonce window |
| Idempotency keys | Process exactly once |
| Retry queue | Exponential backoff |
| Dead-letter | After max attempts |
| Full audit | Every decision logged |
| Zero deps | Only `std` |

## Quick start

```toml
[dependencies]
payhook = { git = "https://github.com/vantacorehq/payhook" }
```

```rust
use payhook::{Verifier, Webhook};

fn main() {
    let verifier = Verifier::new(b"whsec_live_...");

    let webhook = Webhook {
        payload: b"{...}",
        signature: "t=...,v1=...".into(),
        timestamp: 1732000000,
        nonce: Some("n-123".into()),
    };

    match verifier.verify(&webhook) {
        Ok(()) => {
            // process once (idempotent)
        }
        Err(e) => {
            // reject / enqueue for retry
            eprintln!("{:?}", e);
        }
    }
}
```

## Commercial

Integration of the payment core (Stripe + crypto + TON/USDT): **$600 – $2 000**.

Pairs well with `gridlock` and `folio`.

## License

MIT
