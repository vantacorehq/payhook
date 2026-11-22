# payhook

Webhook reception and verification engine.

Pure Rust. Zero dependencies.

## What it solves

When servers crash or webhooks are retried:
- Payments are lost
- Payments are applied twice
- Replay attacks succeed
- No reliable retry queue

## Features

- Strict HMAC-SHA256 verification (Stripe-style and custom)
- Replay protection (timestamp + nonce window)
- Idempotency keys
- Guaranteed retry queue with exponential backoff
- Dead-letter after max attempts
- Audit of every decision

## Usage

```rust
use payhook::{Verifier, Webhook};

let verifier = Verifier::new(b"whsec_live_...");

let webhook = Webhook {
    payload: body.as_bytes(),
    signature: header_sig,
    timestamp: header_ts,
    nonce: header_nonce,
};

match verifier.verify(&webhook) {
    Ok(()) => {
        // process once (idempotent)
    }
    Err(e) => {
        // reject and optionally enqueue for retry
    }
}
```

## Commercial

Integration of the payment core (Stripe + crypto + TON/USDT): $600–$2000.

Pairs well with vantacorehq/gridlock and vantacorehq/folio.

## License

MIT
