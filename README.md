# Lacre Prime

**A transit-integrity protocol for API and AI model responses consumed by autonomous agents.**

Lacre certifies that a fragmented response reaches its consumer without alteration — byte for byte identical to what the source produced — with sub-millisecond latency and without needing to inspect the content it carries. It does not certify that the content is truthful, only that it is intact.

🇪🇸 [Leer en español](README.es.md)

## Why

TLS protects the pipe, not the water. HTTPS guarantees a channel wasn't tampered with in transit and that the server is who it claims to be — it says nothing about whether the response itself was altered after being generated, by a compromised proxy, a corrupted serialization step, or an attacker with access to infrastructure downstream of TLS termination. For an autonomous agent making a real-time decision based on an API or model response, that gap matters.

Heavy verification (zero-knowledge proofs, multi-node consensus) closes that gap but costs seconds to minutes — incompatible with an agent deciding in real time. Lacre occupies the space between "no extra verification" and "heavy verification": fragment the response into small units, seal each fragment with a message authentication code carried exclusively in the transport header, and purge the state tied to each fragment immediately after delivery is confirmed.

## Architecture

Three layers with a strict boundary, enforced structurally — not by convention:

```
Adapters   (lacre-server)   — knows HTTP/WebSocket/tokio, translates a concrete transport
Profiles   (lacre-core)     — operates on frames ALREADY verified by the Core
Core       (lacre-core)     — invariant: fragments, seals/verifies, purges
```

`lacre-core` and `lacre-server` are separate crates in a Cargo workspace. The Core has no dependency on `tokio`, `axum`, or any async runtime — verifiable directly:

```bash
cd lacre-core && cargo tree -i tokio
# package ID specification `tokio` did not match any packages
```

## What's implemented

Verified with `cargo test --workspace` — not asserted from memory.

### Core (`lacre-core`)

- Payload fragmentation, HMAC seal (SHA-256 / Blake3) chained across fragment sequence
- Immutable frame type with separate state machines for sealer and verifier roles
- Circular pre-allocated buffer with ACK-based purge and forced timeout purge
- Optional Ed25519 signature over the seal (non-repudiation, Vault profile)
- Append-only post-purge receipt log (`SHA-256(seal)`, never recoverable to content)
- Session key derivation via HKDF, with ephemeral X25519 key exchange

### Adapters (`lacre-server`)

- **HTTP**: `/v1/health`, `/v1/handshake`, `/v1/seal`, `/v1/verify`, `/v1/ack`, `/v1/receipts/{session_id}`
- **WebSocket**: `/v1/ws` — same operations (`handshake`, `seal`, `verify`, `ack`) over a persistent connection, confirming the Core stays agnostic to which transport carries it
- Deployment profiles: **Core** (general-purpose), **Vault** (financial-grade, Ed25519 + receipts), **Lite** (lightweight checksum via Blake3, no full HMAC)

### What's not implemented yet

- gRPC adapter (dependency present in `Cargo.toml`, not wired up)
- Additional deployment profiles beyond Core / Vault / Lite

## Building

```bash
git clone https://github.com/<your-username>/lacre-prime.git
cd lacre-prime
cargo test --workspace
```

Requires Rust 1.91+ (edition 2021). No external services needed to run the test suite.

## Project structure

```
lacre-core/            The Core. No tokio. No HTTP. No knowledge of "profiles".
  src/
    core.rs             SealerCore / VerifierCore — fragmentation, sealing, purging
    frame.rs             Immutable frame + per-role state machines
    hmac_seal.rs          HMAC-SHA256 / Blake3 sealing, constant-time comparison
    buffer.rs             Pre-allocated circular buffer, purge logic
    session.rs             X25519 + HKDF session key derivation
    vault_signature.rs      Ed25519 signing (Vault profile)
    receipt.rs               Append-only post-purge receipt log
    profile.rs                 Frame reassembly (the only content-inspecting Profile so far)

lacre-server/           The Adapter layer. Depends on tokio/axum. Consumes lacre-core.
  src/
    http_server.rs        HTTP routes
    websocket_adapter.rs    WebSocket protocol handling
    profile_config.rs        Deployment profile presets (Core / Vault / Lite)
```

## Hackathon submission

The current public reference deployment wraps the free Open-Meteo API as a Telegraph Protocol Miner (`weather_forecast` / `weather_check` intents) on Base Sepolia, sealing every response fragment with the mechanism described above. That integration layer is not part of this repository — this repository is the protocol implementation itself, transport- and use-case-agnostic.

## Design principles

- **The Core never inspects content.** Neutrality is a design decision, not a technical limitation — enforced by keeping content-inspecting logic entirely in a separate layer (Profiles), never in the Core.
- **Purge is a security guarantee, not memory housekeeping.** Deleting a fragment's state after delivery confirmation is treated with the same priority as computing the seal itself.
- **Fail closed, always.** Any verification failure — a bad seal, a missing signature, an unrecognized protocol version — discards the fragment or session. No partial acceptance, no silent degradation.
- **Detectability, not prevention.** Lacre does not claim tampering is impossible. It claims that if it happens, it is detected immediately and with mathematical certainty — the same property a wax seal on a museum crate has always had.

## License

Licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See [`LICENSE`](LICENSE).

A commercial license for use cases incompatible with AGPL-3.0's network-copyleft terms may be made available in the future; contact the maintainer for inquiries.

## Contributing

This project is under active development. Issues and pull requests are welcome — please open an issue first for anything beyond a small fix, so we can align on direction before you put work into it.
