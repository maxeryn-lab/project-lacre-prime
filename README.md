# Lacre Prime

**A Transit Integrity Protocol: it shows that a response reached its consumer byte for byte as the source produced it.**

Lacre fragments a response, seals each fragment with an authentication tag carried only in the transport header, and purges the state tied to each fragment once delivery is confirmed. It does not inspect the content and does not say whether the content is true, only whether it is intact. It is general purpose: API responses, AI model output, tool results, or any stream that crosses infrastructure you do not fully control.

🇪🇸 [Leer en español](README.es.md)

## Why

TLS protects the pipe, not the water. It shows the channel was not altered and that the server is who it says it is. It says nothing about whether a response was changed after it was generated, by a compromised proxy, a faulty serialization step, or someone with access downstream of TLS termination. Heavy verification (zero-knowledge proofs, multi-node consensus) closes that gap at a cost of seconds to minutes. Lacre sits between "no extra verification" and that.

## Architecture

Four layers with a boundary enforced by crate dependencies, not by convention:

```
Adapters   lacre-adapter-declarative / -http / -ws, composed by lacre-server
App layer  lacre-domain    wire types, operations, session stores, policy
Profiles   lacre-profiles  work on frames the Core has already verified
Core       lacre-core      fragments, seals, verifies, purges; names no algorithm
```

Algorithms are not in the Core. They live in `lacre-seals` (the catalogue), and a node is composed from the ones its operator builds in and allows by policy. `lacre-seal-conformance` is the suite any algorithm must pass.

## What is here

- **Wire v1** (frozen) and **wire v2** (additive): the contract is in [`Code/workspace/spec/`](Code/workspace/spec/). v2 adds suite descriptors, an operator policy file, and signatures as their own contract.
- **Seal algorithms** in the catalogue: `hmac-sha256`, `hmac-sha512`, `hmac-sha3-512`, `blake2b-keyed`, `blake3-keyed-xof`, `aes-cmac`, and `kmac256` (marked Experimental). `hmac-sha1` exists only behind the `legacy-seals` Cargo feature and is blocked by default policy.
- **Signature scheme**: `ed25519`, for the `vault` profile under wire v2.
- **Third-party example**: [`Code/third-party/`](Code/third-party/) adds `hmac-sha3-256` from a separate Cargo workspace, without changing a byte of `lacre-core` (checked by a file hash).
- **Server**: HTTP (`/v1/handshake`, `/v1/seal`, `/v1/verify`, `/v1/ack`, `/v1/receipts`, `/v1/validate`, `/v1/seal-algorithms`, `/v1/profiles`, `/v1/toolchain/...`) and WebSocket (`/v1/ws`).
- **Behind real intermediaries**: `Tools/intermediaries.py` runs the external suite (381 cases) through nginx, haproxy and mitmproxy (and chains of them): 14 of 15 scenarios pass every case; the one left is the deliberate compatibility mode in which the proxy strips `Authorization` and the token travels in the header (the reference form puts the token in the body, and that scenario passes). A tampering intermediary is detected every time. Lacre also tolerates the usual friction: a large payload can be sealed in small parts (`/v1/seal/open`, `/v1/seal/part`; 20 MiB went through nginx with its default 1 MB body limit), a repeated `/v1/verify` returns the same verdict, WebSocket pings keep idle connections open (`LACRE_WS_PING_SECS`), and errors are `application/problem+json` on request. Details and measurements: [`LACRE-WIRE-v2.md` §11–12](Code/workspace/spec/LACRE-WIRE-v2.md).
- **Verification tools** in [`Tools/`](Tools/): an external black-box suite, mutation harnesses that check the tests fail when the code is broken, and generators that write the known-answer vectors from independent implementations (Python is used only here; the protocol itself is Rust).

## Build and test

Requires Rust 1.91+. No external services.

```bash
git clone https://github.com/maxeryn-lab/project-lacre-prime.git
cd project-lacre-prime/Code/workspace
cargo test --workspace
```

At the time of this update, `cargo test --workspace` runs 522 tests and all pass. The Core has no dependency on `tokio` or any async runtime: `cd lacre-core && cargo tree -i tokio` finds no such package.

## Run a node

```bash
cd Code/workspace
LACRE_SEAL_POLICY=preset:standard cargo run -p lacre-server -- --serve
```

Without `LACRE_SEAL_POLICY` the node speaks only wire v1; there are no silent defaults for v2. For anything beyond a local trial, set `LACRE_MASTER_KEY` and `LACRE_VAULT_SIGNING_KEY`; otherwise the node generates random keys and warns at startup. Other settings are environment variables prefixed `LACRE_` (listen address, session limits, request deadline, request body limit `LACRE_MAX_BODY_BYTES` with a 2 MiB default, WebSocket ping `LACRE_WS_PING_SECS` with a 25 s default, signing key for `vault`).

To run the external suite against a freshly built server, from `Code/workspace`: `python3 ../../Tools/external_suite.py --spawn target/debug/lacre-server`.

## Not done

- No gRPC adapter.
- Receipts and completed-session markers live in memory with a time limit. A permanent audit trail needs storage chosen by whoever deploys it.
- `kmac256` has been checked against NIST SP 800-185 sample 4 only.
- No third-party deployment or independent audit yet.

## Design principles

- **The Core never inspects content.** Neutrality is a design decision.
- **Purge is a security guarantee, not memory housekeeping.**
- **Fail closed.** A bad seal, a missing signature or an unknown version discards the fragment or the session.
- **Detectability, not prevention.** Lacre does not claim tampering is impossible, only that it is detected.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See [`LICENSE`](LICENSE).

## Contributing

Issues and pull requests are welcome. For anything beyond a small fix, please open an issue first.
