
use lacre_server::compose;

use lacre_core::buffer::PendingBuffer;
use lacre_core::hmac_seal::{seal_fragment, verify_fragment, HmacAlgo};
use lacre_core::session::{MasterKeyRing, SessionId};
use std::time::Duration;

/// Reads the process's own VmRSS from /proc/self/status (Linux). This
/// is a real resident-memory measurement, not the logical accounting
/// `PendingBuffer` keeps internally — confirms that "the buffer says
/// it uses X" and "the process actually uses X" don't diverge
/// noticeably.
fn read_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.trim().trim_end_matches(" kB").trim().parse().ok();
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--serve") {
        run_server().await;
        return;
    }
    run_smoke_test();
}

/// Starts the real HTTP Adapter on a TCP port, built with
/// `lacre_adapter_http::build_default_state` + `build_router_with_state`.
/// `LACRE_HTTP_ADDR` allows choosing the bind address (for example,
/// for local testing on a non-privileged port); defaults to listening
/// on `127.0.0.1:3000`.
async fn run_server() {
    let addr = std::env::var("LACRE_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let state = lacre_adapter_http::build_default_state();
    let (state, startup_log) = match compose::compose(
        state,
        compose::build_registry(),
        &|k| std::env::var(k).ok(),
        &|p| std::fs::read_to_string(p).map_err(|e| e.to_string()),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid configuration: {e}");
            std::process::exit(1);
        }
    };
    for line in &startup_log {
        println!("{line}");
    }

    // Periodic sweep of every session store's idle/expired entries.
    // Closes a real gap found while wiring up the Toolchain HTTP
    // routes: `SealerSessionStore::purge_expired`,
    // `SessionStore::purge_expired`, and
    // `ToolchainSessionStore::purge_expired`/`remove` were all
    // implemented (each store already documents, in its own header
    // comment, that purging is invoked explicitly rather than on
    // every operation, to avoid penalizing the hot path) but nothing
    // in `main.rs` ever actually called them — the same shape of gap,
    // three times, until now. A background task on a fixed interval,
    // not tied to request volume, is the same pattern
    // `PendingBuffer::purge_expired` already documents as the
    // intended caller-driven invocation style, just applied at the
    // process level instead of per-request.
    {
        let sweep_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                sweep_state.purge_all_expired();
            }
        });
    }

    let router = lacre_adapter_http::build_router_with_state(state);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not open {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!("lacre-server listening on http://{addr}  (profiles: lite, core, vault)");
    println!("  GET  /v1/health");
    println!("  POST /v1/handshake  {{\"client_public_key_hex\":\"...\"}}");
    println!("  POST /v1/seal    {{\"profile\":\"lite\"|\"core\"|\"vault\",\"payload_hex\":\"...\",\"session_id\":\"optional\"}}");
    println!("  POST /v1/verify  {{\"profile\":\"lite\"|\"core\"|\"vault\",\"session_id\":\"...\",\"key_id\":0,\"frames\":[...]}}");
    println!("  POST /v1/toolchain/episodes  {{\"episode_id_hex\":\"...\",\"algo\":\"sha256\"|\"blake3\",\"max_node_age_ms\":3600000}}");
    println!("  POST /v1/toolchain/episodes/{{session_id}}/nodes   {{\"node_id\":\"...\",\"content_hex\":\"...\",\"parent_ids\":[]}}");
    println!("  POST /v1/toolchain/episodes/{{session_id}}/verify  {{\"output_node_id\":\"...\",\"contents_hex\":{{...}}}}");

    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

fn run_smoke_test() {
    // Manual smoke test: seal and verify a fragment end to end.
    let ring = MasterKeyRing::new(0, b"test-master-key-generated-by-csprng".to_vec(), Duration::from_secs(300));
    let session_id = SessionId::generate();
    let key = ring.derive_for_sealing(&session_id);

    let fragment = b"example response fragment";
    let session_state = b"session-state-step-0";

    let seal = seal_fragment(HmacAlgo::Sha256, &key, fragment, session_state);
    let ok = verify_fragment(HmacAlgo::Sha256, &key, fragment, session_state, &seal);

    println!("Lacre Core — smoke test");
    println!("  active key_id: {}", ring.active_key_id());
    println!("  seal generated and verified: {}", ok);

    // Block IV test 3: seal+verify latency per fragment, measured (not
    // just declared). A real figure from this machine, not a design
    // target — serves as an order-of-magnitude reference, not a formal
    // benchmark (that would need criterion and environment noise
    // control).
    let n = 100_000;
    let fragment = vec![0x42u8; 1024]; // 1 KB, typical Core profile size
    let state = b"benchmark-session-state";

    let start = std::time::Instant::now();
    for _ in 0..n {
        let s = seal_fragment(HmacAlgo::Sha256, &key, &fragment, state);
        std::hint::black_box(verify_fragment(HmacAlgo::Sha256, &key, &fragment, state, &s));
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / n;
    println!(
        "  average seal+verify latency (SHA-256, 1KB, n={}): {:?}",
        n, per_op
    );

    let start = std::time::Instant::now();
    for _ in 0..n {
        let s = seal_fragment(HmacAlgo::Blake3, &key, &fragment, state);
        std::hint::black_box(verify_fragment(HmacAlgo::Blake3, &key, &fragment, state, &s));
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / n;
    println!(
        "  average seal+verify latency (Blake3, 1KB, n={}): {:?}",
        n, per_op
    );

    // 15 MB ceiling (Core profile, expanded from the original 10 MB for
    // better tolerance): fill the buffer and measure the process's real
    // RSS before and after, not just the buffer's internal accounting.
    // 1 KB slots (typical Core size, Block III).
    const SLOT_SIZE: usize = 1024;
    const FIFTEEN_MB: usize = 15 * 1024 * 1024;
    let slot_count = FIFTEEN_MB / SLOT_SIZE;
    let rss_before = read_rss_kb();

    let mut pending = PendingBuffer::new(SLOT_SIZE, slot_count, Duration::from_millis(500));
    let mut idx = 0u64;
    while pending.insert(idx, &[0x42u8; SLOT_SIZE], seal).is_ok() {
        idx += 1;
    }
    let rss_after = read_rss_kb();

    println!(
        "  buffer: {} 1KB fragments inserted, used_bytes={} (ceiling={})",
        idx,
        pending.used_bytes(),
        FIFTEEN_MB
    );
    match (rss_before, rss_after) {
        (Some(before), Some(after)) => println!(
            "  process RSS: {} kB -> {} kB (delta: {} kB)",
            before,
            after,
            after.saturating_sub(before)
        ),
        _ => println!("  process RSS: not available on this platform"),
    }

    // Full purge and confirmation that memory is released.
    for i in 0..idx {
        pending.purge_on_ack(i);
    }
    println!(
        "  after purging everything: used_bytes={}, pending={}",
        pending.used_bytes(),
        pending.pending_count()
    );
}
