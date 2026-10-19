//! Regression test for the verifier memory growth found during verification:
//! `VerifierCore` used to keep one lifecycle entry per verified fragment for
//! the life of the session (+74 MB after 2 million fragments of 64 B).
//! Linux only (reads /proc/self/status); elsewhere it returns without checking.

use lacre_core::core::{SealerCore, VerifierCore};
use lacre_core::hmac_seal::HmacAlgo;
use lacre_core::session::MasterKeyRing;
use std::sync::Arc;
use std::time::Duration;

fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[test]
fn verifier_memory_stays_flat_over_many_fragments() {
    let Some(_) = rss_kb() else { return };
    let ring = Arc::new(MasterKeyRing::new(
        0,
        b"bounded-memory-master-key-32-bytes".to_vec(),
        Duration::from_secs(60),
    ));
    let mut sealer = SealerCore::open(ring.clone(), HmacAlgo::Blake3, 64, 4, Duration::from_secs(60));
    let mut verifier =
        VerifierCore::resume(ring, sealer.session_id(), 0, HmacAlgo::Blake3, 64, 4, Duration::from_secs(60))
            .expect("key id 0 is active");
    let run = |n: u32, sealer: &mut SealerCore, verifier: &mut VerifierCore| {
        for _ in 0..n {
            let (frame, seal) = sealer.seal_chunk(vec![7u8; 64], false).unwrap();
            sealer.ack(frame.index).unwrap();
            verifier.verify_frame(&frame, 0, &seal, None).unwrap();
        }
    };
    run(20_000, &mut sealer, &mut verifier); // warm-up: allocator and buffers settle
    let before = rss_kb().unwrap();
    run(300_000, &mut sealer, &mut verifier);
    let grew = rss_kb().unwrap().saturating_sub(before);
    // The old behavior grew by roughly 13 MB or more over these 300 thousand fragments.
    assert!(grew < 3_000, "RSS grew {grew} kB over 300000 verified fragments");
}
