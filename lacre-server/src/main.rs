mod domain;
mod http_adapter;
mod http_server;
mod profile_config;
mod sealer_session_store;
mod session_store;
mod websocket_adapter;

use lacre_core::buffer::PendingBuffer;
use lacre_core::hmac_seal::{seal_fragment, verify_fragment, HmacAlgo};
use lacre_core::session::{MasterKeyRing, SessionId};
use std::time::Duration;

/// Lee VmRSS del propio proceso desde /proc/self/status (Linux). Es una
/// medición real de memoria residente, no la contabilidad lógica que
/// lleva PendingBuffer internamente — confirma que "el buffer dice que
/// usa X" y "el proceso realmente usa X" no divergen de forma notoria.
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

/// Levanta el Adaptador HTTP real (`http_server::build_router`) sobre
/// un puerto TCP. `LACRE_HTTP_ADDR` permite elegir la dirección de
/// bind (por ejemplo, para pruebas locales en un puerto no
/// privilegiado); por defecto escucha en `127.0.0.1:3000`.
///
/// Nota de alcance: reemplaza el stub anterior, que informaba que esta
/// reescritura estaba pendiente. Cubre el perfil Core solamente — ver
/// comentario de cabecera de `http_server.rs` para el porqué de dejar
/// Vault fuera de esta primera vuelta.
async fn run_server() {
    let addr = std::env::var("LACRE_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let router = http_server::build_router();

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("no se pudo abrir {addr}: {e}");
            std::process::exit(1);
        }
    };
    println!("lacre-server escuchando en http://{addr}  (perfiles: lite, core, vault)");
    println!("  GET  /v1/health");
    println!("  POST /v1/handshake  {{\"client_public_key_hex\":\"...\"}}");
    println!("  POST /v1/seal    {{\"profile\":\"lite\"|\"core\"|\"vault\",\"payload_hex\":\"...\",\"session_id\":\"opcional\"}}");
    println!("  POST /v1/verify  {{\"profile\":\"lite\"|\"core\"|\"vault\",\"session_id\":\"...\",\"key_id\":0,\"frames\":[...]}}");

    if let Err(e) = axum::serve(listener, router).await {
        eprintln!("error del servidor: {e}");
        std::process::exit(1);
    }
}

fn run_smoke_test() {
    // Smoke test manual: sellar y verificar un fragmento de punta a punta.
    // El motor real (engine.rs) reemplazará esto; por ahora confirma que
    // session.rs y hmac_seal.rs interoperan correctamente.
    let ring = MasterKeyRing::new(0, b"clave-maestra-generada-por-csprng-32b".to_vec(), Duration::from_secs(300));
    let session_id = SessionId::generate();
    let key = ring.derive_for_sealing(&session_id);

    let fragment = b"fragmento de respuesta de ejemplo";
    let session_state = b"estado-sesion-paso-0";

    let seal = seal_fragment(HmacAlgo::Sha256, &key, fragment, session_state);
    let ok = verify_fragment(HmacAlgo::Sha256, &key, fragment, session_state, &seal);

    println!("Lacre Core — smoke test");
    println!("  key_id activo: {}", ring.active_key_id());
    println!("  sello generado y verificado: {}", ok);

    // Prueba 3 del Bloque IV: latencia de sellado+verificación por
    // fragmento, medida (no declarada). Cifra real de esta máquina, no un
    // objetivo de diseño — sirve como referencia de orden de magnitud, no
    // como benchmark formal (para eso hace falta criterion y control de
    // ruido del entorno).
    let n = 100_000;
    let fragment = vec![0x42u8; 1024]; // 1 KB, tamaño típico perfil Core
    let state = b"estado-sesion-benchmark";

    let start = std::time::Instant::now();
    for _ in 0..n {
        let s = seal_fragment(HmacAlgo::Sha256, &key, &fragment, state);
        std::hint::black_box(verify_fragment(HmacAlgo::Sha256, &key, &fragment, state, &s));
    }
    let elapsed = start.elapsed();
    let per_op = elapsed / n;
    println!(
        "  latencia media sellado+verificación (SHA-256, 1KB, n={}): {:?}",
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
        "  latencia media sellado+verificación (Blake3, 1KB, n={}): {:?}",
        n, per_op
    );

    // Techo de 15 MB (perfil Core, ampliado desde 10 MB original para
    // dar mejor tolerancia): llenar el buffer y medir RSS real del
    // proceso antes y después, no solo la contabilidad interna del buffer.
    // Slots de 1 KB (tamaño típico Core, Bloque III).
    const SLOT_SIZE: usize = 1024;
    const FIFTEEN_MB: usize = 15 * 1024 * 1024;
    let slot_count = FIFTEEN_MB / SLOT_SIZE;
    let rss_before = read_rss_kb();

    let mut pending = PendingBuffer::new(SLOT_SIZE, slot_count, Duration::from_millis(500));
    let mut idx = 0u64;
    loop {
        match pending.insert(idx, &[0x42u8; SLOT_SIZE], seal) {
            Ok(()) => idx += 1,
            Err(_) => break,
        }
    }
    let rss_after = read_rss_kb();

    println!(
        "  buffer: {} fragmentos de 1KB insertados, used_bytes={} (techo={})",
        idx,
        pending.used_bytes(),
        FIFTEEN_MB
    );
    match (rss_before, rss_after) {
        (Some(before), Some(after)) => println!(
            "  RSS del proceso: {} kB -> {} kB (delta: {} kB)",
            before,
            after,
            after.saturating_sub(before)
        ),
        _ => println!("  RSS del proceso: no disponible en esta plataforma"),
    }

    // Purga total y confirmación de que la memoria se libera.
    for i in 0..idx {
        pending.purge_on_ack(i);
    }
    println!(
        "  tras purgar todo: used_bytes={}, pendientes={}",
        pending.used_bytes(),
        pending.pending_count()
    );
}
