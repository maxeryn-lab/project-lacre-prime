//! lacre-server with a third-party HMAC-SHA3-256 in the registry.
//! Same environment-variable configuration as `lacre-server --serve`.

use std::sync::Arc;

use lacre_domain::seal_policy::SealRegistry;
use lacre_seals::{all, signatures};

#[tokio::main]
async fn main() {
    let addr = std::env::var("LACRE_HTTP_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let mut algorithms = all();
    algorithms.push(Arc::new(hmac_sha3_256_seal::HmacSha3_256));
    let registry = SealRegistry::new(algorithms)
        .and_then(|r| r.with_signatures(signatures()))
        .expect("ids are unique");
    let (state, log) = match lacre_server::compose::compose(
        lacre_adapter_http::build_default_state(),
        registry,
        &|k| std::env::var(k).ok(),
        &|p| std::fs::read_to_string(p).map_err(|e| e.to_string()),
    ) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("invalid configuration: {e}");
            std::process::exit(1);
        }
    };
    for l in &log {
        println!("{l}");
    }
    let router = lacre_adapter_http::build_router_with_state(state);
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind");
    println!("node-with-hmac-sha3-256 listening on http://{addr}");
    axum::serve(listener, router).await.expect("serve");
}
