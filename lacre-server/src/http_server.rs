//! El Adaptador HTTP real — único módulo de `lacre-server` que conoce
//! `axum` directamente. Ver DECISIONS.md punto 16 y
//! ARCHITECTURE_NOTES.md para el porqué de la separación respecto de
//! `http_adapter.rs` (agnóstico de axum).
//!
//! # Alcance de esta implementación
//!
//! Perfiles Core y Vault. Vault cubre la firma Ed25519 (no repudio,
//! 9.5/15.3) de forma completa: `handle_seal` firma cada sello con
//! `VaultSigningKey` cuando el perfil lo requiere y `handle_verify`
//! exige y verifica esa firma. El `ReceiptLog` (recibo post-purga, 7.5)
//! queda deliberadamente FUERA de esta entrega — requiere que `ack()`
//! sea un evento explícito del protocolo (`POST /v1/ack` o
//! equivalente), no algo que se dispare de forma implícita porque un
//! `POST /v1/seal` respondió 200. Un HTTP 200 certifica que el
//! servidor entregó la respuesta, no que el cliente la recibió ni la
//! procesó — automatizar el `ack()` a partir de eso convertiría una
//! garantía de seguridad activa (A3) en housekeeping disfrazado. Ver
//! PENDING.md para el seguimiento de este punto como siguiente paso
//! inmediato, no descartado.
//!
//! # Por qué no hay sesiones vivas del lado servidor entre requests
//!
//! `VerifierCore::resume` construye el estado de verificación desde
//! cero (`next_index: 0`) de forma determinista a partir de
//! `(key_ring, session_id, key_id)` — no hay ningún estado oculto que
//! sobreviva entre llamadas a `resume`. Por eso, en esta primera
//! implementación, `POST /v1/verify` recibe la secuencia COMPLETA de
//! frames de una sesión y los verifica todos dentro de un único
//! `VerifierCore` construido y descartado en el mismo request —
//! coherente con que `POST /v1/seal` también produce la secuencia
//! completa de una sola vez (`SealerCore::seal_payload`). Esto evita
//! necesitar un `Mutex<HashMap<SessionId, VerifierCore>>` de sesiones
//! vivas de servidor, cuya justificación (verificación fragmento a
//! fragmento entre requests HTTP separados) pertenece más bien a la
//! variante de streaming que PENDING.md deja anotada como candidata
//! futura, no a esta primera vuelta. La misma limitación aplica al
//! `SealerCore` de una sesión Vault: no persiste entre requests, así
//! que el `ReceiptLog` que ese `SealerCore` acumularía tampoco puede
//! sobrevivir más allá del propio `POST /v1/seal` — otra razón por la
//! que el recibo post-purga necesita su propio diseño de estado, no
//! uno improvisado dentro de este mismo request.
//!
//! # Clave maestra del servidor
//!
//! Se lee UNA VEZ al arrancar, de la variable de entorno
//! `LACRE_MASTER_KEY` (bytes en hex). Si la variable no está seteada,
//! se usa una clave de desarrollo fija con una advertencia explícita en
//! stderr, NUNCA en silencio (coherente con A4/A8: ausencia de
//! configuración explícita no debe degradar silenciosamente a "modo
//! inseguro sin que nadie se entere").
//!
//! # Clave de firma Vault del servidor
//!
//! Mismo patrón: `LACRE_VAULT_SIGNING_KEY` (hex, 32 bytes) leída UNA
//! VEZ al arrancar, o una clave de desarrollo fija con advertencia
//! explícita si falta. Se usa `VaultSigningKey::from_bytes`/`to_bytes`
//! (agregados a `lacre-core` en esta misma etapa — ver
//! CHANGELOG.md) precisamente porque una clave que cambiara en cada
//! reinicio del proceso rompería el no-repudio a largo plazo que 15.3
//! describe: un verificador externo que ya conoce la clave pública de
//! una sesión anterior debe poder seguir verificando firmas hechas
//! antes de un reinicio del servidor.

use crate::http_adapter::{
    AckRequest, AckResponse, HandshakeRequest, HandshakeResponse, ReceiptsResponse, SealRequest,
    SealResponse, VerifyRequest, VerifyResponse,
};
use crate::session_store::{InMemorySessionStore, SessionStore};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use lacre_core::session::MasterKeyRing;
use lacre_core::vault_signature::{VaultSigningKey, VaultVerifyingKey};
use std::sync::Arc;
use std::time::Duration;

/// Estado compartido entre requests.
///
/// `key_ring` es el ring fijo cargado al arrancar (de
/// `LACRE_MASTER_KEY` o la clave de desarrollo) — el camino que ya
/// existía antes de este endpoint, sin cambios de comportamiento.
///
/// `handshake_sessions` es el `SessionStore` (ver session_store.rs)
/// donde viven los rings derivados de un handshake X25519 completado
/// por `POST /v1/handshake`, indexados por el `session_id` que el
/// propio handshake acuerda. Deliberadamente un tipo separado del
/// `key_ring` fijo: son dos orígenes de clave distintos (estática de
/// despliegue vs. efímera por sesión, 8.4) que conviene no mezclar en
/// una sola estructura de datos.
///
/// `Arc<dyn SessionStore>` (no un tipo concreto) es la costura que
/// permite sustituir `InMemorySessionStore` por un backend distribuido
/// el día que exista, sin tocar los handlers.
///
/// `vault_signing_key`/`vault_verifying_key`: la clave de firma
/// Ed25519 del servidor (15.3). Un único par de claves para todo el
/// servidor, no por sesión — coherente con que 15.3 describe el
/// no-repudio como una propiedad del *sellador* (el servidor,
/// firmando en nombre de sí mismo), no de la sesión en particular. Se
/// guardan por separado (aunque `vault_verifying_key` se puede derivar
/// de `vault_signing_key`) para no tener que volver a derivarla en
/// cada request de `/v1/verify` — el costo es insignificante, pero la
/// razón real es que ya así era el patrón para `key_ring`.
#[derive(Clone)]
pub struct AppState {
    key_ring: Arc<MasterKeyRing>,
    handshake_sessions: Arc<dyn SessionStore>,
    vault_signing_key: Arc<VaultSigningKey>,
    vault_verifying_key: VaultVerifyingKey,
    /// `SealerCore` vivos de sesiones Vault, entre `POST /v1/seal` y
    /// `POST /v1/ack` — ver sealer_session_store.rs. `Arc` directo
    /// sobre el tipo concreto (no `Arc<dyn Trait>` como
    /// `handshake_sessions`): un único uso real hoy no justifica una
    /// interfaz, ver comentario de cabecera de ese módulo.
    sealer_sessions: Arc<crate::sealer_session_store::SealerSessionStore>,
}

impl AppState {
    /// Constructor de `AppState` disponible solo en tests, para
    /// módulos DISTINTOS de `http_server` (por ejemplo,
    /// `websocket_adapter::tests`) que necesitan construir un estado de
    /// prueba sin acceso a los campos privados de esta struct — mismo
    /// principio de encapsulamiento que ya motivó los getters de abajo.
    #[cfg(test)]
    pub(crate) fn new_for_test(
        key_ring: Arc<MasterKeyRing>,
        handshake_sessions: Arc<dyn SessionStore>,
        vault_signing_key: VaultSigningKey,
        sealer_sessions: Arc<crate::sealer_session_store::SealerSessionStore>,
    ) -> Self {
        let vault_verifying_key = vault_signing_key.verifying_key();
        AppState {
            key_ring,
            handshake_sessions,
            vault_signing_key: Arc::new(vault_signing_key),
            vault_verifying_key,
            sealer_sessions,
        }
    }

    /// Getters usados por `domain.rs` (Etapa 20) — deliberadamente NO
    /// se hicieron `pub` los campos directamente: cualquier Adaptador
    /// nuevo (o `domain.rs`) accede al estado a través de estos
    /// métodos, nunca mutando la estructura interna de `AppState` por
    /// fuera de lo que los propios stores (`SessionStore`,
    /// `SealerSessionStore`) ya exponen.
    pub(crate) fn key_ring(&self) -> &Arc<MasterKeyRing> {
        &self.key_ring
    }

    pub(crate) fn handshake_sessions(&self) -> &Arc<dyn SessionStore> {
        &self.handshake_sessions
    }

    pub(crate) fn sealer_sessions(&self) -> &Arc<crate::sealer_session_store::SealerSessionStore> {
        &self.sealer_sessions
    }

    pub(crate) fn vault_verifying_key(&self) -> VaultVerifyingKey {
        self.vault_verifying_key
    }

    /// Devuelve los bytes crudos de la clave de firma del servidor —
    /// `VaultSigningKey` no implementa `Clone` (ver
    /// vault_signature.rs), así que cada llamador que necesite su
    /// propia instancia (por ejemplo, `SealerCore::open_with_vault_key`,
    /// que consume la clave por valor) la reconstruye a partir de estos
    /// bytes con `VaultSigningKey::from_bytes`.
    pub(crate) fn vault_signing_key_bytes(&self) -> [u8; 32] {
        self.vault_signing_key.to_bytes()
    }
}

/// Lee `LACRE_MASTER_KEY` (hex) del entorno, o usa una clave de
/// desarrollo fija con advertencia explícita en stderr si no está
/// seteada. Nunca fallamos en silencio: si alguien corre esto en un
/// entorno real sin configurar la variable, lo sabe por el mensaje, no
/// lo descubre después de una brecha.
fn load_master_key_ring() -> Arc<MasterKeyRing> {
    let ikm = match std::env::var("LACRE_MASTER_KEY") {
        Ok(hex_str) => match hex::decode(hex_str.trim()) {
            Ok(bytes) if bytes.len() >= 16 => bytes,
            Ok(_) => {
                eprintln!(
                    "ADVERTENCIA: LACRE_MASTER_KEY decodifica a menos de 16 bytes; \
                     usando clave de desarrollo fija en su lugar."
                );
                b"clave-de-desarrollo-lacre-32bytes".to_vec()
            }
            Err(_) => {
                eprintln!(
                    "ADVERTENCIA: LACRE_MASTER_KEY no es hex válido; \
                     usando clave de desarrollo fija en su lugar."
                );
                b"clave-de-desarrollo-lacre-32bytes".to_vec()
            }
        },
        Err(_) => {
            eprintln!(
                "ADVERTENCIA: LACRE_MASTER_KEY no está configurada. \
                 Usando una clave de desarrollo FIJA y conocida — \
                 no apto para ningún despliegue real. \
                 Configurar LACRE_MASTER_KEY (hex, ≥16 bytes) antes de exponer este servidor."
            );
            b"clave-de-desarrollo-lacre-32bytes".to_vec()
        }
    };

    Arc::new(MasterKeyRing::new(0, ikm, Duration::from_secs(3600)))
}

/// Lee `LACRE_VAULT_SIGNING_KEY` (hex, 32 bytes) del entorno, o usa una
/// clave de desarrollo fija con advertencia explícita en stderr si
/// falta o es inválida — mismo criterio que `load_master_key_ring`.
/// Usa `VaultSigningKey::from_bytes`/`to_bytes` (agregados a
/// `lacre-core` en esta misma etapa) para poder reconstruir una clave
/// persistente entre reinicios, en vez de `VaultSigningKey::generate()`
/// (que produciría una clave nueva cada vez que arranca el proceso,
/// rompiendo el no-repudio a largo plazo — ver comentario de cabecera
/// del módulo).
fn load_vault_signing_key() -> VaultSigningKey {
    // Clave de desarrollo fija: 32 bytes deterministas, NO generados al
    // azar, para que dos arranques del servidor sin la variable
    // configurada produzcan la MISMA clave — coherente con el
    // propósito de esta función (persistencia entre reinicios), aunque
    // sea con una clave conocida y por tanto insegura para un
    // despliegue real. Si acá se llamara a `generate()` en su lugar, el
    // "modo de desarrollo" tendría una clave distinta cada vez, lo cual
    // ocultaría precisamente el problema que se supone que demuestra.
    const DEV_KEY_BYTES: [u8; 32] = [0x11; 32];

    match std::env::var("LACRE_VAULT_SIGNING_KEY") {
        Ok(hex_str) => match hex::decode(hex_str.trim()) {
            Ok(bytes) => match <[u8; 32]>::try_from(bytes.as_slice()) {
                Ok(arr) => VaultSigningKey::from_bytes(&arr),
                Err(_) => {
                    eprintln!(
                        "ADVERTENCIA: LACRE_VAULT_SIGNING_KEY debe decodificar a exactamente \
                         32 bytes; usando clave Vault de desarrollo fija en su lugar."
                    );
                    VaultSigningKey::from_bytes(&DEV_KEY_BYTES)
                }
            },
            Err(_) => {
                eprintln!(
                    "ADVERTENCIA: LACRE_VAULT_SIGNING_KEY no es hex válido; \
                     usando clave Vault de desarrollo fija en su lugar."
                );
                VaultSigningKey::from_bytes(&DEV_KEY_BYTES)
            }
        },
        Err(_) => {
            eprintln!(
                "ADVERTENCIA: LACRE_VAULT_SIGNING_KEY no está configurada. \
                 Usando una clave Vault de desarrollo FIJA y conocida — \
                 no apto para ningún despliegue real, y rompe el no-repudio \
                 frente a cualquier verificador que asuma que esta clave es \
                 exclusiva de este servidor. \
                 Configurar LACRE_VAULT_SIGNING_KEY (hex, 32 bytes) antes de exponer este servidor."
            );
            VaultSigningKey::from_bytes(&DEV_KEY_BYTES)
        }
    }
}

pub fn build_router() -> Router {
    let vault_signing_key = load_vault_signing_key();
    let vault_verifying_key = vault_signing_key.verifying_key();
    let state = AppState {
        key_ring: load_master_key_ring(),
        // TTL de 1 hora: una sesión de handshake que no se usó en ese
        // margen se purga — mismo orden de magnitud que el
        // retirement_window por defecto del key_ring fijo de arriba.
        // No hay ningún requisito normativo detrás de este valor
        // concreto; es un parámetro de despliegue de ESTE Adaptador
        // (ver session_store.rs), ajustable sin tocar el protocolo.
        handshake_sessions: Arc::new(InMemorySessionStore::new(Duration::from_secs(3600))),
        vault_signing_key: Arc::new(vault_signing_key),
        vault_verifying_key,
        // TTL más corto que handshake_sessions: un SealerCore de Vault
        // solo necesita sobrevivir el margen razonable entre que el
        // cliente recibe la respuesta de /v1/seal y confirma con
        // /v1/ack, no una sesión completa de larga duración. 10
        // minutos es un valor de despliegue de este Adaptador, no un
        // requisito de 7.5.
        sealer_sessions: Arc::new(crate::sealer_session_store::SealerSessionStore::new(
            Duration::from_secs(600),
        )),
    };
    build_router_with_state(state)
}

/// Separado de `build_router` para que los tests de integración puedan
/// inyectar un `AppState` con una clave maestra conocida, sin depender
/// de variables de entorno (que son globales al proceso y, por tanto,
/// una fuente de tests que se pisan entre sí si corren en paralelo).
pub fn build_router_with_state(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/ws", get(crate::websocket_adapter::handle_ws_upgrade))
        .route("/v1/handshake", post(handle_handshake))
        .route("/v1/seal", post(handle_seal))
        .route("/v1/verify", post(handle_verify))
        .route("/v1/ack", post(handle_ack))
        .route("/v1/receipts/{session_id}", get(handle_receipts))
        .with_state(state)
}
async fn health() -> &'static str {
    "ok"
}


/// Traduce un `DomainError` (crate::domain, sin ningún tipo de axum) al
/// vocabulario de error de ESTE Adaptador (`StatusCode` + mensaje).
/// Cada Adaptador tiene su propia función equivalente — ver
/// `to_ws_error_message` en `websocket_adapter.rs`.
fn domain_error_to_http(err: crate::domain::DomainError) -> (StatusCode, String) {
    use crate::domain::DomainError;
    match err {
        DomainError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        DomainError::Unprocessable(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
        DomainError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
    }
}

/// `POST /v1/handshake` — protocolo ClientInitiated (ver comentario de
/// "Handshake X25519" en http_adapter.rs). Delega en
/// `crate::domain::handshake` (Etapa 20) — este handler solo traduce
/// entre los tipos de axum y los de dominio, sin lógica propia.
async fn handle_handshake(
    State(state): State<AppState>,
    Json(req): Json<HandshakeRequest>,
) -> Result<Json<HandshakeResponse>, (StatusCode, String)> {
    crate::domain::handshake(&state, &req)
        .map(Json)
        .map_err(domain_error_to_http)
}

/// `POST /v1/seal` — fragmenta y sella `payload_hex` bajo el perfil
/// indicado. Delega en `crate::domain::seal` (Etapa 20).
async fn handle_seal(
    State(state): State<AppState>,
    Json(req): Json<SealRequest>,
) -> Result<Json<SealResponse>, (StatusCode, String)> {
    crate::domain::seal(&state, &req).map(Json).map_err(domain_error_to_http)
}

/// `POST /v1/verify` — verifica, en orden, todos los frames recibidos.
/// Delega en `crate::domain::verify` (Etapa 20).
async fn handle_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    crate::domain::verify(&state, &req).map(Json).map_err(domain_error_to_http)
}

/// `POST /v1/ack` — confirma, por lote, qué índices de fragmento el
/// cliente recibió y procesó. Delega en `crate::domain::ack` (Etapa
/// 20).
async fn handle_ack(
    State(state): State<AppState>,
    Json(req): Json<AckRequest>,
) -> Result<Json<AckResponse>, (StatusCode, String)> {
    crate::domain::ack(&state, &req).map(Json).map_err(domain_error_to_http)
}

/// `GET /v1/receipts/{session_id}` — lee los recibos post-purga (7.5)
/// acumulados hasta el momento. Delega en `crate::domain::receipts`
/// (Etapa 20).
async fn handle_receipts(
    State(state): State<AppState>,
    Path(session_id_hex): Path<String>,
) -> Result<Json<ReceiptsResponse>, (StatusCode, String)> {
    crate::domain::receipts(&state, &session_id_hex)
        .map(Json)
        .map_err(domain_error_to_http)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::core::SealerCore;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // para Router::oneshot

    fn test_state() -> AppState {
        let vault_signing_key = lacre_core::vault_signature::VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();
        AppState {
            key_ring: Arc::new(MasterKeyRing::new(
                0,
                b"clave-de-test-para-http-server-32b".to_vec(),
                std::time::Duration::from_secs(60),
            )),
            handshake_sessions: Arc::new(crate::session_store::InMemorySessionStore::new(
                std::time::Duration::from_secs(60),
            )),
            vault_signing_key: Arc::new(vault_signing_key),
            vault_verifying_key,
            sealer_sessions: Arc::new(crate::sealer_session_store::SealerSessionStore::new(
                std::time::Duration::from_secs(60),
            )),
        }
    }

    async fn post_json(router: &Router, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn get_json(router: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder().method("GET").uri(path).body(Body::empty()).unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    /// El test central de esta fase: sellar por HTTP real (a través del
    /// router de axum, no llamando funciones Rust directamente) y
    /// verificar por HTTP real, confirmando que los frames que salen de
    /// `/v1/seal` son aceptados por `/v1/verify` sin ninguna
    /// intervención manual — el mismo tipo de prueba que
    /// LESSONS_LEARNED.md ya identificó como necesaria (una integración
    /// HTTP real puede revelar bugs que un test unitario de
    /// `lacre-core` no ve).
    #[tokio::test]
    async fn seal_then_verify_round_trip_over_real_http_router() {
        let router = build_router_with_state(test_state());

        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"contenido de extremo a extremo via HTTP"),
            }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");

        let session_id = seal_body["session_id"].as_str().unwrap().to_string();
        let frames = seal_body["frames"].clone();
        assert!(frames.as_array().unwrap().len() >= 1);

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "core",
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["all_verified"], serde_json::Value::Bool(true));
    }

    /// Un frame con el sello alterado después de sellarlo por HTTP debe
    /// fallar la verificación con un error explícito, no pasar por
    /// error ni provocar un 500.
    #[tokio::test]
    async fn tampered_seal_over_http_is_rejected_not_silently_accepted() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"un mensaje cualquiera"),
            }),
        )
        .await;

        let session_id = seal_body["session_id"].as_str().unwrap().to_string();
        let mut frames = seal_body["frames"].clone();
        // Corromper el sello del primer (único) frame: cambiar el
        // primer byte de seal_hex.
        let first_seal = frames[0]["seal_hex"].as_str().unwrap().to_string();
        let corrupted = format!("{:02x}{}", (u8::from_str_radix(&first_seal[..2], 16).unwrap()) ^ 0xFF, &first_seal[2..]);
        frames[0]["seal_hex"] = serde_json::Value::String(corrupted);

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "core",
                "session_id": session_id,
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK);
        assert_eq!(verify_body["all_verified"], serde_json::Value::Bool(false));
        assert_eq!(verify_body["results"][0]["ok"], serde_json::Value::Bool(false));
    }

    /// El test central del endpoint de handshake: un "cliente" real
    /// (simulado acá con `EphemeralHandshake` directamente, del mismo
    /// modo en que lo haría cualquier implementación de cliente HTTP
    /// externa) completa el intercambio X25519 con el servidor real a
    /// través del router de axum, deriva su propio `MasterKeyRing` del
    /// secreto resultante, SELLA UN FRAGMENTO LOCALMENTE con ese ring
    /// (fuera de HTTP, como haría un cliente de verdad antes de enviar
    /// el frame ya sellado), y luego usa `POST /v1/verify` para
    /// confirmar que el servidor — que derivó el ring de forma
    /// completamente independiente, del lado servidor — llega
    /// exactamente a la misma clave de sesión.
    ///
    /// Esta es la prueba de que el handshake realmente conecta con
    /// `session.rs`/`core.rs` (Fase 1/2) de punta a punta, no solo que
    /// el endpoint HTTP responde con bytes con forma de clave pública.
    #[tokio::test]
    async fn handshake_then_client_side_seal_verifies_on_server() {
        use lacre_core::session_handshake::EphemeralHandshake;

        let router = build_router_with_state(test_state());

        // "Cliente": genera su propio par efímero, exactamente como lo
        // haría un proceso externo separado del servidor.
        let client_handshake = EphemeralHandshake::generate();
        let client_public_key = client_handshake.public_key();

        let (status, body) = post_json(
            &router,
            "/v1/handshake",
            serde_json::json!({
                "client_public_key_hex": hex::encode(client_public_key.to_bytes()),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "handshake body: {body}");

        let server_public_key_hex = body["server_public_key_hex"].as_str().unwrap();
        let session_id_hex = body["session_id"].as_str().unwrap().to_string();
        let key_id = body["key_id"].as_u64().unwrap() as u8;
        assert_eq!(key_id, 0);

        // El cliente completa su lado del DH con la clave pública que
        // el servidor acaba de devolver — sin ninguna otra
        // comunicación fuera de esta única request/response.
        let server_public_key_bytes: [u8; 32] =
            hex::decode(server_public_key_hex).unwrap().try_into().unwrap();
        let server_public_key =
            lacre_core::session_handshake::EphemeralPublicKey::from_bytes(server_public_key_bytes);
        let client_secret = client_handshake.complete(server_public_key);

        // El cliente sella UN FRAGMENTO LOCALMENTE, usando el mismo
        // SealerCore real que usaría cualquier cliente de lacre-core —
        // NO se reconstruye el estado inicial Es(0) a mano (es privado
        // de `core.rs`, HMAC(key, session_id ∥ contexto interno); un
        // test que lo reimplementara por fuera arriesgaría
        // desincronizarse en silencio si ese detalle cambia alguna vez).
        let session_id = crate::http_adapter::session_id_from_hex(&session_id_hex).unwrap();
        let client_ring = std::sync::Arc::new(lacre_core::session::MasterKeyRing::new(
            key_id,
            client_secret.into_ikm_bytes().to_vec(),
            std::time::Duration::from_secs(3600),
        ));
        let mut client_sealer = SealerCore::open_with_session_key(
            client_ring,
            session_id,
            lacre_core::hmac_seal::HmacAlgo::Sha256,
            64,
            10,
            std::time::Duration::from_millis(500),
        );
        let payload = b"sellado del lado cliente, fuera de este servidor HTTP".to_vec();
        let sealed = client_sealer.seal_payload(&payload, 64).unwrap();
        let (frame, seal) = &sealed[0];

        let frame_wire = serde_json::json!({
            "session_id": session_id_hex,
            "index": frame.index,
            "total_fragments": frame.total_fragments,
            "is_last": frame.is_last,
            "payload_hex": hex::encode(&frame.payload),
            "seal_hex": hex::encode(seal.0),
            "vault_signature_hex": null,
        });

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "core",
                "session_id": session_id_hex,
                "key_id": key_id,
                "frames": [frame_wire],
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(
            verify_body["all_verified"], serde_json::Value::Bool(true),
            "el servidor debe derivar exactamente la misma clave de sesión que el cliente, \
             a partir del mismo secreto DH y el mismo session_id — verify_body: {verify_body}"
        );
    }

    /// El servidor también debe poder SELLAR bajo una sesión de
    /// handshake (no solo verificar) cuando `POST /v1/seal` incluye el
    /// `session_id` acordado — confirma que `open_with_session_key`
    /// (Fase 2, `core.rs`) queda correctamente cableado desde el
    /// Adaptador HTTP.
    #[tokio::test]
    async fn seal_with_handshake_session_id_then_verify_round_trips() {
        use lacre_core::session_handshake::EphemeralHandshake;

        let router = build_router_with_state(test_state());

        let client_handshake = EphemeralHandshake::generate();
        let (_, handshake_body) = post_json(
            &router,
            "/v1/handshake",
            serde_json::json!({
                "client_public_key_hex": hex::encode(client_handshake.public_key().to_bytes()),
            }),
        )
        .await;
        let session_id_hex = handshake_body["session_id"].as_str().unwrap().to_string();

        // El servidor sella bajo ese mismo session_id, no bajo uno
        // nuevo generado internamente — es la propiedad puntual que
        // motivó open_with_session_key en Fase 2.
        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"sellado por el servidor bajo sesion de handshake"),
                "session_id": session_id_hex,
            }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");
        assert_eq!(
            seal_body["session_id"].as_str().unwrap(),
            session_id_hex,
            "el session_id devuelto por /v1/seal debe ser EXACTAMENTE el del handshake, no uno nuevo"
        );

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "core",
                "session_id": session_id_hex,
                "key_id": 0,
                "frames": seal_body["frames"].clone(),
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["all_verified"], serde_json::Value::Bool(true));
    }

    /// `POST /v1/seal` con un `session_id` que no corresponde a ningún
    /// handshake activo debe devolver un error explícito (422), no
    /// caer silenciosamente al ring fijo del servidor — eso sería
    /// aceptar una sesión bajo una clave distinta a la que el cliente
    /// cree estar usando, exactamente el tipo de degradación silenciosa
    /// que A4/A8 prohíben.
    #[tokio::test]
    async fn seal_with_unknown_handshake_session_id_is_rejected_not_silently_downgraded() {
        let router = build_router_with_state(test_state());
        let fake_session_id = hex::encode(lacre_core::session::SessionId::generate().0);

        let (status, body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"no deberia sellarse bajo el ring fijo"),
                "session_id": fake_session_id,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "body: {body}");
    }

    /// Un `client_public_key_hex` de longitud incorrecta debe devolver
    /// 400, no un 500 ni un handshake que "funciona" con una clave
    /// truncada o rellenada.
    #[tokio::test]
    async fn handshake_with_malformed_client_public_key_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let (status, _) = post_json(
            &router,
            "/v1/handshake",
            serde_json::json!({"client_public_key_hex": "aabb"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// El test central de Vault por HTTP: sellar bajo el perfil "vault"
    /// debe producir frames con `vault_signature_hex` presente (no
    /// `null`), y esos mismos frames deben verificar exitosamente por
    /// `POST /v1/verify` — confirmando que el servidor firma con su
    /// propia `VaultSigningKey` al sellar y exige/verifica esa misma
    /// firma al verificar, tal como pide 9.5 ("la verificación de firma
    /// está integrada en verify_frame, no es un paso aparte que se
    /// pueda omitir").
    #[tokio::test]
    async fn seal_and_verify_under_vault_profile_carries_signature() {
        let router = build_router_with_state(test_state());

        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(b"transaccion de alto valor con no repudio"),
            }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");

        let signature_hex = seal_body["frames"][0]["vault_signature_hex"].as_str();
        assert!(
            signature_hex.is_some(),
            "un frame sellado bajo el perfil vault debe traer vault_signature_hex, no null — seal_body: {seal_body}"
        );
        assert_eq!(
            signature_hex.unwrap().len(),
            128, // 64 bytes de firma Ed25519, en hex
            "la firma Ed25519 debe ser de 64 bytes (128 caracteres hex)"
        );

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "vault",
                "session_id": seal_body["session_id"],
                "key_id": 0,
                "frames": seal_body["frames"].clone(),
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(verify_body["all_verified"], serde_json::Value::Bool(true));
    }

    /// Un frame sellado bajo el perfil "core" (sin firma) verificado
    /// bajo el perfil "vault" debe FALLAR — 9.5 exige la firma, y no
    /// debe aceptarse en su ausencia solo porque el HMAC subyacente sea
    /// correcto. Confirma `CoreError::VaultSignatureMismatch` reportado
    /// como cualquier otro fallo de verificación (HTTP 200, `ok: false`
    /// en `results`), no como un 500 ni una excepción silenciosa.
    #[tokio::test]
    async fn verifying_an_unsigned_frame_under_vault_profile_is_rejected() {
        let router = build_router_with_state(test_state());

        // Sellado bajo "core": sin firma Vault.
        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"este frame nunca fue firmado"),
            }),
        )
        .await;
        assert!(seal_body["frames"][0]["vault_signature_hex"].is_null());

        // Se intenta verificar ese mismo frame bajo "vault", que exige
        // firma — debe rechazarse, no aceptarse "porque el HMAC ya era
        // válido".
        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "vault",
                "session_id": seal_body["session_id"],
                "key_id": 0,
                "frames": seal_body["frames"].clone(),
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "verify_body: {verify_body}");
        assert_eq!(
            verify_body["all_verified"], serde_json::Value::Bool(false),
            "un frame sin firma Vault nunca debe verificar bajo el perfil vault — verify_body: {verify_body}"
        );
        assert_eq!(verify_body["results"][0]["ok"], serde_json::Value::Bool(false));
    }

    /// Una firma Vault adulterada a mano (un byte cambiado) debe
    /// rechazarse igual que un sello adulterado — el no-repudio no debe
    /// poder falsificarse ni parcialmente.
    #[tokio::test]
    async fn tampered_vault_signature_is_rejected() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(b"firma que sera adulterada"),
            }),
        )
        .await;

        let mut frames = seal_body["frames"].clone();
        let original_sig = frames[0]["vault_signature_hex"].as_str().unwrap().to_string();
        let first_byte = u8::from_str_radix(&original_sig[..2], 16).unwrap();
        let corrupted = format!("{:02x}{}", first_byte ^ 0xFF, &original_sig[2..]);
        frames[0]["vault_signature_hex"] = serde_json::Value::String(corrupted);

        let (verify_status, verify_body) = post_json(
            &router,
            "/v1/verify",
            serde_json::json!({
                "profile": "vault",
                "session_id": seal_body["session_id"],
                "key_id": 0,
                "frames": frames,
            }),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK);
        assert_eq!(verify_body["all_verified"], serde_json::Value::Bool(false));
    }

    /// El test central de ACK: sellar bajo Vault, confirmar los
    /// índices por lote con `POST /v1/ack`, y comprobar que el
    /// servidor reporta `total_receipts` acorde — la prueba de que el
    /// `ReceiptLog` (7.5) realmente se pobló, no solo que el endpoint
    /// respondió 200.
    #[tokio::test]
    async fn ack_after_vault_seal_records_receipts_for_each_index() {
        let router = build_router_with_state(test_state());

        // Payload grande para forzar más de un fragmento y confirmar
        // que el ACK por lote cubre varios índices a la vez, no solo
        // el caso trivial de un único frame.
        let payload = vec![0x42u8; 256 * 1024 * 3]; // 3 slots completos bajo el perfil vault
        let (seal_status, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(&payload),
            }),
        )
        .await;
        assert_eq!(seal_status, StatusCode::OK, "seal_body: {seal_body}");
        let frames = seal_body["frames"].as_array().unwrap();
        assert!(frames.len() >= 2, "el payload debe fragmentarse en más de un frame para esta prueba");

        let indices: Vec<u64> = frames.iter().map(|f| f["index"].as_u64().unwrap()).collect();

        let (ack_status, ack_body) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({
                "session_id": seal_body["session_id"],
                "indices": indices,
            }),
        )
        .await;
        assert_eq!(ack_status, StatusCode::OK, "ack_body: {ack_body}");
        assert_eq!(ack_body["all_acknowledged"], serde_json::Value::Bool(true));
        assert_eq!(
            ack_body["total_receipts"].as_u64().unwrap() as usize,
            indices.len(),
            "debe haber exactamente un recibo por índice confirmado — ack_body: {ack_body}"
        );
        for result in ack_body["results"].as_array().unwrap() {
            assert_eq!(result["ok"], serde_json::Value::Bool(true));
        }
    }

    /// `POST /v1/ack` sobre un `session_id` que nunca se selló bajo
    /// Vault (fue sellado bajo Core, que no persiste ningún
    /// `SealerCore`) debe dar 404 explícito — nunca inventar un recibo
    /// ni degradar silenciosamente.
    #[tokio::test]
    async fn ack_for_a_core_session_is_not_found() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"sellado bajo core, sin persistencia de sealer"),
            }),
        )
        .await;

        let (ack_status, _) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({
                "session_id": seal_body["session_id"],
                "indices": [0],
            }),
        )
        .await;
        assert_eq!(ack_status, StatusCode::NOT_FOUND);
    }

    /// `POST /v1/ack` sobre un `session_id` que directamente no existe
    /// (nunca se llamó a `/v1/seal` con él) también debe dar 404.
    #[tokio::test]
    async fn ack_for_unknown_session_id_is_not_found() {
        let router = build_router_with_state(test_state());
        let fake_session_id = hex::encode(lacre_core::session::SessionId::generate().0);

        let (ack_status, _) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({"session_id": fake_session_id, "indices": [0]}),
        )
        .await;
        assert_eq!(ack_status, StatusCode::NOT_FOUND);
    }

    /// El test central de `GET /v1/receipts/{session_id}`: sellar bajo
    /// Vault, confirmar con ACK, y leer los recibos — confirmando que
    /// `fragment_index`/`receipt_hex`/`purged_at_ms` coinciden con lo
    /// que el propio `AckResponse` ya reportó como `total_receipts`, y
    /// que `receipt_hex` es un valor real de 32 bytes (64 caracteres
    /// hex), no un placeholder.
    #[tokio::test]
    async fn receipts_endpoint_reflects_receipts_recorded_by_ack() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(b"contenido para verificar el registro de recibos"),
            }),
        )
        .await;
        let session_id = seal_body["session_id"].as_str().unwrap().to_string();
        let indices: Vec<u64> = seal_body["frames"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["index"].as_u64().unwrap())
            .collect();

        let (_, ack_body) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({"session_id": session_id, "indices": indices}),
        )
        .await;
        let total_receipts_reported_by_ack = ack_body["total_receipts"].as_u64().unwrap();

        let (status, receipts_body) =
            get_json(&router, &format!("/v1/receipts/{session_id}")).await;
        assert_eq!(status, StatusCode::OK, "receipts_body: {receipts_body}");
        assert_eq!(receipts_body["session_id"], serde_json::json!(session_id));

        let entries = receipts_body["entries"].as_array().unwrap();
        assert_eq!(
            entries.len() as u64,
            total_receipts_reported_by_ack,
            "el conteo de /v1/receipts debe coincidir con total_receipts que ya reportó /v1/ack"
        );
        for entry in entries {
            let receipt_hex = entry["receipt_hex"].as_str().unwrap();
            assert_eq!(receipt_hex.len(), 64, "un Receipt son 32 bytes -> 64 caracteres hex");
            assert!(entry["fragment_index"].is_u64());
            assert!(entry["purged_at_ms"].is_u64());
        }
    }

    /// `GET /v1/receipts/{session_id}` sobre una sesión sellada bajo
    /// Core (que nunca persiste un `SealerCore`) debe dar 404 — mismo
    /// criterio que `POST /v1/ack`.
    #[tokio::test]
    async fn receipts_endpoint_for_a_core_session_is_not_found() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "core",
                "payload_hex": hex::encode(b"sellado bajo core, sin recibos posibles"),
            }),
        )
        .await;
        let session_id = seal_body["session_id"].as_str().unwrap();

        let (status, _) = get_json(&router, &format!("/v1/receipts/{session_id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// `GET /v1/receipts/{session_id}` sobre un `session_id` que
    /// directamente no existe debe dar 404, no un 500 ni una lista
    /// vacía que pudiera confundirse con "todavía no hay recibos".
    #[tokio::test]
    async fn receipts_endpoint_for_unknown_session_id_is_not_found() {
        let router = build_router_with_state(test_state());
        let fake_session_id = hex::encode(lacre_core::session::SessionId::generate().0);

        let (status, _) = get_json(&router, &format!("/v1/receipts/{fake_session_id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// Un `session_id` malformado en la ruta debe dar 400, no un 500
    /// ni tratarse como si fuera un session_id válido pero desconocido.
    #[tokio::test]
    async fn receipts_endpoint_with_malformed_session_id_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let (status, _) = get_json(&router, "/v1/receipts/no-es-hex-valido").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Sellar bajo Vault, pero SIN confirmar ningún ACK todavía, debe
    /// devolver una lista de recibos vacía (200 con `entries: []`), no
    /// un 404 — la sesión Vault existe y está viva, simplemente todavía
    /// no se registró ningún recibo. Distingue "sesión inexistente" de
    /// "sesión existente sin recibos aún", que son estados distintos.
    #[tokio::test]
    async fn receipts_endpoint_before_any_ack_returns_an_empty_list_not_404() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(b"sellado bajo vault, sin confirmar nada todavia"),
            }),
        )
        .await;
        let session_id = seal_body["session_id"].as_str().unwrap();

        let (status, receipts_body) = get_json(&router, &format!("/v1/receipts/{session_id}")).await;
        assert_eq!(status, StatusCode::OK, "receipts_body: {receipts_body}");
        assert_eq!(receipts_body["entries"], serde_json::json!([]));
    }

    /// Confirmar el mismo índice dos veces es idempotente por diseño de
    /// `SealerCore::ack` (ver core.rs): la segunda llamada no encuentra
    /// nada que purgar (el slot del buffer ya se liberó en la primera)
    /// ni registra un segundo recibo — devuelve `Ok(false)`, no un
    /// error. `handle_ack` reporta ambos intentos como `ok: true` (la
    /// request en sí no falló), y `total_receipts` NO crece en el
    /// segundo ack — es la señal correcta de que no se duplicó el
    /// recibo, sin necesidad de que el Núcleo trate un ACK repetido
    /// como un fallo de protocolo.
    #[tokio::test]
    async fn duplicate_ack_for_the_same_index_does_not_duplicate_the_receipt() {
        let router = build_router_with_state(test_state());

        let (_, seal_body) = post_json(
            &router,
            "/v1/seal",
            serde_json::json!({
                "profile": "vault",
                "payload_hex": hex::encode(b"un solo frame para probar ack duplicado"),
            }),
        )
        .await;
        let session_id = seal_body["session_id"].clone();

        let (_, first_ack) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({"session_id": session_id, "indices": [0]}),
        )
        .await;
        assert_eq!(first_ack["total_receipts"], serde_json::json!(1), "first_ack: {first_ack}");

        let (ack_status, second_ack) = post_json(
            &router,
            "/v1/ack",
            serde_json::json!({"session_id": session_id, "indices": [0]}),
        )
        .await;
        assert_eq!(ack_status, StatusCode::OK);
        assert_eq!(
            second_ack["total_receipts"], serde_json::json!(1),
            "un ack duplicado no debe agregar un segundo recibo — second_ack: {second_ack}"
        );
    }

    /// Un perfil desconocido en el cuerpo de la request debe devolver
    /// 400, no un 500 ni un comportamiento silenciosamente degradado a
    /// un perfil por defecto.
    #[tokio::test]
    async fn unknown_profile_returns_bad_request() {
        let router = build_router_with_state(test_state());
        let request = Request::builder()
            .method("POST")
            .uri("/v1/seal")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"profile": "no-existe", "payload_hex": "aa"}).to_string(),
            ))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn health_endpoint_responds_ok() {
        let router = build_router_with_state(test_state());
        let request = Request::builder().uri("/v1/health").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
