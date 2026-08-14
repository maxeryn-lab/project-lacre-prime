//! Lógica de dominio de las 5 operaciones del protocolo (handshake,
//! seal, verify, ack, receipts) — deliberadamente sin ningún tipo de
//! `axum`. Antes de esta etapa, esta lógica vivía directamente dentro
//! de los handlers HTTP de `http_server.rs`; se extrajo acá para que
//! un segundo Adaptador (WebSocket, gRPC) pueda invocarla sin
//! duplicarla ni depender de axum para hacerlo.
//!
//! # Por qué este refactor es la prueba real de DECISIONS.md punto 16
//!
//! Hasta este checkpoint, la afirmación "Adaptadores son un eje de
//! extensión de primer nivel, sustituible sin tocar la lógica de
//! negocio" era una intención de diseño respaldada por UN solo
//! Adaptador — no había manera de confirmar empíricamente que la
//! costura `http_adapter.rs` (traducción de tipos) más
//! `http_server.rs` (transporte) realmente separaba lo que decía
//! separar, hasta que apareciera un segundo Adaptador real que la
//! ejercitara. Este módulo es el resultado de esa prueba: cada función
//! acá recibe exactamente el mismo `AppState` y los mismos tipos
//! `*Request`/`*Response` de `http_adapter.rs` que ya usaba
//! `http_server.rs`, y devuelve `Result<_, DomainError>` — un tipo de
//! error que NINGÚN Adaptador concreto conoce todavía (ni `StatusCode`
//! de HTTP, ni ningún código de cierre de WebSocket). Cada Adaptador
//! traduce `DomainError` a su propio vocabulario de error (HTTP:
//! `StatusCode` + mensaje; WebSocket: un mensaje de error dentro del
//! mismo protocolo de frames, ver `websocket_adapter.rs`).
//!
//! # Qué significa que esto sea genuino y no un refactor cosmético
//!
//! Antes de este checkpoint, `handle_seal` en `http_server.rs` recibía
//! `State<AppState>` y `Json<SealRequest>` (tipos de axum) y devolvía
//! `Result<Json<SealResponse>, (StatusCode, String)>` (también de
//! axum) — la lógica de negocio y el transporte estaban entrelazados
//! en la misma función. Si un segundo Adaptador hubiera necesitado
//! reescribir esa lógica desde cero (aunque fuera copiando y pegando),
//! eso habría confirmado que la separación Núcleo/Profile/Adaptador
//! nunca llegó, en la práctica, hasta la capa de lógica de negocio del
//! Adaptador HTTP — se habría quedado en un nivel más bajo (solo
//! `lacre-core` vs. `lacre-server`). Extraer estas funciones y que
//! `websocket_adapter.rs` las use tal cual, sin modificarlas, es la
//! evidencia de que la separación sí llega hasta ahí.

use crate::http_adapter::{
    decode_client_public_key, describe_core_error, session_id_to_hex, AckRequest, AckResponse,
    AckResult, FrameVerificationResult, HandshakeRequest, HandshakeResponse, ReceiptEntryWire,
    ReceiptsResponse, SealRequest, SealResponse, SealedFrameWire, VerifyRequest, VerifyResponse,
};
use crate::http_server::AppState;
use crate::profile_config::ProfileName;
use lacre_core::core::{SealerCore, VerifierCore};
use lacre_core::session::{MasterKeyRing, SessionId};
use lacre_core::session_handshake::EphemeralHandshake;
use lacre_core::vault_signature::VaultSigningKey;
use std::sync::Arc;
use std::time::Duration;

/// Error de dominio — deliberadamente sin ningún código de transporte
/// (`StatusCode`, código de cierre de WebSocket, código de error
/// gRPC). Cada Adaptador decide cómo traducir cada variante a su
/// propio vocabulario; ver `to_http_error` en `http_server.rs` y
/// `to_ws_error_message` en `websocket_adapter.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// La request llegó bien formada pero con datos que el cliente
    /// controla y equivocó (perfil desconocido, hex inválido,
    /// session_id malformado). Un Adaptador HTTP mapea esto a 400.
    BadRequest(String),
    /// La request está bien formada y los datos son sintácticamente
    /// válidos, pero la operación no puede completarse por una razón
    /// de estado del servidor (session_id de handshake no encontrado,
    /// key_id desconocido, fallo de verificación de un frame). Un
    /// Adaptador HTTP mapea esto a 422.
    Unprocessable(String),
    /// No existe ningún recurso con el identificador dado (sesión
    /// Vault nunca sellada, o expirada). Un Adaptador HTTP mapea esto
    /// a 404.
    NotFound(String),
}

/// `handle_handshake` (antes en `http_server.rs`), sin axum.
pub fn handshake(state: &AppState, req: &HandshakeRequest) -> Result<HandshakeResponse, DomainError> {
    let client_public_key =
        decode_client_public_key(req).map_err(|e| DomainError::BadRequest(e.message().to_string()))?;

    let server_handshake = EphemeralHandshake::generate();
    let server_public_key = server_handshake.public_key();
    let shared_secret = server_handshake.complete(client_public_key);

    let session_id = SessionId::generate();
    let key_id = 0u8;
    let ring = Arc::new(MasterKeyRing::new(
        key_id,
        shared_secret.into_ikm_bytes().to_vec(),
        Duration::from_secs(3600),
    ));

    state.handshake_sessions().insert(session_id, ring);

    Ok(HandshakeResponse {
        server_public_key_hex: hex::encode(server_public_key.to_bytes()),
        session_id: session_id_to_hex(&session_id),
        key_id,
    })
}

/// `handle_seal` (antes en `http_server.rs`), sin axum.
pub fn seal(state: &AppState, req: &SealRequest) -> Result<SealResponse, DomainError> {
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("perfil desconocido: {}", req.profile)))?;
    let cfg = profile.config();
    let use_vault = profile.requires_vault_signature();

    let payload = hex::decode(&req.payload_hex)
        .map_err(|_| DomainError::BadRequest("payload_hex no es hex válido".to_string()))?;

    let mut sealer = match (&req.session_id, use_vault) {
        (None, false) => SealerCore::open(
            state.key_ring().clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        ),
        (None, true) => SealerCore::open_with_vault_key(
            state.key_ring().clone(),
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
        ),
        (Some(session_id_hex), _) => {
            let session_id = crate::http_adapter::session_id_from_hex(session_id_hex)
                .ok_or_else(|| DomainError::BadRequest("session_id inválido".to_string()))?;
            let ring = state.handshake_sessions().get(&session_id).ok_or_else(|| {
                DomainError::Unprocessable(
                    "session_id no corresponde a ningún handshake activo (o ya expiró)".to_string(),
                )
            })?;
            if use_vault {
                SealerCore::open_with_session_key_and_vault_key(
                    ring,
                    session_id,
                    cfg.algo,
                    cfg.slot_size,
                    cfg.slot_count,
                    cfg.forced_purge_timeout,
                    VaultSigningKey::from_bytes(&state.vault_signing_key_bytes()),
                )
            } else {
                SealerCore::open_with_session_key(
                    ring,
                    session_id,
                    cfg.algo,
                    cfg.slot_size,
                    cfg.slot_count,
                    cfg.forced_purge_timeout,
                )
            }
        }
    };

    let sealed = sealer
        .seal_payload(&payload, cfg.slot_size)
        .map_err(|e| DomainError::Unprocessable(describe_core_error(&e)))?;

    let frames = sealed
        .iter()
        .map(|(frame, seal)| {
            let signature = sealer.sign_seal_for_vault(seal);
            SealedFrameWire::from_parts(frame, seal, signature.as_ref())
        })
        .collect();

    let session_id = sealer.session_id();

    if use_vault {
        state.sealer_sessions().insert(session_id, sealer);
    }

    Ok(SealResponse {
        session_id: session_id_to_hex(&session_id),
        frames,
    })
}

/// `handle_verify` (antes en `http_server.rs`), sin axum.
pub fn verify(state: &AppState, req: &VerifyRequest) -> Result<VerifyResponse, DomainError> {
    let profile = ProfileName::from_header_value(&req.profile)
        .ok_or_else(|| DomainError::BadRequest(format!("perfil desconocido: {}", req.profile)))?;
    let cfg = profile.config();

    let session_id: SessionId = crate::http_adapter::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("session_id inválido".to_string()))?;

    let key_ring = state
        .handshake_sessions()
        .get(&session_id)
        .unwrap_or_else(|| state.key_ring().clone());

    let mut verifier = if profile.requires_vault_signature() {
        VerifierCore::resume_with_vault_key(
            key_ring,
            session_id,
            req.key_id,
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
            state.vault_verifying_key(),
        )
    } else {
        VerifierCore::resume(
            key_ring,
            session_id,
            req.key_id,
            cfg.algo,
            cfg.slot_size,
            cfg.slot_count,
            cfg.forced_purge_timeout,
        )
    }
    .ok_or_else(|| DomainError::Unprocessable("key_id no reconocido en el ring del servidor".to_string()))?;

    let mut results = Vec::with_capacity(req.frames.len());
    let mut all_verified = true;

    for wire_frame in &req.frames {
        let index = wire_frame.index;
        let decoded = wire_frame.into_parts();
        let outcome = match decoded {
            Err(decode_err) => Err(decode_err.message().to_string()),
            Ok((frame, seal, vault_sig)) => verifier
                .verify_frame(&frame, req.key_id, &seal, vault_sig.as_ref())
                .map_err(|e| describe_core_error(&e)),
        };

        match outcome {
            Ok(()) => results.push(FrameVerificationResult { index, ok: true, error: None }),
            Err(msg) => {
                all_verified = false;
                results.push(FrameVerificationResult { index, ok: false, error: Some(msg) });
                break;
            }
        }
    }

    Ok(VerifyResponse {
        session_id: req.session_id.clone(),
        results,
        all_verified,
    })
}

/// `handle_ack` (antes en `http_server.rs`), sin axum.
pub fn ack(state: &AppState, req: &AckRequest) -> Result<AckResponse, DomainError> {
    let session_id = crate::http_adapter::session_id_from_hex(&req.session_id)
        .ok_or_else(|| DomainError::BadRequest("session_id inválido".to_string()))?;

    let outcome = state.sealer_sessions().with_sealer(&session_id, |sealer| {
        let mut results = Vec::with_capacity(req.indices.len());
        let mut all_acknowledged = true;
        for &index in &req.indices {
            match sealer.ack(index) {
                Ok(_purged) => results.push(AckResult { index, ok: true, error: None }),
                Err(e) => {
                    all_acknowledged = false;
                    results.push(AckResult { index, ok: false, error: Some(describe_core_error(&e)) });
                }
            }
        }
        let total_receipts = sealer.receipts().map(|r| r.len()).unwrap_or(0);
        (results, all_acknowledged, total_receipts)
    });

    match outcome {
        Err(crate::sealer_session_store::WithSealerError::NotFound) => Err(DomainError::NotFound(
            "no hay ninguna sesión Vault activa con ese session_id (nunca se selló bajo Vault, \
             o ya expiró del lado servidor)"
                .to_string(),
        )),
        Ok((results, all_acknowledged, total_receipts)) => Ok(AckResponse {
            session_id: req.session_id.clone(),
            results,
            all_acknowledged,
            total_receipts,
        }),
    }
}

/// `handle_receipts` (antes en `http_server.rs`), sin axum.
pub fn receipts(state: &AppState, session_id_hex: &str) -> Result<ReceiptsResponse, DomainError> {
    let session_id = crate::http_adapter::session_id_from_hex(session_id_hex)
        .ok_or_else(|| DomainError::BadRequest("session_id inválido".to_string()))?;

    let entries = state
        .sealer_sessions()
        .with_sealer(&session_id, |sealer| {
            sealer
                .receipts()
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| ReceiptEntryWire {
                            fragment_index: entry.fragment_index,
                            receipt_hex: hex::encode(entry.receipt.0),
                            purged_at_ms: entry.purged_at_ms,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .map_err(|crate::sealer_session_store::WithSealerError::NotFound| {
            DomainError::NotFound(
                "no hay ninguna sesión Vault activa con ese session_id (nunca se selló bajo \
                 Vault, o ya expiró del lado servidor)"
                    .to_string(),
            )
        })?;

    Ok(ReceiptsResponse {
        session_id: session_id_hex.to_string(),
        entries,
    })
}
