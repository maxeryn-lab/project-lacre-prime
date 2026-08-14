//! Traducción entre tipos de `lacre-core` y JSON — deliberadamente sin
//! ninguna dependencia de `axum`, `tokio`, ni de ningún detalle de
//! transporte HTTP concreto.
//!
//! # Por qué este módulo existe separado de `http_server.rs`
//!
//! Ver DECISIONS.md punto 16 y ARCHITECTURE_NOTES.md ("Dos ejes de
//! extensión independientes") para el razonamiento completo. Resumen:
//! Adaptadores son, junto con Profiles, un eje de extensión de primer
//! nivel del proyecto (7.1/7.4), no un detalle interno de
//! `lacre-server`. HTTP es apenas el primer Adaptador que se
//! construye — si mañana aparece un Adaptador WebSocket o gRPC, debería
//! poder reutilizar la traducción "frames de lacre-core ↔
//! representación serializable" sin duplicarla ni depender de axum
//! para hacerlo.
//!
//! Esta separación NO es un `trait Transport` especulativo (eso sería
//! exactamente el riesgo de sobreingeniería que ya identificamos): es
//! el refactor mínimo de higiene que ya sabemos necesario porque este
//! mismo Adaptador HTTP lo usa hoy. Si aparece un segundo Adaptador
//! real, ahí — y no antes — se decide si conviene extraer un trait a
//! partir de las DOS implementaciones concretas que ya existirán.
//!
//! # Lo que este módulo NO hace
//!
//! No abre sockets, no sabe qué es una request ni una response HTTP,
//! no importa `axum`. Solo convierte entre `(LacreFrame, Seal, ...)` y
//! tipos `serde`. `http_server.rs` es quien conoce axum y llama a este
//! módulo para producir/consumir los bytes de cuerpo.
//!
//! # Formato de cuerpo elegido para esta primera implementación
//!
//! Array JSON con `frame` y `seal` en el mismo objeto (ver
//! `SealedFrameWire`). Esto es una **desviación declarada** del
//! Axioma A2 ("el sello... nunca se incorpora, modifica o mezcla con
//! el contenido del cuerpo del mensaje") si se interpreta "mensaje de
//! transporte" como cada request/response HTTP: acá el sello viaja en
//! el CUERPO junto al fragmento, no en una cabecera separada por
//! fragmento como sugiere 9.3 literalmente
//! ("...cabecera específica...asociada a cada fragmento").
//!
//! Se eligió así, deliberadamente, para esta primera implementación
//! por ser verificable de punta a punta con curl en un solo intercambio
//! HTTP, dejando la variante fiel a 9.3 (un chunk HTTP por frame, sello
//! en cabecera `X-Lacre-Seal` de cada chunk) como candidata natural de
//! una segunda implementación de Adaptador HTTP — reutilizando, en gran
//! parte, este mismo módulo de traducción (los tipos `*Wire` no
//! cambian; lo que cambiaría es cómo `http_server.rs` los transporta).
//! Ver PENDING.md para el seguimiento de este punto.

use lacre_core::core::CoreError;
use lacre_core::frame::LacreFrame;
use lacre_core::hmac_seal::Seal;
use lacre_core::session::SessionId;
use lacre_core::vault_signature::VaultSignature;
use serde::{Deserialize, Serialize};

/// Representación JSON de un `SessionId` (16 bytes fijos) — hex en vez
/// de base64 por legibilidad directa en curl/logs, sin que importe el
/// costo de unos pocos bytes extra: un session_id nunca es el cuerpo
/// masivo de la respuesta.
pub fn session_id_to_hex(id: &SessionId) -> String {
    hex::encode(id.0)
}

/// Inversa de `session_id_to_hex`. Devuelve `None` si el string no
/// decodifica a exactamente 16 bytes de hex válido — nunca produce un
/// `SessionId` parcial o rellenado con ceros por conveniencia (A4,
/// fallo cerrado: un session_id corrupto no debe interpretarse *como
/// si* fuera un session_id distinto, debe rechazarse).
pub fn session_id_from_hex(s: &str) -> Option<SessionId> {
    let bytes = hex::decode(s).ok()?;
    let arr: [u8; 16] = bytes.try_into().ok()?;
    Some(SessionId(arr))
}

/// Un frame + su sello, en la forma que viaja en el cuerpo JSON. Los
/// campos de `LacreFrame` se aplanan acá en vez de derivar `Serialize`
/// directamente sobre `LacreFrame` — `LacreFrame` es un tipo de
/// `lacre-core`, y `lacre-core` no debe depender de `serde` (ninguna
/// razón de negocio para que el Núcleo sepa qué es JSON). Este `struct`
/// vive enteramente del lado del Adaptador.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedFrameWire {
    pub session_id: String,
    pub index: u64,
    pub total_fragments: Option<u64>,
    pub is_last: bool,
    /// Payload en hex, no en un array JSON de números — más compacto y
    /// más fácil de inspeccionar a mano en una respuesta de curl.
    pub payload_hex: String,
    pub seal_hex: String,
    /// Presente solo si la sesión es Vault (9.5/15.3). Ausente
    /// (`null` en JSON) para el resto de los perfiles — no un campo
    /// vacío ni un string "none", para que la ausencia sea
    /// indistinguible de "este perfil no usa Vault" y no de "Vault
    /// falló en blanco".
    pub vault_signature_hex: Option<String>,
}

impl SealedFrameWire {
    pub fn from_parts(
        frame: &LacreFrame,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Self {
        SealedFrameWire {
            session_id: session_id_to_hex(&frame.session_id),
            index: frame.index,
            total_fragments: frame.total_fragments,
            is_last: frame.is_last,
            payload_hex: hex::encode(&frame.payload),
            seal_hex: hex::encode(seal.0),
            vault_signature_hex: vault_signature.map(|sig| hex::encode(sig.to_bytes())),
        }
    }

    /// Reconstruye `(LacreFrame, Seal, Option<VaultSignature>)` a
    /// partir de la representación de cable. Devuelve un error de
    /// traducción explícito (no un `Option`/panic) porque el llamador
    /// (`http_server.rs`) necesita distinguir "el JSON no decodifica a
    /// un frame válido" (error 400, problema del cliente) de "el frame
    /// decodificó pero no verifica" (error de integridad, tratado por
    /// `verify_frame` — un problema de otra naturaleza).
    pub fn into_parts(&self) -> Result<(LacreFrame, Seal, Option<VaultSignature>), WireDecodeError> {
        let session_id =
            session_id_from_hex(&self.session_id).ok_or(WireDecodeError::InvalidSessionId)?;
        let payload = hex::decode(&self.payload_hex).map_err(|_| WireDecodeError::InvalidPayloadHex)?;
        let seal_bytes = hex::decode(&self.seal_hex).map_err(|_| WireDecodeError::InvalidSealHex)?;
        let seal_arr: [u8; 32] = seal_bytes
            .try_into()
            .map_err(|_| WireDecodeError::InvalidSealLength)?;

        let vault_signature = match &self.vault_signature_hex {
            None => None,
            Some(hex_str) => {
                let bytes = hex::decode(hex_str).map_err(|_| WireDecodeError::InvalidVaultSignatureHex)?;
                let arr: [u8; 64] = bytes
                    .try_into()
                    .map_err(|_| WireDecodeError::InvalidVaultSignatureLength)?;
                Some(VaultSignature::from_bytes(&arr))
            }
        };

        let frame = LacreFrame {
            session_id,
            index: self.index,
            total_fragments: self.total_fragments,
            is_last: self.is_last,
            payload,
        };

        Ok((frame, Seal(seal_arr), vault_signature))
    }
}

/// Fallo al traducir un `SealedFrameWire` recibido por HTTP de vuelta a
/// los tipos de `lacre-core` — siempre un problema del CUERPO recibido
/// (JSON malformado, hex inválido, longitud incorrecta), nunca un fallo
/// de verificación de integridad. `http_server.rs` mapea esto a HTTP
/// 400 (Bad Request); un `CoreError::SealMismatch` real, en cambio, se
/// mapea a 422 (ver `core_error_to_status_and_message`) — son capas de
/// error distintas y no deben confundirse en el código de estado HTTP
/// que el cliente recibe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDecodeError {
    InvalidSessionId,
    InvalidPayloadHex,
    InvalidSealHex,
    InvalidSealLength,
    InvalidVaultSignatureHex,
    InvalidVaultSignatureLength,
}

impl WireDecodeError {
    pub fn message(self) -> &'static str {
        match self {
            WireDecodeError::InvalidSessionId => "session_id debe ser hex de exactamente 16 bytes (32 caracteres)",
            WireDecodeError::InvalidPayloadHex => "payload_hex no es hex válido",
            WireDecodeError::InvalidSealHex => "seal_hex no es hex válido",
            WireDecodeError::InvalidSealLength => "seal_hex debe decodificar a exactamente 32 bytes",
            WireDecodeError::InvalidVaultSignatureHex => "vault_signature_hex no es hex válido",
            WireDecodeError::InvalidVaultSignatureLength => {
                "vault_signature_hex debe decodificar a exactamente 64 bytes"
            }
        }
    }
}

/// Cuerpo de la request de `POST /v1/seal`.
#[derive(Debug, Clone, Deserialize)]
pub struct SealRequest {
    /// Perfil de despliegue, mismo valor que la cabecera `lacre-profile`
    /// de 15.2 — se acepta en el cuerpo en vez de cabecera en esta
    /// primera implementación por simplicidad de probar con curl
    /// (`-d` es más simple que `-H` para el caso de uso de smoke test);
    /// no es una decisión final, ver PENDING.md.
    pub profile: String,
    /// El payload completo a fragmentar y sellar, en hex — no texto
    /// plano, para no imponer una codificación de texto sobre un
    /// payload que 8.1 no exige que sea texto.
    pub payload_hex: String,
    /// Si está presente, se usa el `MasterKeyRing` de la sesión de
    /// handshake correspondiente (ver `POST /v1/handshake`) y ese mismo
    /// `session_id`, en vez de generar uno nuevo bajo el ring fijo del
    /// servidor. Ausente por defecto — coherente con el comportamiento
    /// que ya existía antes de agregar el endpoint de handshake, sin
    /// romperlo.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Cuerpo de la respuesta de `POST /v1/seal`: la secuencia completa de
/// frames sellados que `SealerCore::seal_payload` produjo de una vez —
/// a diferencia del servidor viejo (un frame por request en `/v1/seal`,
/// ver PENDING.md §3), la interfaz actual de `lacre-core` ya fragmenta
/// internamente y devuelve todo junto.
#[derive(Debug, Clone, Serialize)]
pub struct SealResponse {
    pub session_id: String,
    pub frames: Vec<SealedFrameWire>,
}

/// Cuerpo de la request de `POST /v1/verify`: la sesión a la que
/// pertenece (para poder invocar `VerifierCore::resume` del lado
/// servidor) más la lista de frames a verificar en orden.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyRequest {
    pub profile: String,
    pub session_id: String,
    pub key_id: u8,
    pub frames: Vec<SealedFrameWire>,
}

/// Resultado de verificar un frame individual — se reporta uno por
/// frame, no un booleano agregado para toda la request, porque A4
/// (fallo cerrado) exige saber EXACTAMENTE cuál fragmento falló, no
/// solo que "algo" falló en la secuencia.
#[derive(Debug, Clone, Serialize)]
pub struct FrameVerificationResult {
    pub index: u64,
    pub ok: bool,
    /// Presente solo si `ok == false`.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResponse {
    pub session_id: String,
    pub results: Vec<FrameVerificationResult>,
    /// `true` solo si TODOS los frames de la request verificaron. Un
    /// resumen de conveniencia — `results` sigue siendo la fuente de
    /// verdad por frame.
    pub all_verified: bool,
}

/// Traduce un `CoreError` a un mensaje de texto estable para incluir en
/// `FrameVerificationResult::error` o en el cuerpo de un 4xx/5xx. No
/// expone el `Debug` interno de `CoreError` directamente al cliente:
/// eso acoplaría el formato de la API HTTP a los nombres de variantes
/// de un enum de `lacre-core`, que puede cambiar de forma no
/// relacionada con la API pública del Adaptador.
pub fn describe_core_error(err: &CoreError) -> String {
    match err {
        CoreError::Buffer(_) => "fallo del buffer de sesión (capacidad, timeout, o duplicado)".to_string(),
        CoreError::FrameState(_) => "transición de estado de frame inválida".to_string(),
        CoreError::UnknownKeyId => "key_id no reconocido en el ring de esta sesión".to_string(),
        CoreError::SealMismatch => "el sello no verifica contra el fragmento recibido".to_string(),
        CoreError::OutOfSequence { expected, received } => {
            format!("orden de fragmento inválido: se esperaba índice {expected}, se recibió {received}")
        }
        CoreError::VaultSignatureMismatch => {
            "la sesión requiere firma Vault y la firma está ausente o no verifica".to_string()
        }
    }
}

// -----------------------------------------------------------------
// Handshake X25519 (8.4, paso 1 — session_handshake.rs de lacre-core)
// -----------------------------------------------------------------
//
// Protocolo elegido para esta primera implementación: ClientInitiated,
// un único intercambio POST/response (ver conversación de diseño en
// CHANGELOG.md). El cliente genera su par efímero y envía su clave
// pública; el servidor genera la suya, calcula el secreto DH, construye
// el MasterKeyRing resultante, decide un session_id, lo guarda en su
// SessionStore (ver session_store.rs — deliberadamente decisión de
// ESTE Adaptador, no del protocolo), y responde con su propia clave
// pública más el session_id acordado.
//
// Documentado explícitamente porque no es la única variante posible:
// ServerAdvertised (el servidor publica su clave pública en un GET
// estático y el cliente hace POST con la suya) es igual de válida
// dentro de 8.4 y podría implementarse como una ruta HTTP alternativa,
// o como parte de un Adaptador WebSocket/QUIC/gRPC futuro, sin tocar
// session_handshake.rs en lacre-core ni este módulo de traducción más
// allá de, quizás, un tipo de wire adicional — el mecanismo de
// intercambio en sí pertenece al Adaptador, tal como 8.4/7.4 ya
// separan "qué garantiza el protocolo" de "cómo llegan los bytes".

/// Cuerpo de `POST /v1/handshake`: la clave pública efímera del
/// cliente, en hex (32 bytes fijos de X25519).
#[derive(Debug, Clone, Deserialize)]
pub struct HandshakeRequest {
    pub client_public_key_hex: String,
}

/// Respuesta de `POST /v1/handshake`: la clave pública efímera del
/// servidor (para que el cliente derive el mismo secreto de su lado) y
/// el `session_id` bajo el cual el servidor registró el
/// `MasterKeyRing` resultante — el mismo `session_id` que el cliente
/// debe usar luego en `POST /v1/seal`/`POST /v1/verify`.
#[derive(Debug, Clone, Serialize)]
pub struct HandshakeResponse {
    pub server_public_key_hex: String,
    pub session_id: String,
    /// `key_id` bajo el cual quedó registrado el ring — hoy siempre
    /// `0` (un único `MasterKeyRing` por sesión, sin rotación), pero se
    /// expone explícitamente en vez de asumirlo en el cliente, para no
    /// acoplar al cliente a un valor que `MasterKeyRing::new` podría,
    /// en el futuro, no fijar en `0` por defecto.
    pub key_id: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeDecodeError {
    InvalidClientPublicKeyHex,
    InvalidClientPublicKeyLength,
}

impl HandshakeDecodeError {
    pub fn message(self) -> &'static str {
        match self {
            HandshakeDecodeError::InvalidClientPublicKeyHex => {
                "client_public_key_hex no es hex válido"
            }
            HandshakeDecodeError::InvalidClientPublicKeyLength => {
                "client_public_key_hex debe decodificar a exactamente 32 bytes"
            }
        }
    }
}

/// Decodifica `client_public_key_hex` a los tipos de
/// `session_handshake`. Separado de `http_server.rs` para que la
/// traducción de wire quede en un solo lugar, igual que
/// `SealedFrameWire::into_parts`.
pub fn decode_client_public_key(
    req: &HandshakeRequest,
) -> Result<lacre_core::session_handshake::EphemeralPublicKey, HandshakeDecodeError> {
    let bytes = hex::decode(&req.client_public_key_hex)
        .map_err(|_| HandshakeDecodeError::InvalidClientPublicKeyHex)?;
    lacre_core::session_handshake::EphemeralPublicKey::from_slice(&bytes)
        .map_err(|_| HandshakeDecodeError::InvalidClientPublicKeyLength)
}

// -----------------------------------------------------------------
// ACK y recibo post-purga (7.5) — exclusivo del perfil Vault
// -----------------------------------------------------------------
//
// Ver comentario de cabecera de sealer_session_store.rs para el
// razonamiento completo de por qué esto necesita un SealerCore vivo
// entre `POST /v1/seal` y `POST /v1/ack`, y por qué se decidió
// explícitamente NO disparar ack() de forma implícita a partir de un
// HTTP 200 (CHANGELOG.md Etapa 16).

/// Cuerpo de `POST /v1/ack`: la sesión Vault correspondiente y los
/// índices de fragmento que el cliente confirma haber recibido y
/// procesado. Por lote, no uno por índice — coherente con que
/// `POST /v1/seal` también devuelve la secuencia completa de una sola
/// vez, en vez de forzar un round-trip HTTP por fragmento.
#[derive(Debug, Clone, Deserialize)]
pub struct AckRequest {
    pub session_id: String,
    pub indices: Vec<u64>,
}

/// Resultado de confirmar un índice — uno por índice, no un booleano
/// agregado, mismo criterio que `FrameVerificationResult`: A4 exige
/// saber EXACTAMENTE cuál índice falló, no solo que "algo" falló en el
/// lote.
/// Resultado de confirmar un índice — uno por índice, no un booleano
/// agregado, mismo criterio que `FrameVerificationResult`.
///
/// `ok: false` ocurre únicamente si `SealerCore::ack` devuelve `Err`
/// (una transición de `FrameState` inválida — ver core.rs) — no ante
/// un índice ya confirmado antes: `ack()` es idempotente por diseño
/// del Núcleo (un segundo `ack()` sobre el mismo índice no encuentra
/// nada que purgar ni duplica el recibo, y devuelve `Ok(false)`, no un
/// error). Un cliente que reintenta un ACK por una respuesta HTTP
/// perdida, por ejemplo, no debe interpretar `ok: true` en el segundo
/// intento como que se generó un segundo recibo — `total_receipts` en
/// `AckResponse` es la fuente de verdad sobre cuántos recibos existen
/// realmente.
#[derive(Debug, Clone, Serialize)]
pub struct AckResult {
    pub index: u64,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AckResponse {
    pub session_id: String,
    pub results: Vec<AckResult>,
    pub all_acknowledged: bool,
    /// Cantidad total de recibos acumulados en el `ReceiptLog` de esta
    /// sesión hasta el momento — no solo los confirmados en ESTE
    /// request, para que el cliente pueda saber si el registro sigue
    /// vivo del lado servidor sin tener que llevar la cuenta él mismo.
    pub total_receipts: usize,
}

// -----------------------------------------------------------------
// Lectura de recibos — GET /v1/receipts/{session_id}
// -----------------------------------------------------------------
//
// Ver comentario de cabecera de `handle_receipts` en http_server.rs
// para la limitación de alcance importante: los recibos viven dentro
// del mismo `SealerSessionStore` con TTL que `handle_ack` ya usa, NO
// en un registro de auditoría de largo plazo independiente. Este
// endpoint expone lo que 7.5 exige mientras la sesión sigue viva del
// lado servidor; no reemplaza a un sistema de archivo permanente si el
// caso de uso real lo necesita.

/// Un `ReceiptEntry` (`lacre-core`) traducido a JSON. `receipt_hex` es
/// el valor derivado del sello (`SHA-256(seal)`, 32 bytes) — NO
/// recuperable hacia el contenido ni hacia el sello original, tal como
/// 7.5 exige explícitamente ("no recuperable hacia el contenido, ni
/// del contenido mismo"). `purged_at_ms` es relativo al inicio del
/// `ReceiptLog` de la sesión (mismo valor interno de `lacre-core`, sin
/// reinterpretarlo como timestamp absoluto — el propio `ReceiptLog` no
/// conoce la hora de pared en la que arrancó, solo cuánto tiempo pasó
/// desde su propio `epoch`).
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptEntryWire {
    pub fragment_index: u64,
    pub receipt_hex: String,
    pub purged_at_ms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReceiptsResponse {
    pub session_id: String,
    pub entries: Vec<ReceiptEntryWire>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;

    fn sample_frame() -> (LacreFrame, Seal) {
        let session_id = SessionId([7u8; 16]);
        let frame = LacreFrame {
            session_id,
            index: 3,
            total_fragments: Some(5),
            is_last: false,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let seal = Seal([9u8; 32]);
        (frame, seal)
    }

    /// El round-trip frame → wire → frame debe ser exacto, campo por
    /// campo. Si esto falla, cualquier cosa construida encima (el
    /// servidor HTTP real) fallaría de forma mucho más difícil de
    /// diagnosticar.
    #[test]
    fn sealed_frame_wire_round_trips_exactly() {
        let (frame, seal) = sample_frame();
        let wire = SealedFrameWire::from_parts(&frame, &seal, None);

        let (decoded_frame, decoded_seal, decoded_sig) = wire.into_parts().unwrap();

        assert_eq!(decoded_frame, frame);
        assert_eq!(decoded_seal.0, seal.0);
        assert!(decoded_sig.is_none());
    }

    /// `vault_signature_hex` debe ser `None` cuando no se pasó firma —
    /// confirma que la ausencia de Vault no se codifica accidentalmente
    /// como un string vacío o "none" literal.
    #[test]
    fn sealed_frame_wire_omits_vault_signature_when_absent() {
        let (frame, seal) = sample_frame();
        let wire = SealedFrameWire::from_parts(&frame, &seal, None);
        assert!(wire.vault_signature_hex.is_none());

        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("\"vault_signature_hex\":null"));
    }

    /// session_id_from_hex debe rechazar, no rellenar ni truncar, un
    /// hex de longitud incorrecta — coherente con A4.
    #[test]
    fn session_id_from_hex_rejects_wrong_length() {
        assert!(session_id_from_hex("aabb").is_none()); // muy corto
        assert!(session_id_from_hex(&"aa".repeat(20)).is_none()); // muy largo
        assert!(session_id_from_hex("no es hex").is_none());
    }

    /// into_parts debe devolver un error específico y estable, no
    /// entrar en pánico, ante cada tipo de corrupción del cuerpo JSON —
    /// probado uno por uno para que un futuro cambio no colapse varios
    /// casos distintos en el mismo mensaje genérico.
    ///
    /// Usa `match` explícito en vez de `.unwrap_err()`: el tipo `Ok` de
    /// `into_parts` incluye `VaultSignature`, que deliberadamente no
    /// implementa `Debug` en `lacre-core` (no es más secreto que una
    /// firma pública, pero no hay motivo de negocio para agregarlo
    /// solo para que un test del Adaptador use `unwrap_err`) — no vale
    /// la pena tocar Fase 1 por la comodidad de un helper de test en
    /// Fase 3.
    #[test]
    fn into_parts_reports_specific_errors_for_malformed_wire_data() {
        fn expect_decode_err(
            result: Result<(LacreFrame, Seal, Option<VaultSignature>), WireDecodeError>,
            expected: WireDecodeError,
        ) {
            match result {
                Err(actual) => assert_eq!(actual, expected),
                Ok(_) => panic!("se esperaba WireDecodeError::{expected:?}, la decodificación tuvo éxito"),
            }
        }

        let (frame, seal) = sample_frame();

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.session_id = "zz".to_string();
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidSessionId);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.payload_hex = "no-hex-aqui".to_string();
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidPayloadHex);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.seal_hex = "aabb".to_string(); // hex válido, longitud incorrecta
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidSealLength);

        let mut wire = SealedFrameWire::from_parts(&frame, &seal, None);
        wire.vault_signature_hex = Some("aabb".to_string());
        expect_decode_err(wire.into_parts(), WireDecodeError::InvalidVaultSignatureLength);
    }

    /// Confirma que el algo de sello no se pierde en la traducción de
    /// ida y vuelta cuando se sella de verdad con hmac_seal — no solo
    /// con bytes de prueba arbitrarios como en `sample_frame`.
    #[test]
    fn round_trip_preserves_a_real_seal_computed_with_hmac_seal() {
        use lacre_core::hmac_seal::seal_fragment;
        use lacre_core::session::MasterKeyRing;
        use std::time::Duration;

        let session_id = SessionId([1u8; 16]);
        let frame = LacreFrame {
            session_id,
            index: 0,
            total_fragments: Some(1),
            is_last: true,
            payload: b"contenido real de prueba".to_vec(),
        };
        // Camino real de derivación de clave — no hay (ni debe haber)
        // ningún atajo que construya un SessionKey sin pasar por
        // MasterKeyRing::derive_for_sealing, que es el único punto
        // donde el HKDF con salt=session_id (8.4) realmente ocurre.
        let ring = MasterKeyRing::new(0, b"clave-de-prueba-para-este-test-32b".to_vec(), Duration::from_secs(60));
        let key = ring.derive_for_sealing(&session_id);
        let seal = seal_fragment(HmacAlgo::Sha256, &key, &frame.payload, b"estado-0");

        let wire = SealedFrameWire::from_parts(&frame, &seal, None);
        let (decoded_frame, decoded_seal, _) = wire.into_parts().unwrap();

        assert_eq!(decoded_frame.payload, frame.payload);
        assert_eq!(decoded_seal.0, seal.0);
    }
}
