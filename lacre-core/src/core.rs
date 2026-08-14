//! El Núcleo (Core) del protocolo Lacre — Capítulo 7.2 de Lacre Prime.
//!
//! Reemplaza a `engine.rs` + la mitad de `protocol.rs` de la iteración
//! anterior. Diferencia central respecto a esa iteración: **el Núcleo
//! fragmenta internamente**. El llamador entrega un payload completo
//! (`SealerCore::seal_payload`) o recibe frames ya delimitados por un
//! Adaptador de transporte (`VerifierCore::verify_frame`) — nunca
//! ensambla ni conoce el payload completo del lado verificador, porque
//! eso excede las tres responsabilidades exclusivas del Núcleo:
//! fragmentar, sellar/verificar, purgar (7.2).
//!
//! # Por qué el Núcleo no reensambla
//!
//! 8.1 es explícito: el reensamblado "no corresponde al Núcleo sino a
//! una capa de Profile específica". `VerifierCore::verify_frame` por
//! diseño no acumula fragmentos verificados ni retiene los que llegan
//! fuera de orden más allá de lo estrictamente necesario para
//! verificarlos en su turno — esa acumulación (`pending_ahead`,
//! `verified_payloads`, reensamblado) se movió a `profile.rs`
//! (`ReassembleProfile`). El Núcleo certifica "este fragmento, en esta
//! posición, es idéntico a lo que la fuente produjo" y nada más.
//!
//! # Sᵢ y Es(i)
//!
//! Ver razonamiento heredado de la iteración anterior de engine.rs: Sᵢ
//! (el valor que entra al HMAC) y Es(i) (el estado residual no
//! invertible, 8.5) son la misma variable — Es(i) hereda las garantías
//! del HMAC por construcción, en vez de ser una variable separada y
//! potencialmente más débil. Se implementa como HMAC encadenado
//! (Es(0) = HMAC(session_id ∥ contexto, k), Es(i) = HMAC(Es(i-1) ∥ fᵢ,
//! k)), una construcción estándar que resuelve el punto que 8.5 deja
//! como fórmula sin instanciar (σ, Wₑ, Wₓ sin especificar).

use crate::buffer::{BufferError, PendingBuffer};
use crate::frame::{FrameStateError, LacreFrame, SealerFrameState, VerifierFrameState};
use crate::hmac_seal::{seal_fragment, verify_fragment, HmacAlgo, Seal};
use crate::receipt::ReceiptLog;
use crate::session::{KeyId, MasterKeyRing, SessionId, SessionKey};
use crate::vault_signature::{VaultSignature, VaultSigningKey, VaultVerifyingKey};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const INITIAL_STATE_CONTEXT: &[u8] = b"lacre-core/v1/initial-state";
const STATE_LEN: usize = 32;

/// Es(i) — ver razonamiento en el comentario de cabecera. Sin
/// Debug/Display: es exactamente lo que un memory dump expondría, y no
/// debe terminar en un log.
#[derive(Clone, PartialEq, Eq)]
struct SessionState([u8; STATE_LEN]);

impl SessionState {
    fn initial(key: &SessionKey, session_id: &SessionId) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC acepta claves de cualquier longitud");
        mac.update(&session_id.0);
        mac.update(INITIAL_STATE_CONTEXT);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; STATE_LEN];
        out.copy_from_slice(&result);
        SessionState(out)
    }

    fn next(&self, key: &SessionKey, fragment: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
            .expect("HMAC acepta claves de cualquier longitud");
        mac.update(&self.0);
        mac.update(fragment);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; STATE_LEN];
        out.copy_from_slice(&result);
        SessionState(out)
    }
}

#[derive(Debug)]
pub enum CoreError {
    Buffer(BufferError),
    FrameState(FrameStateError),
    UnknownKeyId,
    SealMismatch,
    OutOfSequence { expected: u64, received: u64 },
    /// La sesión requiere firma Vault (resume_with_vault_key) y la
    /// firma recibida está ausente o no verifica bajo la clave pública
    /// del sellador.
    VaultSignatureMismatch,
}

impl From<BufferError> for CoreError {
    fn from(e: BufferError) -> Self {
        CoreError::Buffer(e)
    }
}

impl From<FrameStateError> for CoreError {
    fn from(e: FrameStateError) -> Self {
        CoreError::FrameState(e)
    }
}

/// Divide un payload en frames. Función libre, no método, porque tanto
/// `SealerCore::seal_payload` como (potencialmente) un Adaptador que
/// necesite pre-calcular cuántos frames resultarán de un payload la
/// usan sin necesitar una instancia del Núcleo.
fn split_into_frames(payload: &[u8], slot_size: usize) -> Vec<Vec<u8>> {
    if payload.is_empty() {
        return vec![Vec::new()];
    }
    payload.chunks(slot_size).map(|c| c.to_vec()).collect()
}

/// Lado sellador del Núcleo: fragmenta un payload completo, sella cada
/// frame resultante, y gestiona su ciclo de vida hasta `Purged`.
pub struct SealerCore {
    session_id: SessionId,
    algo: HmacAlgo,
    key_ring: Arc<MasterKeyRing>,
    state: SessionState,
    next_index: u64,
    buffer: PendingBuffer,
    frame_states: HashMap<u64, SealerFrameState>,
    /// Presente únicamente bajo el perfil Vault (15.3, 9.5). `None` en
    /// cualquier otro perfil: la firma asimétrica es una capacidad
    /// opcional del Núcleo, no una obligación de todos los perfiles —
    /// Lite y Core nunca la tocan.
    vault_key: Option<VaultSigningKey>,
    /// Recibo post-purga (7.5), también exclusivo de perfiles que lo
    /// requieran (Vault). `None` cuando no está habilitado — mismo
    /// patrón que `vault_key`.
    receipt_log: Option<ReceiptLog>,
}

impl SealerCore {
    pub fn open(
        key_ring: Arc<MasterKeyRing>,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Self {
        let session_id = SessionId::generate();
        let key = key_ring.derive_for_sealing(&session_id);
        let state = SessionState::initial(&key, &session_id);
        SealerCore {
            session_id,
            algo,
            key_ring,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            frame_states: HashMap::new(),
            vault_key: None,
            receipt_log: None,
        }
    }

    /// Igual que `open`, pero habilita la firma Ed25519 por fragmento
    /// (perfil Vault, 15.3) y el recibo post-purga (7.5). Ambas
    /// capacidades se activan juntas porque 7.5 vincula explícitamente
    /// el recibo a "perfiles que requieran capacidad de auditoría
    /// (véase el perfil Vault)" — no hay un perfil intermedio en el
    /// documento que tenga firma sin recibo o viceversa. Método
    /// separado de `open` por la misma razón que antes: no romper la
    /// firma de los perfiles que no usan Vault, y que "esto es una
    /// sesión Vault" sea visible en el sitio de la llamada.
    pub fn open_with_vault_key(
        key_ring: Arc<MasterKeyRing>,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultSigningKey,
    ) -> Self {
        let mut core = Self::open(key_ring, algo, slot_size, slot_count, forced_purge_timeout);
        core.vault_key = Some(vault_key);
        core.receipt_log = Some(ReceiptLog::new());
        core
    }

    /// Igual que `open`, pero acepta un `session_id` ya acordado desde
    /// afuera en vez de generar uno nuevo internamente.
    ///
    /// # Por qué existe (Fase 2, 8.4)
    ///
    /// 8.4 especifica `k_sesión = HKDF(secreto_compartido,
    /// salt=id_sesión, info="lacre-v1")` — el `session_id` participa
    /// como salt de la derivación de clave, lo cual significa que debe
    /// existir *antes* de poder derivar la clave (que `key_ring` ya
    /// hace internamente en `derive_for_sealing`). Cuando la clave
    /// maestra de `key_ring` proviene de un secreto Diffie-Hellman
    /// efímero (`session_handshake::EphemeralSharedSecret::
    /// into_ikm_bytes`, en vez de una clave maestra estática de
    /// despliegue), el `session_id` normalmente ya se negoció como
    /// parte de ese mismo handshake — un Adaptador (7.4) necesita que
    /// AMBAS partes converjan en el mismo `session_id` antes de que
    /// el verificador pueda derivar la misma clave con
    /// `VerifierCore::resume`, que ya aceptaba `session_id` como
    /// parámetro desde Fase 0/1. `open` (sin este método) rompía esa
    /// simetría: `resume` siempre aceptó un `session_id` externo,
    /// mientras que `open` siempre generaba el suyo. Este método
    /// cierra esa asimetría del lado sellador, sin cambiar la firma de
    /// `open` (mismo patrón que `open_with_vault_key`: método nuevo,
    /// no rotura de compatibilidad).
    ///
    /// # Lo que este método NO hace
    ///
    /// No ejecuta el handshake X25519 ni construye `key_ring` a partir
    /// de él — eso es responsabilidad de quien llama (un Adaptador,
    /// 7.4), usando `session_handshake::EphemeralHandshake` y pasando
    /// el resultado (`into_ikm_bytes()`) como `ikm` de
    /// `MasterKeyRing::new`. Este método solo evita que `open` pise el
    /// `session_id` ya acordado con uno nuevo generado internamente.
    pub fn open_with_session_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Self {
        let key = key_ring.derive_for_sealing(&session_id);
        let state = SessionState::initial(&key, &session_id);
        SealerCore {
            session_id,
            algo,
            key_ring,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            frame_states: HashMap::new(),
            vault_key: None,
            receipt_log: None,
        }
    }

    /// Igual que `open_with_session_key`, pero habilita además Vault
    /// (firma Ed25519 + recibo post-purga) — combinación de
    /// `open_with_session_key` y `open_with_vault_key`, para el caso
    /// de un despliegue que use X25519 (Fase 2) sobre el perfil Vault
    /// (Fase 1, 15.3) simultáneamente. Ningún perfil de despliegue
    /// documentado hasta ahora exige esta combinación, pero no hay
    /// razón textual en 8.4/9.5 para prohibirla — ambos mecanismos
    /// operan en capas distintas (establecimiento de clave vs. firma
    /// de no repudio sobre el sello ya calculado).
    pub fn open_with_session_key_and_vault_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultSigningKey,
    ) -> Self {
        let mut core = Self::open_with_session_key(
            key_ring,
            session_id,
            algo,
            slot_size,
            slot_count,
            forced_purge_timeout,
        );
        core.vault_key = Some(vault_key);
        core.receipt_log = Some(ReceiptLog::new());
        core
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Fragmenta `payload` internamente (conforme a 7.2 — el Núcleo
    /// fragmenta, el llamador no le entrega frames ya cortados) y sella
    /// cada fragmento resultante en orden. Devuelve la secuencia
    /// completa de `(LacreFrame, Seal)` lista para que un Adaptador la
    /// transporte.
    ///
    /// Para el caso de streaming continuo (9.3: tokens de LLM llegando
    /// uno por uno, sin conocer el total de antemano), esta función NO
    /// es la correcta — asume que `payload` es el contenido completo
    /// disponible en el momento de la llamada, y por tanto calcula
    /// `total_fragments`/`is_last` en base a ESA llamada, no al stream
    /// completo. Usar `seal_chunk` en su lugar para ese caso (ver su
    /// documentación para el porqué).
    pub fn seal_payload(
        &mut self,
        payload: &[u8],
        slot_size: usize,
    ) -> Result<Vec<(LacreFrame, Seal)>, CoreError> {
        let chunks = split_into_frames(payload, slot_size);
        let total = chunks.len() as u64;
        let mut out = Vec::with_capacity(chunks.len());

        for (i, chunk) in chunks.into_iter().enumerate() {
            let index = self.next_index + i as u64;
            let (frame, seal) = self.seal_one(chunk, index, Some(total), (i as u64) == total - 1)?;
            out.push((frame, seal));
        }
        self.next_index += total;
        Ok(out)
    }

    /// Sella un único fragmento cuyo contenido llega en el momento
    /// (streaming, 9.3) — sin asumir que se conoce el total de la
    /// secuencia. `is_last` lo decide explícitamente el llamador, que
    /// es quien sabe cuándo el stream terminó (por ejemplo, al recibir
    /// el token de fin de generación de un LLM); el Núcleo no puede
    /// inferirlo de un solo chunk aislado.
    ///
    /// A diferencia de `seal_payload`, no fragmenta — `chunk` se sella
    /// tal cual, entero, como un frame. Si `chunk` excede `slot_size`
    /// del perfil, la inserción en el buffer lo rechaza igual que
    /// cualquier otro exceso de tamaño (ver `buffer::BufferError`).
    pub fn seal_chunk(
        &mut self,
        chunk: Vec<u8>,
        is_last: bool,
    ) -> Result<(LacreFrame, Seal), CoreError> {
        let index = self.next_index;
        let result = self.seal_one(chunk, index, None, is_last)?;
        self.next_index += 1;
        Ok(result)
    }

    /// Lógica común de sellado de un único fragmento ya delimitado,
    /// compartida por `seal_payload` (que fragmenta primero) y
    /// `seal_chunk` (que recibe el fragmento ya hecho). No toca
    /// `self.next_index` — cada llamador lo actualiza a su propio ritmo
    /// (`seal_payload` de a lotes, `seal_chunk` de a uno).
    fn seal_one(
        &mut self,
        chunk: Vec<u8>,
        index: u64,
        total_fragments: Option<u64>,
        is_last: bool,
    ) -> Result<(LacreFrame, Seal), CoreError> {
        let key = self.key_ring.derive_for_sealing(&self.session_id);
        let seal = seal_fragment(self.algo, &key, &chunk, &self.state.0);

        self.buffer.insert(index, &chunk, seal)?;

        let entry = self
            .frame_states
            .entry(index)
            .or_insert(SealerFrameState::Raw);
        *entry = std::mem::replace(entry, SealerFrameState::Raw).seal(seal)?;

        self.state = self.state.next(&key, &chunk);

        let frame = LacreFrame {
            session_id: self.session_id,
            index,
            total_fragments,
            is_last,
            payload: chunk,
        };
        Ok((frame, seal))
    }

    /// Firma un `Seal` ya generado bajo la clave Ed25519 de esta
    /// sesión, si el perfil Vault fue habilitado (`open_with_vault_key`,
    /// no `open`). Devuelve `None` en cualquier otro perfil — llamar a
    /// esto sin clave Vault no es un error, simplemente no produce
    /// firma, porque no todo perfil la necesita.
    ///
    /// Método separado de `seal_one`/`seal_payload`/`seal_chunk` en vez
    /// de integrado en su firma de retorno, para no cambiar el tipo que
    /// devuelven esos métodos y así no romper ningún llamador existente
    /// que no usa Vault (46 tests de core.rs/profile.rs, entre otros).
    pub fn sign_seal_for_vault(&self, seal: &Seal) -> Option<VaultSignature> {
        self.vault_key.as_ref().map(|k| k.sign_seal(seal))
    }

    /// Registra el ACK de un frame por índice: purga su entrada del
    /// buffer y avanza su estado a `Committed → Purged`. Si el registro
    /// de recibos está habilitado (Vault), captura el recibo derivado
    /// del sello ANTES de purgarlo — el orden importa: el recibo debe
    /// generarse mientras el sello todavía existe en el buffer, y
    /// recién después el sello se destruye. Invertir el orden dejaría
    /// sin sello del que derivar el recibo.
    pub fn ack(&mut self, index: u64) -> Result<bool, CoreError> {
        if self.receipt_log.is_some() {
            if let Some(seal) = self.buffer.seal_of(index) {
                let seal = *seal;
                self.receipt_log
                    .as_mut()
                    .expect("ya confirmado Some arriba")
                    .record(index, &seal);
            }
        }
        let purged_from_buffer = self.buffer.purge_on_ack(index);
        if let Some(state) = self.frame_states.remove(&index) {
            let state = state.commit()?;
            let _ = state.purge()?;
        }
        Ok(purged_from_buffer)
    }

    /// Recibos registrados hasta el momento, si el perfil habilitó el
    /// registro (Vault). `None` en cualquier otro perfil.
    pub fn receipts(&self) -> Option<&[crate::receipt::ReceiptEntry]> {
        self.receipt_log.as_ref().map(|log| log.entries())
    }

    pub fn purge_expired(&mut self) -> u64 {
        self.buffer.purge_expired()
    }

    pub fn pending_count(&self) -> usize {
        self.buffer.pending_count()
    }
}

/// Lado verificador del Núcleo: verifica frames uno a uno, en el orden
/// estricto que Sᵢ exige. No acumula, no reensambla — eso es trabajo de
/// Profile (ver comentario de cabecera del módulo).
pub struct VerifierCore {
    session_id: SessionId,
    algo: HmacAlgo,
    key_ring: Arc<MasterKeyRing>,
    state: SessionState,
    next_index: u64,
    buffer: PendingBuffer,
    frame_states: HashMap<u64, VerifierFrameState>,
    /// Simétrico a `SealerCore::vault_key` — presente solo bajo Vault.
    vault_key: Option<VaultVerifyingKey>,
}

impl VerifierCore {
    /// Retoma una sesión conocida por su `session_id` (recibido de
    /// afuera, no generado acá — el verificador nunca origina una
    /// sesión) bajo el `key_id` con el que el sellador derivó Es(0).
    ///
    /// Nota de Fase 2 (8.4, X25519): este método ya aceptaba
    /// `session_id` como parámetro externo desde Fase 0/1 — a
    /// diferencia de `SealerCore::open`, que generaba el suyo
    /// internamente hasta que se agregó `open_with_session_key`. Para
    /// una sesión cuyo `key_ring` proviene de un secreto Diffie-Hellman
    /// efímero, `resume` no necesita ningún método nuevo: basta con
    /// pasarle el `session_id` que ambas partes ya acordaron durante el
    /// handshake (ver `session_handshake.rs`).
    pub fn resume(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
    ) -> Option<Self> {
        let key = key_ring.derive_for_verifying(key_id, &session_id)?;
        let state = SessionState::initial(&key, &session_id);
        Some(VerifierCore {
            session_id,
            algo,
            key_ring,
            state,
            next_index: 0,
            buffer: PendingBuffer::new(slot_size, slot_count, forced_purge_timeout),
            frame_states: HashMap::new(),
            vault_key: None,
        })
    }

    /// Igual que `resume`, pero habilita la verificación de firma
    /// Ed25519 (perfil Vault). `vault_key` es la clave PÚBLICA del
    /// sellador — se distribuye libremente, a diferencia de la clave
    /// privada que solo `SealerCore` conoce.
    pub fn resume_with_vault_key(
        key_ring: Arc<MasterKeyRing>,
        session_id: SessionId,
        key_id: KeyId,
        algo: HmacAlgo,
        slot_size: usize,
        slot_count: usize,
        forced_purge_timeout: Duration,
        vault_key: VaultVerifyingKey,
    ) -> Option<Self> {
        let mut core = Self::resume(
            key_ring,
            session_id,
            key_id,
            algo,
            slot_size,
            slot_count,
            forced_purge_timeout,
        )?;
        core.vault_key = Some(vault_key);
        Some(core)
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn next_expected_index(&self) -> u64 {
        self.next_index
    }

    /// Verifica un único frame contra su sello. Exige que
    /// `frame.index` sea exactamente el próximo esperado — un frame
    /// fuera de orden no puede verificarse (Sᵢ depende de la cadena
    /// completa hasta ahí); es responsabilidad de quien llama (un
    /// Profile) decidir qué hacer con un frame que llegó antes de
    /// tiempo, no de este método.
    ///
    /// # Verificación de firma Vault: parte del mismo flujo, no un paso
    /// aparte
    ///
    /// Si esta sesión se abrió con `resume_with_vault_key`, `verify_frame`
    /// EXIGE `vault_signature` y la rechaza si falta o no verifica —
    /// deliberadamente no es un método separado que el llamador podría
    /// olvidarse de invocar. Un `VerifierCore` sin clave Vault (`None`)
    /// ignora el parámetro `vault_signature` sin más: no tiene con qué
    /// verificar una firma, así que aceptar `None` ahí no debilita nada
    /// que no estuviera ya fuera de su alcance.
    pub fn verify_frame(
        &mut self,
        frame: &LacreFrame,
        key_id: KeyId,
        seal: &Seal,
        vault_signature: Option<&VaultSignature>,
    ) -> Result<(), CoreError> {
        if frame.index != self.next_index {
            return Err(CoreError::OutOfSequence {
                expected: self.next_index,
                received: frame.index,
            });
        }
        let key = self
            .key_ring
            .derive_for_verifying(key_id, &self.session_id)
            .ok_or(CoreError::UnknownKeyId)?;

        if !verify_fragment(self.algo, &key, &frame.payload, &self.state.0, seal) {
            return Err(CoreError::SealMismatch);
        }

        if let Some(vault_key) = &self.vault_key {
            match vault_signature {
                Some(sig) if vault_key.verify_seal(seal, sig) => {}
                _ => return Err(CoreError::VaultSignatureMismatch),
            }
        }

        self.buffer.insert(frame.index, &frame.payload, *seal)?;

        let state = VerifierFrameState::new().verify()?;
        self.frame_states.insert(frame.index, state);

        self.state = self.state.next(&key, &frame.payload);
        self.next_index += 1;

        // El Núcleo purga inmediatamente tras verificar: no espera un
        // ACK aparte del lado verificador, mismo razonamiento que ya
        // validamos en la iteración anterior del servidor — el frame
        // cumplió su propósito del lado verificador en cuanto se
        // certificó su integridad.
        self.buffer.purge_on_ack(frame.index);
        if let Some(state) = self.frame_states.remove(&frame.index) {
            if let Ok(purged) = state.purge() {
                self.frame_states.insert(frame.index, purged);
            }
        }

        Ok(())
    }

    pub fn purge_expired(&mut self) -> u64 {
        self.buffer.purge_expired()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"clave-maestra-de-prueba-minimo-32b".to_vec(),
            Duration::from_secs(60),
        ))
    }

    fn open_pair(
        ring: &Arc<MasterKeyRing>,
        slot_size: usize,
        slot_count: usize,
    ) -> (SealerCore, VerifierCore) {
        let sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            slot_size,
            slot_count,
            Duration::from_millis(500),
        );
        let verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            slot_size,
            slot_count,
            Duration::from_millis(500),
        )
        .unwrap();
        (sealer, verifier)
    }

    /// Fase 2 (8.4), flujo de punta a punta completo: dos partes
    /// ejecutan un handshake X25519 efímero real, cada una construye su
    /// propio `MasterKeyRing` a partir del secreto DH crudo (sin pasar
    /// por ningún HKDF adicional — `MasterKeyRing::derive_for_sealing`/
    /// `derive_for_verifying` son el único HKDF, tal como pide 8.4:
    /// "HKDF(secreto_compartido, salt=id_sesión, info=...)"), acuerdan
    /// el mismo `session_id`, y sellan/verifican un fragmento real.
    ///
    /// Esto es lo que ninguno de los dos tramos anteriores de esta fase
    /// pudo probar (no tenían `session.rs` real ni podían compilar) — es
    /// la primera verificación de integración real de Fase 2, cerrando
    /// exactamente el punto 5 de la sección "Punto exacto donde Claude A
    /// debe retomar" de INFORME_FASE2_TRAMO2.md.
    #[test]
    fn end_to_end_x25519_handshake_feeds_master_key_ring_and_seals_verifies() {
        use crate::session_handshake::EphemeralHandshake;

        // Paso 1 de 8.4: intercambio Diffie-Hellman efímero. Cada parte
        // genera su propio par y solo intercambia la mitad pública.
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();
        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_secret = alice.complete(bob_public);
        let bob_secret = bob.complete(alice_public);

        // El session_id se negocia (en un Adaptador real, viajaría
        // junto con la clave pública en el primer mensaje del
        // handshake) ANTES de construir el ring, porque 8.4 lo exige
        // como salt de la derivación.
        let session_id = SessionId::generate();

        // Cada lado construye su propio MasterKeyRing a partir del
        // secreto DH crudo — MasterKeyRing::new no aplica ningún HKDF
        // por sí mismo, solo lo hace derive_for_sealing/
        // derive_for_verifying cuando se les pide una clave de sesión.
        let sealer_ring = Arc::new(MasterKeyRing::new(
            0,
            alice_secret.into_ikm_bytes().to_vec(),
            Duration::from_secs(60),
        ));
        let verifier_ring = Arc::new(MasterKeyRing::new(
            0,
            bob_secret.into_ikm_bytes().to_vec(),
            Duration::from_secs(60),
        ));

        let mut sealer = SealerCore::open_with_session_key(
            sealer_ring,
            session_id,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        );
        let mut verifier = VerifierCore::resume(
            verifier_ring,
            session_id,
            0,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        )
        .expect("ambos lados derivaron el mismo ikm del mismo secreto DH y el mismo session_id");

        let sealed = sealer
            .seal_payload(b"fragmento sellado bajo clave X25519 efimera", 64)
            .unwrap();
        for (frame, seal) in &sealed {
            verifier
                .verify_frame(frame, 0, seal, None)
                .expect("un fragmento sellado con la clave derivada del secreto DH compartido debe verificar bajo la misma clave derivada del otro lado");
        }
    }

    /// Confirma, de forma aislada del resto del flujo, que dos
    /// `MasterKeyRing` construidos a partir de secretos DH DISTINTOS
    /// (dos handshakes independientes, sin relación entre sí) producen
    /// claves de sesión que NO coinciden — para que el test de arriba
    /// no pase "por accidente" si `into_ikm_bytes` estuviera devolviendo
    /// siempre el mismo valor por algún error de implementación.
    #[test]
    fn different_x25519_handshakes_yield_different_session_keys_via_master_key_ring() {
        use crate::session_handshake::EphemeralHandshake;

        let alice1 = EphemeralHandshake::generate();
        let bob1 = EphemeralHandshake::generate();
        let secret1 = alice1.complete(bob1.public_key());

        let alice2 = EphemeralHandshake::generate();
        let bob2 = EphemeralHandshake::generate();
        let secret2 = alice2.complete(bob2.public_key());

        let session_id = SessionId::generate();
        let ring1 = MasterKeyRing::new(0, secret1.into_ikm_bytes().to_vec(), Duration::from_secs(60));
        let ring2 = MasterKeyRing::new(0, secret2.into_ikm_bytes().to_vec(), Duration::from_secs(60));

        let key1 = ring1.derive_for_sealing(&session_id);
        let key2 = ring2.derive_for_sealing(&session_id);

        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    /// `open_with_session_key` debe usar EXACTAMENTE el `session_id`
    /// que se le pasa, no generar uno nuevo por su cuenta — es la
    /// propiedad puntual que motiva la existencia de este método sobre
    /// `open` (que sí genera uno internamente). Se prueba aislada del
    /// resto del flujo X25519 para que un futuro cambio no pueda
    /// "acertar por casualidad" mezclando session_ids en el camino.
    #[test]
    fn open_with_session_key_uses_the_provided_session_id_verbatim() {
        let ring = test_ring();
        let forced_session_id = SessionId::generate();
        let sealer = SealerCore::open_with_session_key(
            ring,
            forced_session_id,
            HmacAlgo::Sha256,
            64,
            10,
            Duration::from_millis(500),
        );
        assert_eq!(sealer.session_id(), forced_session_id);
    }

    /// El Núcleo fragmenta internamente: seal_payload recibe el
    /// payload completo, no frames ya cortados (7.2).
    #[test]
    fn seal_payload_fragments_internally() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 10, 100, Duration::from_millis(500));
        let payload = b"0123456789abcdef0123456789"; // 27 bytes
        let sealed = sealer.seal_payload(payload, 10).unwrap();

        assert_eq!(sealed.len(), 3); // 10 + 10 + 7
        assert_eq!(sealed[0].0.payload, b"0123456789");
        assert!(!sealed[0].0.is_last);
        assert!(sealed[2].0.is_last);
        assert!(sealed.iter().all(|(f, _)| f.total_fragments == Some(3)));
    }

    /// Flujo de punta a punta: sellar un payload completo, verificar
    /// cada frame en orden a través del Núcleo. El Núcleo no
    /// reensambla — eso se confirma en protocol/profile, no acá.
    #[test]
    fn end_to_end_seal_and_verify_all_frames() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"el zorro veloz salta sobre el perro perezoso";
        let sealed = sealer.seal_payload(payload, 8).unwrap();

        for (frame, seal) in &sealed {
            let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
            assert!(result.is_ok(), "frame {} debe verificar", frame.index);
        }
        assert_eq!(verifier.next_expected_index(), sealed.len() as u64);
    }

    /// Prueba de integridad heredada del documento: fragmento alterado
    /// tras sellarse debe fallar la verificación en el Núcleo.
    #[test]
    fn tampered_frame_fails_verification() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"contenido original intacto";
        let sealed = sealer.seal_payload(payload, 8).unwrap();
        let (mut frame, seal) = sealed[0].clone();
        frame.payload[0] ^= 0x01;

        let result = verifier.verify_frame(&frame, ring.active_key_id(), &seal, None);
        assert!(matches!(result, Err(CoreError::SealMismatch)));
    }

    /// Un frame fuera de orden se rechaza en el Núcleo antes de tocar
    /// el HMAC — decidir qué hacer con él (retenerlo, descartarlo)
    /// queda fuera del Núcleo, es responsabilidad del llamador.
    #[test]
    fn out_of_order_frame_is_rejected_by_core() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let payload = b"fragmento uno fragmento dos fragmento tres";
        let sealed = sealer.seal_payload(payload, 8).unwrap();
        assert!(sealed.len() >= 2);

        let (frame1, seal1) = &sealed[1];
        let result = verifier.verify_frame(frame1, ring.active_key_id(), seal1, None);
        assert!(matches!(
            result,
            Err(CoreError::OutOfSequence {
                expected: 0,
                received: 1
            })
        ));
    }

    #[test]
    fn verifier_resume_with_unknown_key_id_returns_none() {
        let ring = test_ring();
        let session_id = SessionId::generate();
        let result = VerifierCore::resume(
            ring,
            session_id,
            99,
            HmacAlgo::Sha256,
            1024,
            8,
            Duration::from_millis(500),
        );
        assert!(result.is_none());
    }

    /// ACK del lado sellador purga el buffer y avanza el estado del
    /// frame a Purged sin afectar Es(i). Payload de exactamente 8 bytes
    /// con slot_size=8 para producir un único frame — un payload más
    /// largo (p. ej. 9 bytes) produciría dos frames y el ACK de uno
    /// solo dejaría pending_count() en 1, no 0 (encontrado al correr
    /// este test con b"fragmento", 9 bytes, que sí generaba 2 frames).
    #[test]
    fn sealer_ack_purges_frame() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Blake3, 8, 100, Duration::from_millis(500));
        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        assert_eq!(sealed.len(), 1, "el payload de prueba debe producir un único frame");
        let index = sealed[0].0.index;

        let purged = sealer.ack(index).unwrap();
        assert!(purged);
        assert_eq!(sealer.pending_count(), 0);
    }

    /// Dos llamadas sucesivas a seal_payload en la misma sesión deben
    /// continuar la numeración de índices donde quedó la anterior, no
    /// reiniciar desde 0 — la sesión es continua aunque el payload se
    /// entregue en más de una llamada.
    #[test]
    fn successive_seal_payload_calls_continue_index_sequence() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 8, 100, Duration::from_millis(500));

        let first = sealer.seal_payload(b"12345678", 8).unwrap();
        assert_eq!(first[0].0.index, 0);

        let second = sealer.seal_payload(b"abcdefgh", 8).unwrap();
        assert_eq!(second[0].0.index, 1);
    }

    /// Streaming (9.3 del documento Lacre Prime): tokens llegando uno a
    /// uno, cada uno sellado por separado porque el emisor no tiene el
    /// contenido completo de antemano. Usa `seal_chunk`, no
    /// `seal_payload` — la primera versión de este test intentaba
    /// simular streaming llamando a `seal_payload` una vez por token, y
    /// encontró que esa función marcaba cada token como `is_last: true`
    /// e `total_fragments: Some(1)`, porque calculaba ambos a partir
    /// del conteo de ESA llamada individual, no del stream completo.
    /// `seal_chunk` corrige esto: no infiere nada, el llamador decide
    /// `is_last` explícitamente y `total_fragments` queda en `None`
    /// hasta que se sepa.
    #[test]
    fn streaming_tokens_are_not_falsely_marked_as_last() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 64, 100, Duration::from_millis(500));

        let (frame1, _) = sealer.seal_chunk(b"El".to_vec(), false).unwrap();
        let (frame2, _) = sealer.seal_chunk(b" cielo".to_vec(), false).unwrap();
        let (frame3, _) = sealer.seal_chunk(b" es azul".to_vec(), true).unwrap();

        assert!(!frame1.is_last);
        assert!(frame1.total_fragments.is_none());
        assert!(!frame2.is_last);
        assert!(frame3.is_last);

        // Los índices deben ser consecutivos, igual que con seal_payload.
        assert_eq!(frame1.index, 0);
        assert_eq!(frame2.index, 1);
        assert_eq!(frame3.index, 2);
    }

    /// seal_chunk y seal_payload comparten la misma secuencia de
    /// índices dentro de una sesión — mezclar ambas formas de llamada
    /// (por ejemplo, un payload inicial conocido seguido de streaming)
    /// no debe reiniciar ni duplicar índices.
    #[test]
    fn seal_chunk_and_seal_payload_share_index_sequence() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 64, 100, Duration::from_millis(500));

        let batch = sealer.seal_payload(b"encabezado", 64).unwrap();
        assert_eq!(batch[0].0.index, 0);

        let (chunk_frame, _) = sealer.seal_chunk(b"resto en streaming".to_vec(), true).unwrap();
        assert_eq!(chunk_frame.index, 1);
    }

    /// Flujo de streaming de punta a punta: el sellador emite tokens
    /// uno por uno con seal_chunk (sin conocer el total de antemano),
    /// el Núcleo verificador los certifica en orden. La confirmación de
    /// que "el payload no se da por completo antes de is_last" se
    /// prueba en profile.rs (ReassembleProfile), que es quien realmente
    /// decide cuándo reensamblar — acá solo se confirma que el Núcleo
    /// deja pasar la secuencia completa de tokens sin objeciones.
    #[test]
    fn end_to_end_streaming_seal_verify() {
        let ring = test_ring();
        let mut sealer = SealerCore::open(
            ring.clone(),
            HmacAlgo::Sha256,
            64,
            100,
            Duration::from_millis(500),
        );
        let mut verifier = VerifierCore::resume(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            64,
            100,
            Duration::from_millis(500),
        )
        .unwrap();

        let tokens: [(&[u8], bool); 3] = [(b"El", false), (b" cielo", false), (b" es azul", true)];

        for (bytes, is_last) in tokens {
            let (frame, seal) = sealer.seal_chunk(bytes.to_vec(), is_last).unwrap();
            verifier
                .verify_frame(&frame, ring.active_key_id(), &seal, None)
                .expect("cada token debe verificar en su turno, streaming o no");
        }

        assert_eq!(verifier.next_expected_index(), 3);
    }

    /// Flujo Vault de punta a punta: sellador con clave privada Ed25519
    /// (open_with_vault_key), verificador con la clave pública
    /// correspondiente (resume_with_vault_key). La firma viaja como
    /// tercer elemento junto al Seal — no dentro de LacreFrame, mismo
    /// criterio que ya aplicamos al propio Seal (A2: el sello vive en
    /// cabecera, aparte de la identidad del frame).
    #[test]
    fn end_to_end_vault_seal_sign_verify() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_verifying_key,
        )
        .unwrap();

        let sealed = sealer
            .seal_payload(b"transaccion financiera de prueba", 8)
            .unwrap();

        for (frame, seal) in &sealed {
            let vault_sig = sealer
                .sign_seal_for_vault(seal)
                .expect("sealer abierto con open_with_vault_key debe producir firma");
            verifier
                .verify_frame(frame, ring.active_key_id(), seal, Some(&vault_sig))
                .expect("frame con HMAC y firma Vault válidos debe verificar");
        }
    }

    /// Requisito de seguridad central de esta implementación (no
    /// especificado explícitamente por el documento, pero necesario
    /// para que Vault tenga sentido: ver comentario de verify_frame):
    /// una sesión Vault DEBE rechazar un frame que llega sin firma,
    /// aunque el HMAC sea perfectamente válido. Si esto no se cumpliera,
    /// Vault sería indistinguible de Core en la práctica — cualquiera
    /// podría omitir la firma y el frame pasaría igual.
    #[test]
    fn vault_session_rejects_frame_without_signature() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();
        let vault_verifying_key = vault_signing_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_verifying_key,
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];

        // El HMAC es válido (no se alteró nada); el fallo debe venir
        // exclusivamente de la firma Vault ausente.
        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
        assert!(matches!(
            result,
            Err(CoreError::VaultSignatureMismatch)
        ));
    }

    /// Una firma Vault de una clave distinta a la que el verificador
    /// espera también debe rechazarse — no repudio real, no solo
    /// "presencia de alguna firma".
    #[test]
    fn vault_session_rejects_signature_from_wrong_key() {
        let ring = test_ring();
        let legitimate_key = VaultSigningKey::generate();
        let attacker_key = VaultSigningKey::generate();
        let legitimate_verifying_key = legitimate_key.verifying_key();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            attacker_key, // el sellador firma con la clave "equivocada"
        );
        let mut verifier = VerifierCore::resume_with_vault_key(
            ring.clone(),
            sealer.session_id(),
            ring.active_key_id(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            legitimate_verifying_key,
        )
        .unwrap();

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];
        let signature = sealer.sign_seal_for_vault(seal).unwrap();

        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, Some(&signature));
        assert!(matches!(
            result,
            Err(CoreError::VaultSignatureMismatch)
        ));
    }

    /// Confirma que una sesión SIN clave Vault (open/resume normales)
    /// sigue funcionando exactamente igual que antes de introducir
    /// Vault — la capacidad es genuinamente opcional, no un cambio de
    /// comportamiento por defecto.
    #[test]
    fn non_vault_session_ignores_absent_signature_without_error() {
        let ring = test_ring();
        let (mut sealer, mut verifier) = open_pair(&ring, 8, 100);

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let (frame, seal) = &sealed[0];

        let result = verifier.verify_frame(frame, ring.active_key_id(), seal, None);
        assert!(result.is_ok());
    }

    /// Confirma el requisito de 7.5 de punta a punta: el recibo se
    /// genera en el momento de la purga (ack), y sigue disponible
    /// DESPUÉS de que el fragmento y su sello ya no existen en el
    /// buffer — es justamente la propiedad que 7.5 pide ("se conserva
    /// ... tras la purga del fragmento y su sello original").
    #[test]
    fn receipt_survives_purge_of_original_fragment_and_seal() {
        let ring = test_ring();
        let vault_signing_key = VaultSigningKey::generate();

        let mut sealer = SealerCore::open_with_vault_key(
            ring.clone(),
            HmacAlgo::Sha256,
            8,
            100,
            Duration::from_millis(500),
            vault_signing_key,
        );

        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        let index = sealed[0].0.index;

        assert_eq!(sealer.pending_count(), 1, "el frame debe estar pendiente antes del ack");
        assert!(sealer.receipts().unwrap().is_empty(), "aún no hay recibo antes del ack");

        sealer.ack(index).unwrap();

        // El fragmento y su sello ya no están en el buffer...
        assert_eq!(sealer.pending_count(), 0);
        // ...pero el recibo sí sobrevivió a esa purga.
        let receipts = sealer.receipts().expect("Vault debe tener receipt_log habilitado");
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].fragment_index, index);
    }

    /// Una sesión sin Vault no lleva registro de recibos — la capacidad
    /// es opcional, igual que la firma.
    #[test]
    fn non_vault_session_has_no_receipt_log() {
        let ring = test_ring();
        let mut sealer =
            SealerCore::open(ring, HmacAlgo::Sha256, 8, 100, Duration::from_millis(500));
        let sealed = sealer.seal_payload(b"12345678", 8).unwrap();
        sealer.ack(sealed[0].0.index).unwrap();

        assert!(sealer.receipts().is_none());
    }
}
