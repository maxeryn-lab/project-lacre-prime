//! Dónde vive un `SealerCore` de una sesión Vault entre el momento en
//! que `POST /v1/seal` lo crea y el momento en que `POST /v1/ack` lo
//! usa para registrar recibos post-purga (7.5) y purgar el buffer.
//!
//! # Por qué esto existe, y por qué NO es un `trait` como `SessionStore`
//!
//! `VerifierCore::resume` es determinista: dado `(key_ring,
//! session_id, key_id)`, cualquier instancia reconstruida es
//! equivalente — por eso `handle_verify` nunca necesitó persistir un
//! `VerifierCore` entre requests (ver comentario de cabecera de
//! `http_server.rs`). `SealerCore::ack` no tiene ese lujo: acumula
//! estado real (el `ReceiptLog`, qué índices ya se purgaron del
//! buffer) que no puede reconstruirse desde cero — es, literalmente,
//! lo que 7.5 describe como "un registro de solo adición" que debe
//! seguir siendo el mismo registro entre un `record()` y el siguiente,
//! no una copia nueva cada vez.
//!
//! `session_store.rs` (Etapa 15) se justificó como `trait
//! SessionStore` porque tenía DOS usos reales simultáneos (ring fijo +
//! ring de handshake, ver DECISIONS.md punto 17). Este módulo tiene
//! exactamente UN uso real hoy: `SealerCore` de sesiones Vault entre
//! `seal` y `ack`. Aplicando la misma regla con honestidad, un solo
//! uso no justifica extraer una interfaz todavía — se implementa
//! directamente como `Mutex<HashMap<...>>`, sin trait. Si en el futuro
//! aparece un segundo uso real de "selladores vivos de servidor" (por
//! ejemplo, para la variante de streaming ya anotada en PENDING.md),
//! ahí se evalúa si conviene generalizar, no antes.
//!
//! # Alcance: exclusivo de Vault
//!
//! 7.5 vincula el recibo post-purga al perfil que "requiera capacidad
//! de auditoría posterior a la purga (véase el perfil Vault)" — no es
//! una capacidad general que Core deba heredar. Este módulo, en
//! consecuencia, solo se usa cuando `ProfileName::requires_vault_signature()`
//! es verdadero; el perfil Core sigue sin persistir nada entre
//! `POST /v1/seal` y ninguna otra request.

use lacre_core::core::SealerCore;
use lacre_core::session::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct StoredSealer {
    sealer: SealerCore,
    inserted_at: Instant,
}

/// TTL fijo, purga explícita — mismo criterio que
/// `InMemorySessionStore` (session_store.rs) y que
/// `PendingBuffer::purge_expired` en `lacre-core/buffer.rs`: la purga
/// nunca ocurre implícitamente dentro de `insert`/`with_sealer`, se
/// invoca aparte para no penalizar el camino caliente de cada request.
pub struct SealerSessionStore {
    entries: Mutex<HashMap<[u8; 16], StoredSealer>>,
    ttl: Duration,
}

/// Resultado de intentar operar sobre un `SealerCore` guardado.
#[derive(Debug)]
pub enum WithSealerError {
    /// No hay ningún `SealerCore` vivo bajo ese `session_id` — nunca se
    /// selló nada bajo Vault con ese id, o ya se purgó por TTL, o ya
    /// se removió explícitamente (ver `remove`).
    NotFound,
}

impl SealerSessionStore {
    pub fn new(ttl: Duration) -> Self {
        SealerSessionStore {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    /// Guarda un `SealerCore` recién creado por `POST /v1/seal` bajo
    /// Vault. Si ya existía uno con el mismo `session_id`, lo
    /// reemplaza — mismo criterio que `SessionStore::insert`.
    pub fn insert(&self, session_id: SessionId, sealer: SealerCore) {
        let mut guard = self.entries.lock().expect("mutex de selladores envenenado");
        guard.insert(
            session_id.0,
            StoredSealer {
                sealer,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Ejecuta `f` sobre el `SealerCore` guardado bajo `session_id`,
    /// con acceso mutable — necesario porque `SealerCore::ack` exige
    /// `&mut self`. Se usa un closure en vez de exponer un guard de
    /// `MutexGuard` directamente para que el `Mutex` interno nunca
    /// quede prestado más tiempo del estrictamente necesario (el mismo
    /// motivo por el que `InMemorySessionStore::get` devuelve un
    /// `Arc` clonado en vez de un guard).
    ///
    /// Una sesión expirada por TTL se trata igual que una inexistente
    /// (`NotFound`), sin distinguir el caso — un cliente que intenta
    /// confirmar un ACK demasiado tarde no tiene, de todas formas,
    /// ningún recibo válido que registrar: el buffer del lado servidor
    /// ya habría purgado esos frames por su propio timeout de purga
    /// forzada mucho antes de que el `SealerSessionStore` los
    /// descartara por TTL (el TTL de este store es deliberadamente más
    /// holgado que `forced_purge_timeout` del perfil, para dar margen
    /// a que el cliente complete su propio procesamiento antes de
    /// confirmar).
    pub fn with_sealer<T>(
        &self,
        session_id: &SessionId,
        f: impl FnOnce(&mut SealerCore) -> T,
    ) -> Result<T, WithSealerError> {
        let mut guard = self.entries.lock().expect("mutex de selladores envenenado");
        let entry = guard.get_mut(&session_id.0).ok_or(WithSealerError::NotFound)?;
        if entry.inserted_at.elapsed() > self.ttl {
            guard.remove(&session_id.0);
            return Err(WithSealerError::NotFound);
        }
        Ok(f(&mut entry.sealer))
    }

    /// Purga las entradas cuyo TTL venció. Invocación explícita, igual
    /// que `InMemorySessionStore::purge_expired`.
    pub fn purge_expired(&self) -> usize {
        let mut guard = self.entries.lock().expect("mutex de selladores envenenado");
        let before = guard.len();
        guard.retain(|_, entry| entry.inserted_at.elapsed() <= self.ttl);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lacre_core::hmac_seal::HmacAlgo;
    use lacre_core::session::MasterKeyRing;
    use lacre_core::vault_signature::VaultSigningKey;
    use std::sync::Arc;

    fn dummy_sealer() -> (SealerCore, SessionId) {
        let ring = Arc::new(MasterKeyRing::new(
            0,
            b"clave-de-prueba-para-sealer-store-32b".to_vec(),
            Duration::from_secs(60),
        ));
        let sealer = SealerCore::open_with_vault_key(
            ring,
            HmacAlgo::Sha256,
            256 * 1024,
            64,
            Duration::from_secs(5),
            VaultSigningKey::generate(),
        );
        let session_id = sealer.session_id();
        (sealer, session_id)
    }

    #[test]
    fn insert_then_with_sealer_can_operate_on_the_same_instance() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let (sealer, session_id) = dummy_sealer();
        store.insert(session_id, sealer);

        let pending_before = store
            .with_sealer(&session_id, |s| s.pending_count())
            .unwrap();
        assert_eq!(pending_before, 0);
    }

    #[test]
    fn with_sealer_returns_not_found_for_unknown_session_id() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let unknown = SessionId::generate();
        let result = store.with_sealer(&unknown, |_| ());
        assert!(matches!(result, Err(WithSealerError::NotFound)));
    }

    /// El caso central: sellar un fragmento, guardarlo, luego llamar
    /// `ack()` a través del store, y confirmar que el recibo quedó
    /// registrado — no solo que el closure se ejecutó, sino que el
    /// EFECTO de `ack()` (poblar el `ReceiptLog`) persiste en la misma
    /// instancia entre dos llamadas separadas a `with_sealer`.
    #[test]
    fn ack_through_with_sealer_records_a_receipt_that_persists_across_calls() {
        let store = SealerSessionStore::new(Duration::from_secs(60));
        let (mut sealer, session_id) = dummy_sealer();
        let sealed = sealer.seal_payload(b"contenido de prueba", 256 * 1024).unwrap();
        let index = sealed[0].0.index;
        store.insert(session_id, sealer);

        // Primera llamada: ack() real.
        let ack_result = store
            .with_sealer(&session_id, |s| s.ack(index))
            .unwrap()
            .unwrap();
        assert!(ack_result, "ack() debe reportar que purgó el frame del buffer");

        // Segunda llamada, instancia separada de with_sealer: el
        // recibo debe seguir presente en el MISMO SealerCore.
        let receipt_count = store
            .with_sealer(&session_id, |s| s.receipts().map(|r| r.len()).unwrap_or(0))
            .unwrap();
        assert_eq!(receipt_count, 1);
    }

    #[test]
    fn expired_entry_is_treated_as_not_found() {
        let store = SealerSessionStore::new(Duration::from_millis(20));
        let (sealer, session_id) = dummy_sealer();
        store.insert(session_id, sealer);

        std::thread::sleep(Duration::from_millis(40));

        let result = store.with_sealer(&session_id, |_| ());
        assert!(matches!(result, Err(WithSealerError::NotFound)));
    }

    #[test]
    fn purge_expired_removes_only_expired_entries() {
        let store = SealerSessionStore::new(Duration::from_millis(20));
        let (stale_sealer, stale_id) = dummy_sealer();
        store.insert(stale_id, stale_sealer);
        std::thread::sleep(Duration::from_millis(40));

        let (fresh_sealer, fresh_id) = dummy_sealer();
        store.insert(fresh_id, fresh_sealer);

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert!(matches!(
            store.with_sealer(&stale_id, |_| ()),
            Err(WithSealerError::NotFound)
        ));
        assert!(store.with_sealer(&fresh_id, |_| ()).is_ok());
    }
}
