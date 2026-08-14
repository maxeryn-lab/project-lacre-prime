//! Dónde vive un `MasterKeyRing` derivado de un handshake, entre el
//! momento en que se completa (`POST /v1/handshake`) y el momento en
//! que se usa (`POST /v1/seal`/`POST /v1/verify` de una sesión con
//! `session_id` acordado por handshake, en vez de la clave estática
//! `LACRE_MASTER_KEY`).
//!
//! # Por qué existe este módulo, y por qué es tan chico
//!
//! Surge de una observación del usuario, no de especulación propia:
//! si Núcleo/Profile/Adaptador ya están separados (7.1/7.4,
//! DECISIONS.md punto 16), "dónde persiste el estado de sesión entre
//! dos requests HTTP separados" es, por la misma lógica, una decisión
//! de *este* Adaptador concreto — nunca del protocolo Lacre en
//! general. `session_handshake.rs` (Fase 2, `lacre-core`) ya es
//! agnóstico de esto: produce un `EphemeralSharedSecret` y no le
//! importa qué se hace con él después. Lo único que faltaba era la
//! costura explícita en el Adaptador.
//!
//! Esto NO es un `trait Transport` especulativo con métodos para
//! backends que no existen todavía (Redis, etc.) — es la interfaz
//! MÍNIMA que hoy ya tiene DOS usos reales simultáneos en
//! `http_server.rs`: el ring fijo cargado al arrancar (que pasa a
//! tratarse como "una sesión pre-sembrada más") y el ring nuevo que
//! produce cada handshake completado. Dos usos reales es la señal
//! correcta para extraer una interfaz — no una anticipación de un
//! tercer Adaptador hipotético.
//!
//! # Qué implementación se usa en esta primera vuelta
//!
//! `InMemorySessionStore`: un `HashMap` protegido por `Mutex`
//! (`http_server.rs` ya corre sobre tokio multi-hilo), con purga
//! explícita por timeout — mismo criterio que `PendingBuffer::
//! purge_expired` en `lacre-core/src/buffer.rs`: un método invocado
//! desde fuera, no un hilo de fondo implícito, para no penalizar el
//! camino caliente de cada request con trabajo de limpieza que no le
//! corresponde. Suficiente para un solo proceso; un Adaptador
//! distribuido (varias instancias de `lacre-server` detrás de un
//! balanceador) necesitaría una implementación distinta (Redis u
//! otro almacén compartido) — implementando el mismo `trait
//! SessionStore`, sin tocar `http_adapter.rs`, `http_server.rs` (más
//! allá de qué implementación se inyecta), ni `lacre-core` en
//! absoluto.

use lacre_core::session::{MasterKeyRing, SessionId};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Contrato mínimo que un Adaptador HTTP necesita de un almacén de
/// sesiones derivadas de handshake. Tres operaciones, ninguna más: si
/// un futuro backend necesitara algo adicional (por ejemplo,
/// enumerar todas las sesiones activas), se agrega cuando exista esa
/// necesidad real, no antes.
pub trait SessionStore: Send + Sync {
    /// Registra el ring resultante de un handshake bajo `session_id`.
    /// Si ya existía una entrada para ese `session_id`, la reemplaza
    /// — un `session_id` no debería reutilizarse entre handshakes
    /// distintos (`SessionId::generate()` usa un CSPRNG, ver
    /// `session.rs`), pero este trait no impone esa garantía: es
    /// responsabilidad del generador de `session_id`, no del
    /// almacén.
    fn insert(&self, session_id: SessionId, ring: Arc<MasterKeyRing>);

    /// Recupera el ring de una sesión, si existe y no expiró.
    fn get(&self, session_id: &SessionId) -> Option<Arc<MasterKeyRing>>;

    /// Purga las sesiones cuyo TTL ya venció. Se invoca explícitamente
    /// (por ejemplo, antes de atender un request, o desde una tarea
    /// periódica) — nunca de forma implícita en `insert`/`get`, mismo
    /// criterio que `PendingBuffer::purge_expired` en `lacre-core`.
    /// Devuelve cuántas entradas se purgaron, solo para observabilidad
    /// de tests/logs.
    fn purge_expired(&self) -> usize;
}

struct StoredEntry {
    ring: Arc<MasterKeyRing>,
    inserted_at: Instant,
}

/// Implementación en memoria de `SessionStore`, con TTL fijo por
/// instancia — suficiente para un único proceso de `lacre-server`. No
/// sobrevive un reinicio del proceso: una sesión de handshake
/// interrumpida por un reinicio del servidor debe rehacerse desde
/// cero, coherente con A4 (fallo cerrado) — no hay ningún intento de
/// "recuperar" un secreto DH efímero tras perderlo, porque intentarlo
/// violaría la propia noción de "efímero".
///
/// Internamente, la clave del `HashMap` son los bytes crudos de
/// `SessionId` (`[u8; 16]`), no `SessionId` directamente — `SessionId`
/// no implementa `Hash` en `lacre-core` (solo `Debug, Clone, Copy,
/// PartialEq, Eq`), y no corresponde agregarlo ahí solo por la
/// conveniencia de este módulo de Fase 3: tocar un tipo de Fase 1/2 por
/// una necesidad de un Adaptador concreto invertiría la dirección de
/// dependencia que el proyecto sostiene desde el principio (Núcleo no
/// se ajusta a sus consumidores).
pub struct InMemorySessionStore {
    entries: Mutex<HashMap<[u8; 16], StoredEntry>>,
    ttl: Duration,
}

impl InMemorySessionStore {
    pub fn new(ttl: Duration) -> Self {
        InMemorySessionStore {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn insert(&self, session_id: SessionId, ring: Arc<MasterKeyRing>) {
        let mut guard = self.entries.lock().expect("mutex de sesiones envenenado");
        guard.insert(
            session_id.0,
            StoredEntry {
                ring,
                inserted_at: Instant::now(),
            },
        );
    }

    fn get(&self, session_id: &SessionId) -> Option<Arc<MasterKeyRing>> {
        let guard = self.entries.lock().expect("mutex de sesiones envenenado");
        let entry = guard.get(&session_id.0)?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None; // expirada — purge_expired la limpiará explícitamente
        }
        Some(entry.ring.clone())
    }

    fn purge_expired(&self) -> usize {
        let mut guard = self.entries.lock().expect("mutex de sesiones envenenado");
        let before = guard.len();
        guard.retain(|_, entry| entry.inserted_at.elapsed() <= self.ttl);
        before - guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dummy_ring() -> Arc<MasterKeyRing> {
        Arc::new(MasterKeyRing::new(
            0,
            b"clave-de-prueba-para-session-store-32b".to_vec(),
            Duration::from_secs(60),
        ))
    }

    #[test]
    fn insert_then_get_returns_the_same_ring() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        let session_id = SessionId::generate();
        let ring = dummy_ring();

        store.insert(session_id, ring.clone());
        let fetched = store.get(&session_id).expect("debe existir recién insertada");

        assert_eq!(fetched.active_key_id(), ring.active_key_id());
    }

    #[test]
    fn get_returns_none_for_unknown_session_id() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        assert!(store.get(&SessionId::generate()).is_none());
    }

    /// Una sesión cuyo TTL ya venció debe dejar de ser recuperable por
    /// `get` — no hay ninguna forma de "extender" el TTL implícitamente
    /// con un `get`, para no convertir un timeout de purga en un
    /// timeout de inactividad sin que eso se haya decidido
    /// explícitamente.
    #[test]
    fn expired_session_is_not_returned_by_get() {
        let store = InMemorySessionStore::new(Duration::from_millis(20));
        let session_id = SessionId::generate();
        store.insert(session_id, dummy_ring());

        std::thread::sleep(Duration::from_millis(40));

        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn purge_expired_removes_only_expired_entries_and_reports_count() {
        let store = InMemorySessionStore::new(Duration::from_millis(20));
        let fresh_id = SessionId::generate();
        let stale_id = SessionId::generate();

        store.insert(stale_id, dummy_ring());
        std::thread::sleep(Duration::from_millis(40));
        store.insert(fresh_id, dummy_ring()); // insertada después de que "stale" ya venció

        let purged = store.purge_expired();
        assert_eq!(purged, 1);
        assert!(store.get(&stale_id).is_none());
        assert!(store.get(&fresh_id).is_some());
    }

    /// `insert` sobre un `session_id` ya existente reemplaza la
    /// entrada, no la duplica ni falla.
    #[test]
    fn insert_overwrites_existing_entry_for_the_same_session_id() {
        let store = InMemorySessionStore::new(Duration::from_secs(60));
        let session_id = SessionId::generate();

        store.insert(session_id, Arc::new(MasterKeyRing::new(0, b"primera-clave-de-32-bytes-exactos".to_vec(), Duration::from_secs(60))));
        store.insert(session_id, Arc::new(MasterKeyRing::new(7, b"segunda-clave-de-32-bytes-exacta!".to_vec(), Duration::from_secs(60))));

        let fetched = store.get(&session_id).unwrap();
        assert_eq!(fetched.active_key_id(), 7);
    }
}
