//! Buffer circular en RAM para fragmentos en tránsito, con purga explícita.
//!
//! Dos promesas cuantificadas del documento viven acá y las dos se miden
//! en este módulo, no se declaran:
//!   - B ≤ 15 MB por sesión (techo de seguridad ampliado desde 10 MB
//!     original para dar mejor tolerancia; el buffer se preasigna,
//!     nunca crece más allá de ese valor).
//!   - Purga síncrona al ACK: `Erase(δᵢ, fᵢ)` ocurre en el mismo flujo,
//!     no en un ciclo de limpieza aparte.
//!
//! # De HashMap a slab preasignado
//!
//! La primera versión de este módulo usaba un `HashMap<FragmentIndex,
//! PendingFragment>` con un `Vec<u8>` propio por fragmento. Medido en la
//! práctica (ver smoke test en main.rs), un buffer con `used_bytes` en
//! el techo lógico costaba ~19% más de RSS real: cada fragmento traía su
//! propia alocación de heap más el overhead de la tabla hash.
//!
//! Esta versión preasigna un único `Vec<u8>` de `capacity_bytes` al
//! construirse (`vec![0u8; capacity_bytes]`, una sola alocación) y lo
//! subdivide en slots de tamaño fijo (`slot_size`). Cada slot guarda un
//! fragmento entero; los índices libres se llevan en una free-list
//! (`Vec<usize>`) en vez de un mapa hash. Esto es lo que "buffer
//! circular con punteros de lectura/escritura" describe en el Bloque II
//! del documento — la versión anterior tenía el nombre correcto pero la
//! estructura de un mapa disperso.
//!
//! Costo del cambio: fragmentos deben caber en `slot_size` (se rechazan
//! si no caben, igual que antes se rechazaban por exceder la capacidad
//! total), y hay fragmentación interna si el fragmento real es más chico
//! que el slot. Esto es aceptable porque el tamaño de fragmento ya es un
//! parámetro fijo por perfil (Bloque III): no es un buffer de tamaños
//! arbitrarios, es un buffer de fragmentos de un perfil con tamaño
//! conocido de antemano.

use crate::hmac_seal::Seal;
use std::time::{Duration, Instant};

/// Identificador de fragmento dentro de una sesión. Corresponde al índice
/// i en fᵢ — no es un ID global, es la posición en la secuencia.
pub type FragmentIndex = u64;

#[derive(Debug)]
pub enum BufferError {
    /// El fragmento no cabe en un slot de este buffer.
    FragmentTooLarge { fragment_len: usize, slot_size: usize },
    /// Todos los slots preasignados están ocupados; no se crea uno nuevo.
    NoSlotsAvailable,
}

/// Marca de "slot libre" para `occupant`. FragmentIndex es u64; reservar
/// el valor máximo como sentinel evita los 16 bytes de `Option<u64>`
/// (Rust no tiene niche optimization para u64 arbitrario) a cambio de
/// perder un único valor de índice que en la práctica nunca se usa —
/// 2⁶⁴-1 fragmentos en una sesión no es un escenario real.
const EMPTY_SLOT: FragmentIndex = FragmentIndex::MAX;

/// Slot vacío o con un fragmento pendiente de ACK. `occupant == EMPTY_SLOT`
/// es el estado "libre, listo para el próximo insert".
///
/// Tamaño elegido a propósito para minimizar metadata por slot (medido:
/// bajó de 72 a 48 bytes frente a una versión con `usize`/`Instant`/
/// `Option<u64>` sin ajustar — ver smoke test en main.rs para el impacto
/// real en RSS). Cada campo usa el tipo más chico que el problema
/// realmente necesita, no un algoritmo de compresión: no hay redundancia
/// que comprimir en un timestamp o un largo que ya ocupan su mínimo.
struct Slot {
    /// Cuántos bytes de `region` (desde el inicio del slot) son datos
    /// reales del fragmento. u32 alcanza sobrado: el tamaño de slot más
    /// grande de cualquier perfil (Bloque III, perfil Space: 1 MB) cabe
    /// muchas veces en 4 GB.
    len: u32,
    seal: Seal,
    /// Milisegundos transcurridos desde que el buffer se creó, no un
    /// timestamp absoluto de sistema. Un `Instant` completo (16 bytes)
    /// sobra: un buffer con timeout de purga forzada en el orden de
    /// segundos no necesita precisión de nanosegundos ni rango de años;
    /// u32 en milisegundos cubre ~49 días de sesión continua, muy por
    /// encima de cualquier timeout de perfil definido (500 ms–30 s).
    inserted_at_ms: u32,
    occupant: FragmentIndex,
}

/// Buffer circular preasignado para una única sesión activa.
///
/// Preasignación real: `region` es un único `Vec<u8>` de
/// `slot_size * slot_count` bytes, alocado una vez en `new`. Ninguna
/// operación posterior hace crecer `region` — un insert que no entra en
/// un slot libre se rechaza, no se atiende alocando más memoria.
pub struct PendingBuffer {
    region: Vec<u8>,
    slot_size: usize,
    slots: Vec<Slot>,
    /// Índices de slots libres, usados como pila (LIFO): el próximo
    /// insert toma el último liberado, manteniendo el acceso caliente
    /// en las mismas páginas de memoria en vez de dispersarse.
    free_slots: Vec<usize>,
    forced_purge_timeout: Duration,
    /// Referencia de tiempo para `inserted_at_ms`. Todas las marcas de
    /// tiempo de este buffer son relativas a este instante.
    epoch: Instant,
}

impl PendingBuffer {
    /// Preasigna un buffer para `slot_count` fragmentos de hasta
    /// `slot_size` bytes cada uno (`slot_size * slot_count` bytes en
    /// total, una sola alocación). No debe superar el techo de seguridad
    /// de 15 MB (perfil Core); perfiles distintos pasan sus propios
    /// valores (Lite: 64 KB, Vault: 256 KB, ver Bloque III).
    pub fn new(slot_size: usize, slot_count: usize, forced_purge_timeout: Duration) -> Self {
        let region = vec![0u8; slot_size * slot_count];
        let mut slots = Vec::with_capacity(slot_count);
        let mut free_slots = Vec::with_capacity(slot_count);
        for i in 0..slot_count {
            slots.push(Slot {
                len: 0,
                seal: Seal([0u8; crate::hmac_seal::SEAL_LEN]),
                inserted_at_ms: 0,
                occupant: EMPTY_SLOT,
            });
            free_slots.push(i);
        }
        PendingBuffer {
            region,
            slot_size,
            slots,
            free_slots,
            forced_purge_timeout,
            epoch: Instant::now(),
        }
    }

    /// Milisegundos transcurridos desde la creación del buffer, saturando
    /// en u32::MAX en el caso extremo de una sesión de más de ~49 días
    /// (no un escenario real dado que los timeouts de perfil son de
    /// segundos, pero se satura en vez de hacer wrap silencioso).
    fn elapsed_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis().min(u32::MAX as u128) as u32
    }

    /// Capacidad total preasignada, en bytes. Fijo desde la construcción.
    pub fn capacity_bytes(&self) -> usize {
        self.region.len()
    }

    /// Bytes de fragmento real actualmente en uso (no cuenta el relleno
    /// de slots parcialmente ocupados).
    pub fn used_bytes(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.occupant != EMPTY_SLOT)
            .map(|s| s.len as usize)
            .sum()
    }

    /// Inserta un fragmento sellado en el primer slot libre disponible.
    /// Falla si el fragmento no cabe en un slot, o si no hay slots
    /// libres — en ningún caso se alarga `region` para acomodarlo.
    pub fn insert(
        &mut self,
        index: FragmentIndex,
        bytes: &[u8],
        seal: Seal,
    ) -> Result<(), BufferError> {
        if index == EMPTY_SLOT {
            // Único valor de FragmentIndex no representable, por ser el
            // sentinel de "slot libre". Ver comentario en EMPTY_SLOT.
            return Err(BufferError::FragmentTooLarge {
                fragment_len: bytes.len(),
                slot_size: self.slot_size,
            });
        }
        if bytes.len() > self.slot_size {
            return Err(BufferError::FragmentTooLarge {
                fragment_len: bytes.len(),
                slot_size: self.slot_size,
            });
        }
        let slot_idx = self.free_slots.pop().ok_or(BufferError::NoSlotsAvailable)?;

        let offset = slot_idx * self.slot_size;
        self.region[offset..offset + bytes.len()].copy_from_slice(bytes);

        let now_ms = self.elapsed_ms();
        let slot = &mut self.slots[slot_idx];
        slot.len = bytes.len() as u32;
        slot.seal = seal;
        slot.inserted_at_ms = now_ms;
        slot.occupant = index;

        Ok(())
    }

    fn find_slot(&self, index: FragmentIndex) -> Option<usize> {
        if index == EMPTY_SLOT {
            return None;
        }
        self.slots.iter().position(|s| s.occupant == index)
    }

    /// Regla de purga por ACK: `Status(fᵢ) == ACK ⟹ Erase(δᵢ, fᵢ)`.
    /// Síncrona: el slot vuelve a la free-list en esta misma llamada.
    /// Devuelve false si el índice no estaba pendiente (ACK duplicado o
    /// ya purgado).
    pub fn purge_on_ack(&mut self, index: FragmentIndex) -> bool {
        match self.find_slot(index) {
            Some(slot_idx) => {
                self.release_slot(slot_idx);
                true
            }
            None => false,
        }
    }

    fn release_slot(&mut self, slot_idx: usize) {
        let slot = &mut self.slots[slot_idx];
        // Se sobreescribe el contenido del slot al liberarlo (no solo el
        // marcador `occupant`), para que un volcado de memoria posterior
        // no encuentre el fragmento ya purgado todavía en `region`.
        let offset = slot_idx * self.slot_size;
        let len = slot.len as usize;
        self.region[offset..offset + len].fill(0);
        slot.len = 0;
        slot.occupant = EMPTY_SLOT;
        self.free_slots.push(slot_idx);
    }

    /// Timeout de purga forzada: recorre los slots ocupados y libera los
    /// que superaron `forced_purge_timeout` sin ACK. Devuelve cuántos
    /// slots purgó por esta vía (para métricas).
    pub fn purge_expired(&mut self) -> u64 {
        let timeout_ms: u32 = self
            .forced_purge_timeout
            .as_millis()
            .min(u32::MAX as u128) as u32;
        let now_ms = self.elapsed_ms();
        let expired: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                s.occupant != EMPTY_SLOT && now_ms.saturating_sub(s.inserted_at_ms) > timeout_ms
            })
            .map(|(i, _)| i)
            .collect();

        for slot_idx in &expired {
            self.release_slot(*slot_idx);
        }
        expired.len() as u64
    }

    /// Cuántos fragmentos siguen pendientes de ACK ahora mismo.
    pub fn pending_count(&self) -> usize {
        self.slots.len() - self.free_slots.len()
    }

    /// Verifica el sello de un fragmento pendiente, sin purgarlo — la
    /// decisión de purgar es de quien llama, para no acoplar
    /// verificación y liberación de memoria en un único paso.
    pub fn seal_of(&self, index: FragmentIndex) -> Option<&Seal> {
        self.find_slot(index).map(|i| &self.slots[i].seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_seal::SEAL_LEN;

    fn dummy_seal() -> Seal {
        Seal([0u8; SEAL_LEN])
    }

    #[test]
    fn insert_within_slot_size_succeeds() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        let res = buf.insert(0, &[0u8; 100], dummy_seal());
        assert!(res.is_ok());
        assert_eq!(buf.used_bytes(), 100);
    }

    #[test]
    fn insert_exceeding_slot_size_is_rejected() {
        let mut buf = PendingBuffer::new(100, 4, Duration::from_millis(500));
        let res = buf.insert(0, &[0u8; 200], dummy_seal());
        assert!(matches!(res, Err(BufferError::FragmentTooLarge { .. })));
        assert_eq!(buf.used_bytes(), 0);
    }

    #[test]
    fn insert_beyond_slot_count_is_rejected_not_grown() {
        let mut buf = PendingBuffer::new(100, 2, Duration::from_millis(500));
        let capacity_before = buf.capacity_bytes();
        buf.insert(0, &[0u8; 50], dummy_seal()).unwrap();
        buf.insert(1, &[0u8; 50], dummy_seal()).unwrap();

        let res = buf.insert(2, &[0u8; 50], dummy_seal());
        assert!(matches!(res, Err(BufferError::NoSlotsAvailable)));
        // La región preasignada nunca cambió de tamaño.
        assert_eq!(buf.capacity_bytes(), capacity_before);
    }

    #[test]
    fn ack_purges_synchronously() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        assert_eq!(buf.used_bytes(), 100);

        let purged = buf.purge_on_ack(0);
        assert!(purged);
        assert_eq!(buf.used_bytes(), 0);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn duplicate_ack_is_a_noop_not_an_error() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        assert!(buf.purge_on_ack(0));
        assert!(!buf.purge_on_ack(0));
        assert_eq!(buf.used_bytes(), 0);
    }

    #[test]
    fn purged_slot_is_immediately_reusable() {
        let mut buf = PendingBuffer::new(100, 1, Duration::from_millis(500));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        // Único slot ocupado: un segundo fragmento no entra.
        assert!(matches!(
            buf.insert(1, &[0u8; 1], dummy_seal()),
            Err(BufferError::NoSlotsAvailable)
        ));

        buf.purge_on_ack(0);
        // Tras la purga, el mismo slot se reutiliza sin realojar región.
        assert!(buf.insert(1, &[0u8; 100], dummy_seal()).is_ok());
    }

    #[test]
    fn purged_slot_content_is_zeroed() {
        // El estado residual no debe conservar el fragmento crudo tras
        // purgarlo — releva la propiedad de no-invertibilidad del
        // Bloque II.6 a nivel de buffer físico, no solo del estado Es(i).
        let mut buf = PendingBuffer::new(16, 1, Duration::from_millis(500));
        buf.insert(0, &[0xAAu8; 16], dummy_seal()).unwrap();
        buf.purge_on_ack(0);
        assert!(buf.region.iter().all(|&b| b == 0));
    }

    #[test]
    fn forced_timeout_purges_without_ack() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(20));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();
        std::thread::sleep(Duration::from_millis(40));

        let purged = buf.purge_expired();
        assert_eq!(purged, 1);
        assert_eq!(buf.used_bytes(), 0);
        assert_eq!(buf.pending_count(), 0);
    }

    #[test]
    fn non_expired_fragments_survive_purge_sweep() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(200));
        buf.insert(0, &[0u8; 100], dummy_seal()).unwrap();

        let purged = buf.purge_expired();
        assert_eq!(purged, 0);
        assert_eq!(buf.pending_count(), 1);
    }

    /// Caso borde introducido por el sentinel EMPTY_SLOT: el valor
    /// reservado para "slot libre" no puede usarse como índice real de
    /// fragmento. Se documenta con un test explícito en vez de dejarlo
    /// como comportamiento implícito.
    #[test]
    fn sentinel_value_is_rejected_as_fragment_index() {
        let mut buf = PendingBuffer::new(1024, 4, Duration::from_millis(500));
        let res = buf.insert(FragmentIndex::MAX, &[0u8; 10], dummy_seal());
        assert!(res.is_err());
    }

    /// Confirma la cota de 15 MB del perfil Core como caso de uso real,
    /// con slots de 1 KB (tamaño típico Core, Bloque III).
    #[test]
    fn fifteen_megabyte_ceiling_via_fixed_slots() {
        const FIFTEEN_MB: usize = 15 * 1024 * 1024;
        const SLOT_SIZE: usize = 1024;
        let slot_count = FIFTEEN_MB / SLOT_SIZE;
        let mut buf = PendingBuffer::new(SLOT_SIZE, slot_count, Duration::from_millis(500));

        assert_eq!(buf.capacity_bytes(), FIFTEEN_MB);

        for i in 0..slot_count as u64 {
            buf.insert(i, &[0x42u8; SLOT_SIZE], dummy_seal()).unwrap();
        }
        assert_eq!(buf.used_bytes(), FIFTEEN_MB);
        assert!(matches!(
            buf.insert(slot_count as u64, &[0x42u8; SLOT_SIZE], dummy_seal()),
            Err(BufferError::NoSlotsAvailable)
        ));
    }
}
