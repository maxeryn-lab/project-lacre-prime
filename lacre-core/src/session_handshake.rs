//! Establecimiento de clave de sesión — Sección 8.4, paso 1, del
//! documento Lacre Prime.
//!
//! # Qué exige el documento, textualmente
//!
//! 8.4 especifica un esquema de tres capas complementarias:
//!   1. Establecimiento (una vez por sesión): intercambio de
//!      Diffie-Hellman efímero (curva X25519) → produce un secreto
//!      compartido que nunca viaja por la red.
//!   2. Derivación (una vez, a partir del secreto compartido):
//!      k_sesión = HKDF(secreto_compartido, salt=id_sesión, info="lacre-v1")
//!   3. Operación (por cada fragmento): δᵢ = HMAC(fᵢ ∥ Sᵢ, k_sesión)
//!
//! Este módulo implementa EXCLUSIVAMENTE el paso 1.
//!
//! # CORRECCIÓN DE INTEGRACIÓN (checkpoint Claude Alfa V2, con
//! `session.rs` real a la vista — no presente en los dos tramos
//! anteriores de esta fase)
//!
//! El paso 2 **ya existe, completo, en `session.rs`**:
//! `MasterKeyRing::derive_for_sealing`/`derive_for_verifying` llaman a
//! `derive_session_key(key_id, ikm, session_id)`, que ejecuta
//! literalmente `Hkdf::<Sha256>::new(Some(&session_id.0),
//! ikm).expand(HKDF_INFO, ...)` — es decir, `HKDF(ikm,
//! salt=session_id, info=...)`. Esto es el paso 2 de 8.4 al pie de la
//! letra (la única diferencia es que `HKDF_INFO` en `session.rs` vale
//! `"lacre-core/v1/session-key"` en vez del literal `"lacre-v1"` de la
//! prosa de 8.4 — un nombre de contexto de dominio más específico, no
//! un mecanismo distinto; ver RFC 5869 §3.2 sobre el propósito del
//! campo "info").
//!
//! **Consecuencia:** este módulo NO debe volver a aplicar HKDF sobre
//! el secreto DH. Los tramos anteriores de esta fase (entregados sin
//! `session.rs` a la vista) implementaban
//! `derive_session_key_material` como un HKDF completo adicional
//! (`Hkdf::new(salt=session_id, secreto).expand("lacre-v1")`) — eso
//! es exactamente el riesgo 3 que ambos informes de cierre señalaron
//! sin poder resolver: conectar ese resultado a
//! `MasterKeyRing::new(key_id, ikm, ...)` habría producido
//! `HKDF(HKDF(secreto, session_id, "lacre-v1"), session_id,
//! "lacre-core/v1/session-key")` — doble derivación, ya no lo que 8.4
//! describe. Ese método se retiró de este archivo. En su lugar,
//! `EphemeralSharedSecret` expone los 32 bytes crudos del secreto DH
//! (`into_ikm_bytes`), pensados para entrar directamente como
//! parámetro `ikm` de `MasterKeyRing::new`/`MasterKeyRing::rotate` —
//! el único HKDF con `salt=session_id` ocurre ahí, una sola vez, tal
//! como pide 8.4.
//!
//! # Clasificación epistémica de esta pieza
//!
//! El propio documento clasifica el esquema de 8.4 en su conjunto como
//! `[CA]` Conocimiento Aceptado (Apéndice C: "patrón de TLS 1.3"), no
//! `[DO]`. Este módulo, por tanto, no inventa un mecanismo nuevo: aplica
//! X25519 efímero exactamente como TLS 1.3 lo hace para forward
//! secrecy, con la única particularidad de que el resultado alimenta al
//! HKDF ya existente en `session.rs` en vez de a un contexto TLS.
//!
//! # Decisiones de ingeniería NO especificadas por el documento
//!
//! 8.4 fija el algoritmo (X25519) y la fórmula de derivación, pero NO
//! fija:
//!   1. El formato exacto de los mensajes de handshake (qué bytes viajan,
//!      en qué orden, por qué canal). Eso es, por definición de 7.4,
//!      responsabilidad de un Adaptador de transporte — este módulo se
//!      limita a producir y consumir bytes de clave pública (32 bytes
//!      fijos, tamaño nativo de X25519) y a producir el secreto
//!      resultante. No impone HTTP, ni framing, ni ningún transporte.
//!   2. Si hay una distinción de roles "iniciador"/"respondedor" en el
//!      intercambio. Decisión tomada aquí: NO la hay — X25519 es
//!      simétrico por construcción (ambas partes ejecutan la misma
//!      operación DH con su propia clave efímera y la pública ajena), así
//!      que se modela como un único tipo `EphemeralHandshake` usado
//!      igual por ambos lados, en vez de dos tipos distintos
//!      "iniciador"/"respondedor" que duplicarían lógica idéntica sin
//!      necesidad. Esto es un cambio deliberado respecto de cómo
//!      `SealerCore`/`VerifierCore` sí están separados en dos tipos
//!      (ahí la asimetría de rol es real: uno origina la sesión, el otro
//!      la retoma). Acá no hay asimetría de rol que justificar.
//!   3. Quién deriva la clave de sesión final: se decidió, en este
//!      checkpoint, que NO es este módulo — es `session.rs`, que ya
//!      tenía la implementación completa del paso 2 antes de que Fase 2
//!      empezara. Este módulo termina su responsabilidad en el secreto
//!      DH crudo.
//!
//! # Lo que este módulo NO hace (deliberadamente)
//!
//! No reemplaza `MasterKeyRing` ni duplica su HKDF. `MasterKeyRing`
//! sigue siendo, sin cambios, el único componente que aplica HKDF con
//! `salt = session_id` — este módulo solo produce los 32 bytes de
//! `ikm` que hoy se le pasaban a mano como `master_key_bytes` fijos a
//! `MasterKeyRing::new`. La integración real (dónde se llama al
//! handshake, quién construye el `MasterKeyRing` resultante, y cómo se
//! fuerza que `SealerCore` y `VerifierCore` compartan el mismo
//! `session_id` ya acordado) se resuelve en `core.rs` — ver
//! `open_with_session_key`/`resume_with_session_key` y el comentario
//! de cabecera correspondiente ahí.

use x25519_dalek::{EphemeralSecret, PublicKey};

/// Longitud en bytes de una clave pública X25519 — tamaño nativo de la
/// curva, no una elección nuestra.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;

/// Clave pública efímera de una de las partes del intercambio. Se
/// distribuye libremente (es, por definición, la mitad pública del DH);
/// lo que nunca debe viajar es la clave efímera privada correspondiente
/// (`EphemeralHandshake`, que no implementa `Clone`/`Debug` a propósito
/// — ver más abajo). `Debug` aquí es seguro y deliberado: a diferencia
/// de `EphemeralHandshake`/`EphemeralSharedSecret`, este tipo nunca
/// contiene material secreto — es exactamente lo que ya viaja en claro
/// por la red. Necesario, además, para que `assert_eq!` compile en los
/// tests de `from_slice` (error real encontrado recién al compilar en
/// este checkpoint, no detectado por la revisión manual anterior).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralPublicKey([u8; X25519_PUBLIC_KEY_LEN]);

/// Error al reconstruir una `EphemeralPublicKey` desde bytes de
/// longitud variable recibidos por un canal de transporte real.
///
/// # Por qué esto no existía en la primera entrega y por qué hace falta
///
/// `from_bytes([u8; 32])` (abajo) es infalible porque el compilador ya
/// garantiza la longitud en tiempo de compilación — sirve para el caso
/// interno/de test donde el llamador ya tiene un array fijo. Pero un
/// Adaptador real (7.4) recibe bytes de un socket, un campo de
/// cabecera HTTP, o un mensaje gRPC como `&[u8]` de longitud NO
/// garantizada: el otro extremo puede estar corrupto, truncado, o ser
/// simplemente hostil. Sin esta variante falible, la única opción del
/// llamador sería un `.try_into().unwrap()` a ciegas antes de llegar
/// aquí — exactamente el tipo de panic en el borde de confianza con la
/// red que 7.4 exige evitar (el Adaptador debe delimitar bytes sin
/// exponer al Núcleo, ni a sus capacidades asociadas, a un panic
/// inducible por un peer malicioso).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EphemeralPublicKeyError {
    /// La cantidad de bytes recibida no es exactamente 32 — ni más ni
    /// menos. Se registra la longitud recibida para que quien maneje
    /// el error pueda decidir si vale la pena registrar el incidente
    /// (una longitud de 0 o absurdamente grande sugiere un peer
    /// hostil o un framing roto, no un simple bit-flip).
    InvalidLength { received: usize },
}

impl EphemeralPublicKey {
    pub fn to_bytes(&self) -> [u8; X25519_PUBLIC_KEY_LEN] {
        self.0
    }

    /// Construcción infalible desde un array ya validado en tiempo de
    /// compilación (uso interno / tests). Para bytes de longitud
    /// variable provenientes de un transporte real, usar
    /// `from_slice`.
    pub fn from_bytes(bytes: [u8; X25519_PUBLIC_KEY_LEN]) -> Self {
        EphemeralPublicKey(bytes)
    }

    /// Construcción falible desde un slice de longitud arbitraria —
    /// pensada para el punto donde un Adaptador (7.4) entrega bytes
    /// recién leídos de la red. Rechaza cualquier longitud distinta de
    /// 32 con un error explícito en vez de entrar en pánico.
    ///
    /// Nota deliberada: al igual que la biblioteca `x25519_dalek`
    /// subyacente (`PublicKey::from([u8;32])`), esto NO valida que los
    /// bytes representen un punto válido de la curva ni descarta
    /// puntos de orden bajo — RFC 7748 permite operar sobre cualquier
    /// entrada de 32 bytes por diseño (el propio X25519 está construido
    /// para ser seguro incluso frente a esto en el modelo de amenaza
    /// estándar de Diffie-Hellman efímero puro). Si en el futuro Lacre
    /// necesita descartar explícitamente puntos de orden bajo como
    /// salvaguarda adicional (algunos protocolos de nivel superior lo
    /// hacen — ver `SharedSecret::was_contributory()` en
    /// `x25519-dalek`), esa es una decisión de ingeniería adicional a
    /// tomar explícitamente, no algo que este método deba asumir en
    /// silencio.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EphemeralPublicKeyError> {
        let array: [u8; X25519_PUBLIC_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| EphemeralPublicKeyError::InvalidLength {
                received: bytes.len(),
            })?;
        Ok(EphemeralPublicKey(array))
    }
}

/// El secreto compartido resultante del DH — 8.4 es explícito en que
/// "nunca viaja por la red". No implementa Debug/Clone por la misma
/// razón que `SessionState` en `core.rs` y `VaultSigningKey` en
/// `vault_signature.rs`: es exactamente lo que un memory dump o un log
/// descuidado expondría, y compartirlo por un clone accidental
/// derrotaría la propiedad de forward secrecy que X25519 efímero existe
/// para dar.
///
/// # Por qué este tipo NO deriva la clave de sesión él mismo
///
/// Un tramo anterior de esta fase (entregado sin `session.rs` real a
/// la vista) implementaba aquí un método
/// `derive_session_key_material` que aplicaba su propio
/// `Hkdf::new(salt=session_id, secreto).expand("lacre-v1")`. Con
/// `session.rs` real confirmado, ese método habría producido una
/// doble derivación: `MasterKeyRing::derive_for_sealing` YA ejecuta
/// `Hkdf::new(salt=session_id, ikm).expand(HKDF_INFO)` sobre lo que
/// reciba como `ikm`. Pasarle el resultado de un HKDF ya aplicado
/// habría producido `HKDF(HKDF(secreto, ...), ...)`, que ya no es
/// literalmente "HKDF(secreto_compartido, salt=id_sesión,
/// info='lacre-v1')" como pide 8.4 — un desvío silencioso del texto
/// del documento. Este tipo se limita, por tanto, a exponer los 32
/// bytes crudos del secreto DH: el único HKDF con `salt=session_id`
/// ocurre una sola vez, dentro de `MasterKeyRing`.
pub struct EphemeralSharedSecret([u8; 32]);

impl EphemeralSharedSecret {
    /// Expone el secreto DH crudo como `ikm` (material de clave de
    /// entrada) listo para pasarse directamente a
    /// `MasterKeyRing::new`/`MasterKeyRing::rotate` en lugar de una
    /// clave maestra estática. Consume `self`: una vez extraídos los
    /// bytes para construir el ring, no existe motivo legítimo para
    /// retener el `EphemeralSharedSecret` por más tiempo del necesario
    /// — es, de nuevo, la misma disciplina de "efímero, un solo uso"
    /// del resto de este módulo.
    ///
    /// Nombrado deliberadamente `into_ikm_bytes` (no
    /// `derive_session_key_material`, el nombre del tramo anterior)
    /// para que el nombre del método deje claro, en el sitio de la
    /// llamada, que esto NO es todavía una clave de sesión lista para
    /// HMAC — es material de entrada para la derivación que
    /// `MasterKeyRing` hace después.
    pub fn into_ikm_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Lado de un intercambio X25519 efímero. No hay distinción de
/// "iniciador"/"respondedor" — ver justificación en el comentario de
/// cabecera del módulo, punto 2.
///
/// No implementa Debug/Clone: contiene la clave privada efímera
/// (`x25519_dalek::EphemeralSecret` ya lo impide a nivel de biblioteca,
/// por la misma razón de higiene de claves).
pub struct EphemeralHandshake {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralHandshake {
    /// Genera un par efímero nuevo. "Efímero" no es solo un nombre: este
    /// valor está diseñado para usarse una única vez y luego
    /// descartarse — no hay método para serializar la parte privada, a
    /// propósito.
    ///
    /// Nota de compatibilidad NO verificada por compilación real (ver
    /// limitación de entorno en el reporte de cierre): se usa
    /// `rand::rngs::OsRng`, igual que `vault_signature.rs` ya hace para
    /// Ed25519, en vez de `rand_core::OsRng` como aparece en los
    /// ejemplos oficiales de `x25519-dalek`. Ambas cratesitas (`rand`
    /// 0.8 y `x25519-dalek` 2.x) dependen de la familia `rand_core =
    /// "0.6.x"` — confirmado contra el `Cargo.toml` fuente de
    /// `ed25519-dalek` 2.x (que también fija `rand_core = "0.6.4"`) y
    /// contra un fork público de `x25519-dalek` que fija `rand_core =
    /// "0.6"` — así que `rand::rngs::OsRng`, que implementa los traits
    /// de `rand_core` 0.6, debería aceptarse por `EphemeralSecret::
    /// random_from_rng` sin conflicto de versión. Esto es una
    /// verificación por documentación externa, NO por compilación real
    /// del crate — hay que confirmarlo con `cargo build` en cuanto se
    /// integre este archivo al workspace real.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = PublicKey::from(&secret);
        EphemeralHandshake { secret, public }
    }

    /// La clave pública a enviar a la contraparte. Cómo viaja
    /// (formato de mensaje, canal) es responsabilidad de un Adaptador
    /// (7.4) — este método solo entrega los 32 bytes nativos.
    pub fn public_key(&self) -> EphemeralPublicKey {
        EphemeralPublicKey(self.public.to_bytes())
    }

    /// Completa el intercambio: combina esta clave efímera propia con
    /// la clave pública efímera recibida de la contraparte, produciendo
    /// el secreto compartido. Consume `self` porque la clave efímera
    /// privada no debe reutilizarse tras completar un intercambio — una
    /// vez gastada, no existe una operación legítima de "volver a
    /// combinar" con otra clave pública distinta bajo el mismo secreto
    /// efímero sin violar la propiedad de "efímero, un solo uso" que
    /// 8.4 exige explícitamente ("secreto compartido que nunca viaja
    /// por la red" presupone que además es de un solo uso: reutilizar
    /// la misma clave efímera en dos sesiones distintas anularía la
    /// forward secrecy entre esas dos sesiones).
    pub fn complete(self, their_public: EphemeralPublicKey) -> EphemeralSharedSecret {
        // `PublicKey::from([u8; 32])` reconstruye una clave pública AJENA
        // a partir de sus bytes crudos recibidos por el canal de
        // transporte — distinto del `PublicKey::from(&EphemeralSecret)`
        // que se usa en `public_key()` arriba para derivar la propia
        // clave pública a partir del propio secreto. Son dos `impl
        // From` distintos de la misma biblioteca; confundirlos sería un
        // error de tipos que el compilador rechazaría, no algo que
        // pueda quedar ambiguo en la práctica.
        let their_public = PublicKey::from(their_public.0);
        let shared = self.secret.diffie_hellman(&their_public);
        EphemeralSharedSecret(*shared.as_bytes())
    }
}

// -----------------------------------------------------------------
// Nota de alcance de esta entrega — Claude Alfa V2, checkpoint con
// session.rs real a la vista
// -----------------------------------------------------------------
//
// Este módulo resuelve el paso 1 de 8.4 de forma autocontenida y
// probada (ver tests abajo: dos `EphemeralHandshake` independientes que
// intercambian claves públicas producen el MISMO secreto DH crudo en
// ambos lados).
//
// La integración con `MasterKeyRing` (paso 2, ya implementado en
// `session.rs`) y con `SealerCore`/`VerifierCore` (paso 3, en
// `core.rs`) se resuelve en `core.rs`, no en este archivo — ver
// `SealerCore::open_with_session_key` y
// `VerifierCore::resume_with_session_key`. Las tres preguntas que los
// dos tramos anteriores de esta fase dejaron abiertas por no tener
// `session.rs` real quedan respondidas ahí:
//
//   1. `MasterKeyRing::derive_for_sealing`/`derive_for_verifying` SÍ
//      aplican HKDF internamente sobre `ikm` — confirmado leyendo
//      `derive_session_key` en `session.rs`. Por eso este módulo ya
//      NO aplica su propio HKDF (ver comentario de cabecera y de
//      `EphemeralSharedSecret` arriba) — se corrigió respecto del
//      tramo anterior, que sí lo hacía.
//   2. `SessionId::generate()` es una función libre de `session.rs`,
//      no depende de vivir dentro de `SealerCore::open` — puede
//      invocarse antes del handshake sin tocar `session.rs`.
//   3. `SealerCore::open` no aceptaba un `session_id` ya acordado
//      desde afuera (siempre generaba uno propio internamente) —
//      esta era la única brecha real. Se agregó
//      `open_with_session_key` como método nuevo (mismo patrón que
//      `open_with_vault_key`: no rompe la firma existente de `open`),
//      que sí lo acepta.
//
// Fase 1 (`core.rs`, `vault_signature.rs`, `receipt.rs`,
// `profile_config.rs`) permanece sin cambios de comportamiento fuera
// de los métodos nuevos agregados explícitamente para esta
// integración.

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodificador hex mínimo, sin dependencias externas — deliberado:
    /// agregar `hex-literal` solo para un test violaría la instrucción
    /// de "sin dependencias innecesarias" por un beneficio que un
    /// helper de 8 líneas ya cubre. Entra en pánico ante hex inválido,
    /// lo cual es aceptable AQUÍ porque solo se usa con constantes
    /// literales de este mismo archivo, nunca con datos externos.
    fn hex_to_32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "vector de prueba debe representar 32 bytes exactos");
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .expect("vector de prueba hardcodeado debe ser hex válido");
        }
        out
    }

    /// Vector de prueba OFICIAL de RFC 7748 §6.1 (Langley, Hamburg,
    /// Turner, enero 2016) — transcrito y verificado carácter por
    /// carácter contra la fuente primaria
    /// (https://www.rfc-editor.org/rfc/rfc7748.html, sección 6.1,
    /// "Test vector"), no citado de memoria ni tomado de un snippet de
    /// búsqueda sin cotejar. Cada constante hex de abajo tiene
    /// exactamente 64 caracteres (32 bytes) — confirmado
    /// programáticamente antes de escribir este test, después de que
    /// una primera transcripción manual introdujera un error de un
    /// carácter faltante por cadena.
    ///
    /// # Por qué esto usa `x25519_dalek::StaticSecret` y no
    /// `EphemeralHandshake`
    ///
    /// `EphemeralHandshake`/`EphemeralSecret` son DELIBERADAMENTE no
    /// deserializables desde bytes fijos — es la propiedad que impide
    /// reutilizar una clave efímera, y es correcta para el código
    /// productivo. Pero un vector de prueba RFC exige cargar una clave
    /// PRIVADA exacta y conocida, que `EphemeralSecret` no permite por
    /// diseño. `StaticSecret::from([u8;32])` aplica el MISMO
    /// `clamp_scalar` que usa `EphemeralSecret` internamente (confirmado
    /// contra el código fuente de `x25519-dalek`: ambos tipos comparten
    /// la operación de clamping de RFC 7748 §5), así que el resultado
    /// matemático es idéntico — este test verifica la CORRECCIÓN DE LA
    /// BIBLIOTECA subyacente que `EphemeralHandshake` envuelve, sin
    /// necesitar (ni poder) instanciar `EphemeralHandshake` con una
    /// clave fija. Es un arnés de verificación externo al tipo
    /// productivo, no una prueba de `EphemeralHandshake` en sí mismo —
    /// esa distinción se deja explícita para que quien audite este test
    /// no asuma que cubre más de lo que cubre.
    #[test]
    fn rfc7748_section_6_1_test_vector() {
        use x25519_dalek::StaticSecret;

        let alice_private = hex_to_32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public_expected = hex_to_32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_private = hex_to_32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public_expected = hex_to_32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_expected = hex_to_32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice_secret = StaticSecret::from(alice_private);
        let alice_public = PublicKey::from(&alice_secret);
        assert_eq!(
            alice_public.to_bytes(),
            alice_public_expected,
            "clave pública de Alice no coincide con RFC 7748 §6.1"
        );

        let bob_secret = StaticSecret::from(bob_private);
        let bob_public = PublicKey::from(&bob_secret);
        assert_eq!(
            bob_public.to_bytes(),
            bob_public_expected,
            "clave pública de Bob no coincide con RFC 7748 §6.1"
        );

        let alice_shared = alice_secret.diffie_hellman(&bob_public);
        let bob_shared = bob_secret.diffie_hellman(&alice_public);

        assert_eq!(
            alice_shared.as_bytes(),
            &shared_expected,
            "secreto compartido (lado Alice) no coincide con RFC 7748 §6.1"
        );
        assert_eq!(
            bob_shared.as_bytes(),
            &shared_expected,
            "secreto compartido (lado Bob) no coincide con RFC 7748 §6.1"
        );
        assert_eq!(
            alice_shared.as_bytes(),
            bob_shared.as_bytes(),
            "ambos lados deben coincidir entre sí, no solo con el vector"
        );
    }

    /// Prueba central de X25519: dos partes que generan su propio par
    /// efímero, intercambian SOLO la clave pública, y ejecutan
    /// `complete` con la clave pública ajena, deben llegar al MISMO
    /// secreto compartido — es la propiedad matemática básica de
    /// Diffie-Hellman (g^ab == g^ba), no una suposición nuestra.
    #[test]
    fn both_sides_derive_the_same_shared_secret() {
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();

        let alice_public = alice.public_key();
        let bob_public = bob.public_key();

        let alice_secret = alice.complete(bob_public);
        let bob_secret = bob.complete(alice_public);

        // A partir de este checkpoint, `EphemeralSharedSecret` ya no
        // aplica su propio HKDF (ver comentario de cabecera del
        // módulo) — expone el secreto DH crudo con `into_ikm_bytes`,
        // que es lo que la propiedad matemática de DH garantiza
        // idéntico en ambos lados.
        let ikm_a = alice_secret.into_ikm_bytes();
        let ikm_b = bob_secret.into_ikm_bytes();

        assert_eq!(ikm_a, ikm_b);
    }

    /// Dos ejecuciones de handshake distintas (dos pares efímeros
    /// nuevos) deben producir secretos compartidos distintos, incluso
    /// si en teoría "las mismas dos partes" vuelven a hablar — esto es
    /// exactamente forward secrecy: cada sesión es criptográficamente
    /// independiente de la anterior porque la clave efímera nunca se
    /// reutiliza.
    #[test]
    fn independent_handshakes_produce_independent_secrets() {
        let alice1 = EphemeralHandshake::generate();
        let bob1 = EphemeralHandshake::generate();
        let alice1_public = alice1.public_key();
        let secret1 = bob1.complete(alice1_public);

        let alice2 = EphemeralHandshake::generate();
        let bob2 = EphemeralHandshake::generate();
        let alice2_public = alice2.public_key();
        let secret2 = bob2.complete(alice2_public);

        assert_ne!(
            secret1.into_ikm_bytes(),
            secret2.into_ikm_bytes(),
            "sesiones con handshakes efímeros independientes nunca deben coincidir en secreto"
        );
    }

    /// Un tercero que solo observa las dos claves públicas efímeras (lo
    /// único que "viaja por la red" según 8.4) no debe poder reconstruir
    /// el secreto sin conocer al menos una de las dos claves privadas.
    /// Esta prueba no puede demostrar seguridad computacional (eso es
    /// la garantía del propio X25519, ya auditado externamente como
    /// primitiva), pero sí confirma que la clave pública por sí sola no
    /// es igual al secreto ni lo contiene en claro.
    #[test]
    fn public_key_bytes_differ_from_resulting_shared_secret() {
        let alice = EphemeralHandshake::generate();
        let bob = EphemeralHandshake::generate();
        let alice_public = alice.public_key();
        let bob_public_bytes = bob.public_key().to_bytes();

        let shared = alice
            .complete(EphemeralPublicKey::from_bytes(bob_public_bytes))
            .into_ikm_bytes();

        assert_ne!(shared, alice_public.to_bytes());
        assert_ne!(shared, bob_public_bytes);
    }

    /// Round-trip de serialización de la clave pública — necesario
    /// porque un Adaptador (7.4) va a necesitar transportar estos bytes
    /// por HTTP/gRPC/etc.
    #[test]
    fn public_key_round_trips_through_bytes() {
        let handshake = EphemeralHandshake::generate();
        let public = handshake.public_key();
        let bytes = public.to_bytes();
        let restored = EphemeralPublicKey::from_bytes(bytes);

        assert_eq!(public.to_bytes(), restored.to_bytes());
    }

    // -------------------------------------------------------------
    // Tests de robustez pedidos explícitamente: un Adaptador real (7.4)
    // entrega &[u8] de longitud NO garantizada, no un [u8;32] ya
    // validado por el compilador. Estos tests cubren exactamente el
    // borde donde `from_bytes` (infalible, uso interno) no basta.
    // -------------------------------------------------------------

    /// `from_slice` debe rechazar, con un error explícito y sin pánico,
    /// bytes más cortos que 32 — el caso de un mensaje truncado a mitad
    /// de transporte (conexión cortada, lectura parcial de socket).
    #[test]
    fn from_slice_rejects_truncated_input() {
        let too_short = [0u8; 16];
        let result = EphemeralPublicKey::from_slice(&too_short);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 16 })
        );
    }

    /// `from_slice` debe rechazar, igual de explícitamente, bytes más
    /// largos que 32 — el caso de un framing de Adaptador roto que
    /// entrega el campo siguiente pegado al de la clave pública.
    #[test]
    fn from_slice_rejects_oversized_input() {
        let too_long = [0u8; 40];
        let result = EphemeralPublicKey::from_slice(&too_long);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 40 })
        );
    }

    /// Caso límite explícito: entrada vacía. No debería tratarse
    /// distinto de cualquier otra longitud incorrecta, pero se prueba
    /// aparte porque es el caso más probable ante una conexión que se
    /// cierra antes de enviar nada.
    #[test]
    fn from_slice_rejects_empty_input() {
        let result = EphemeralPublicKey::from_slice(&[]);

        assert_eq!(
            result,
            Err(EphemeralPublicKeyError::InvalidLength { received: 0 })
        );
    }

    /// `from_slice` con exactamente 32 bytes debe aceptar y producir el
    /// mismo valor que `from_bytes` con el array equivalente — confirma
    /// que la variante falible no introduce ninguna transformación
    /// adicional sobre el caso feliz, solo valida la longitud.
    #[test]
    fn from_slice_accepts_exact_length_and_matches_from_bytes() {
        let handshake = EphemeralHandshake::generate();
        let bytes = handshake.public_key().to_bytes();

        let via_from_bytes = EphemeralPublicKey::from_bytes(bytes);
        let via_from_slice = EphemeralPublicKey::from_slice(&bytes)
            .expect("32 bytes exactos debe ser aceptado");

        assert_eq!(via_from_bytes.to_bytes(), via_from_slice.to_bytes());
    }

    // Nota: los tests de límite de HKDF (255*32 = 8160 bytes, RFC 5869
    // §2.3) que existían en el tramo anterior se retiraron junto con
    // `derive_session_key_material` — ese HKDF ya no vive en este
    // módulo. `session.rs::derive_session_key` sigue usando
    // `.expect()` sobre ese límite, justificado ahí porque
    // `SESSION_KEY_LEN` es una constante fija de 32 bytes, muy por
    // debajo del límite, sin ningún `out_len` variable que pudiera
    // dispararlo — ver `session.rs` para ese comentario.
}
