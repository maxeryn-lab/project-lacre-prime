//! lacre-domain — application logic shared by all Adapters:
//! wire DTOs (`wire`), domain operations, session stores and `AppState`.
//! It knows neither axum nor any concrete transport protocol.
pub mod admission;
pub mod app_state;
pub mod capability;
pub mod domain;
pub mod profile_config;
pub mod rulesets;
pub mod version;
pub mod seal_policy;
pub mod sealer_session_store;
pub mod session_store;
pub mod toolchain_session_store;
pub mod verifier_session_store;
pub mod wire;
