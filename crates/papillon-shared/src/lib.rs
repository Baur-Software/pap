pub mod events;
pub mod intent;
pub mod template_gen;
pub mod types;

// Re-export PAP URI resolution from pap-transport where it logically belongs.
pub use pap_transport::uri::{resolve_pap_uri, LinkOrigin, PapUriError, ResolvedUri};

#[cfg(any(feature = "native", feature = "wasm"))]
pub mod db;

pub use events::*;
pub use template_gen::generate_template_from_json_ld;
pub use types::*;
