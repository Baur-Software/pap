pub mod duckduckgo;
pub mod frankfurter;
pub mod hacker_news;
pub mod nominatim;
pub mod on_device_ai;
pub mod open_library;
pub mod open_meteo;
mod session_store;
pub mod wikipedia;

pub use duckduckgo::DuckDuckGoAgent;
pub use frankfurter::FrankfurterAgent;
pub use hacker_news::HackerNewsAgent;
pub use nominatim::NominatimAgent;
pub use on_device_ai::OnDeviceAiAgent;
pub use open_library::OpenLibraryAgent;
pub use open_meteo::OpenMeteoAgent;
pub use wikipedia::WikipediaAgent;
