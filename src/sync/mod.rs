mod http;
mod store;
pub use http::routes;
use nddev_device_sync_application::sync::SyncService;
pub type Service = SyncService<store::Store>;
pub fn initialize(pool: sqlx::PgPool) -> Service {
    SyncService::new(store::Store::new(pool))
}
