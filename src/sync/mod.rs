pub(crate) mod codec;
pub(crate) mod http;
pub(crate) mod store;
mod telemetry;
pub(crate) mod v3;
pub use http::routes;
use nddev_device_sync_application::sync::SyncService;
pub struct Service {
    legacy: SyncService<store::Store>,
    pub(crate) history: store::Store,
}
impl std::ops::Deref for Service {
    type Target = SyncService<store::Store>;
    fn deref(&self) -> &Self::Target {
        &self.legacy
    }
}
pub fn initialize(pool: sqlx::PgPool) -> Service {
    let history = store::Store::new(pool);
    Service {
        legacy: SyncService::new(history.clone()),
        history,
    }
}
