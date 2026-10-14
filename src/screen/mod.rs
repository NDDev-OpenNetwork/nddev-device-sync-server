pub(crate) mod http;
pub(crate) mod store;
pub use http::routes;

pub fn initialize(pool: sqlx::PgPool, origin: String) -> store::Store {
    store::Store::new(pool, origin)
}
