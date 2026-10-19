use auth_server::db::db_connect::connect_mod::AppPool;
use sqlx::{Error, query};

#[cfg(feature = "postgres")]
use sqlx::postgres::PgQueryResult;

#[cfg(feature = "mysql")]
use sqlx::mysql::MySqlQueryResult;

#[cfg(feature = "sqlite")]
use sqlx::sqlite::SqliteQueryResult;

#[cfg(feature = "postgres")]
type AppQueryResult = PgQueryResult;

#[cfg(feature = "mysql")]
type AppQueryResult = MySqlQueryResult;

#[cfg(feature = "sqlite")]
type AppQueryResult = SqliteQueryResult;

pub async fn update_verified(
    verification_type: &str,
    val: String,
    pool: &AppPool,
) -> Result<AppQueryResult, Error> {
    if verification_type == "email" {
        query!(
            "
            UPDATE users SET email_verified = $1 WHERE email = $2
            ",
            true,
            val
        )
        .execute(&pool.pool)
        .await
    } else {
        query!(
            "
            UPDATE users SET phone_verified = $1 WHERE phone = $2
            ",
            true,
            val
        )
        .execute(&pool.pool)
        .await
    }
}
