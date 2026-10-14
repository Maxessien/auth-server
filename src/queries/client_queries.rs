#[cfg(feature = "postgres")]
use sqlx::Postgres;

#[cfg(feature = "postgres")]
use sqlx::postgres::PgArguments;

#[cfg(feature = "mysql")]
use sqlx::MySql;

#[cfg(feature = "mysql")]
use sqlx::mysql::MySqlArguments;

#[cfg(feature = "sqlite")]
use sqlx::Sqlite;

#[cfg(feature = "sqlite")]
use sqlx::sqlite::SqliteArguments;

use sqlx::query::Query;
use sqlx::types::JsonValue;
use sqlx::{query, types::chrono::Utc};
use uuid::Uuid;

use crate::models::api_requests::RegisterReqBody;

#[cfg(feature = "postgres")]
type QueryType<'a> = Query<'a, Postgres, PgArguments>;

#[cfg(feature = "mysql")]
type QueryType<'a> = Query<'a, MySql, MySqlArguments>;

#[cfg(feature = "sqlite")]
type QueryType<'a> = Query<'a, Sqlite, SqliteArguments>;

pub fn register_user_query(body: &RegisterReqBody) -> QueryType<'_> {
    let RegisterReqBody {
        user_name,
        password,
        email,
        phone,
    } = body;
    let is_verified = "{}".to_string();
    // let is_verified = IsVerified {
    //     email: false,
    //     phone: false,
    // };
    let uuid = Uuid::new_v4().to_string();
    let now = Utc::now();

    let phone = phone.as_deref().expect("NULL");

    #[cfg(feature = "postgres")]
    let query_val = query!(
        "
            INSERT INTO users (user_name, password_hash, email, phone, is_verified, user_id,
            created_at, updated_at) VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8)
        ",
        user_name,
        password,
        email,
        phone,
        JsonValue::String(is_verified),
        uuid,
        now,
        now
    );

    query_val
}
