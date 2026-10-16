use auth_server::db::db_connect::connect_mod::AppPool;

use serde_json::json;
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
use sqlx::{Error, query_as};

use sqlx::query::Query;
use sqlx::{query, types::chrono::Utc};
use uuid::Uuid;

use crate::models::api_requests::{AvailableField, RegisterReqBody};
use crate::models::users::{IsVerified, User};

#[cfg(feature = "postgres")]
type QueryType<'a> = Query<'a, Postgres, PgArguments>;

#[cfg(feature = "mysql")]
type QueryType<'a> = Query<'a, MySql, MySqlArguments>;

#[cfg(feature = "sqlite")]
type QueryType<'a> = Query<'a, Sqlite, SqliteArguments>;

pub fn register_user_query(body: &RegisterReqBody, password_hash: String) -> QueryType<'_> {
    let RegisterReqBody {
        user_name,
        password: _,
        email,
        phone,
    } = body;
    let is_verified = match serde_json::to_string(&IsVerified {
        email: false,
        phone: false,
    }) {
        Ok(val) => val,
        Err(_) => json!({
            "email": false, "phone": false
        })
        .to_string(),
    };
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
        password_hash,
        email,
        phone,
        is_verified,
        uuid,
        now,
        now
    );

    #[cfg(not(feature = "postgres"))]
    let query_val = query!(
        "
            INSERT INTO users (user_name, password_hash, email, phone, is_verified, user_id,
            created_at, updated_at) VALUES
            (?, ?, ?, ?, ?, ?, ?, ?)
        ",
        user_name,
        password_hash,
        email,
        phone,
        is_verified,
        uuid,
        now,
        now
    );

    query_val
}

pub async fn login_user_query(
    field: AvailableField,
    value: String,
    pool: &AppPool,
) -> Result<User, Error> {
    #[cfg(feature = "postgres")]
    if let AvailableField::Email = field {
        return query_as!(
            User,
            "
            SELECT user_id, password_hash, email, phone, is_verified, user_name FROM users
            WHERE email = $1
        ",
            value
        )
        .fetch_one(&pool.pool)
        .await;
    } else {
        return query_as!(
            User,
            "
            SELECT user_id, password_hash, email, phone, is_verified, user_name FROM users
            WHERE email = $1
        ",
            value,
        )
        .fetch_one(&pool.pool)
        .await;
    }

    #[cfg(not(feature = "postgres"))]
    if let AvailableField::Email = field {
        return query_as!(
            User,
            "
                SELECT user_id, password_hash, email, phone, is_verified, user_name FROM users
                WHERE email = ?
            ",
            value
        )
        .fetch_one(&pool.pool)
        .await;
    } else {
        return query_as!(
            User,
            "
                SELECT user_id, password_hash, email, phone, is_verified, user_name FROM users
                WHERE email = ?
            ",
            value,
        )
        .fetch_one(&pool.pool)
        .await;
    }
}
