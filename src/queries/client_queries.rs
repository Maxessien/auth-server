use auth_server::db::db_connect::connect_mod::AppPool;

use serde_json::json;

#[cfg(feature = "postgres")]
use sqlx::postgres::PgQueryResult;

#[cfg(feature = "mysql")]
use sqlx::mysql::MySqlQueryResult;

#[cfg(feature = "sqlite")]
use sqlx::sqlite::SqliteQueryResult;

use sqlx::{Error, query_as};

use sqlx::{query, types::chrono::Utc};
use uuid::Uuid;

use crate::models::api_requests::{AvailableField, RegisterReqBody};
use crate::models::users::{IsVerified, User};

#[cfg(feature = "postgres")]
type AppQueryResult = PgQueryResult;

#[cfg(feature = "mysql")]
type AppQueryResult = MySqlQueryResult;

#[cfg(feature = "sqlite")]
type AppQueryResult = SqliteQueryResult;

pub async fn register_user_query(
    body: RegisterReqBody,
    password_hash: String,
    pool: &AppPool,
) -> Result<AppQueryResult, Error> {
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

    query_val.execute(&pool.pool).await
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
            WHERE phone = $1
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
