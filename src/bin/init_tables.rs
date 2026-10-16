use std::env::var;

use auth_server::db::db_connect::connect_mod::{AppPool, connect_pg};
use sqlx::{Error, postgres::PgQueryResult, query};

#[cfg(feature = "postgres")]
type AppQueryResult = PgQueryResult;

#[cfg(feature = "mysql")]
type AppQueryResult = MySqlQueryResult;

#[cfg(feature = "sqlite")]
type AppQueryResult = SqliteQueryResult;

fn wrapper(result: Result<AppQueryResult, Error>) {
    match result {
        Ok(_) => (),
        Err(err) => {
            println!("Error creating table: {}", err.to_string());
            panic!("")
        }
    };
    ()
}

async fn create_user_table(pool: &AppPool) {
    let res = query!(
        "
        CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        user_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT UNIQUE,
        is_verified TEXT NOT NULL,
        last_login TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    "
    )
    .execute(&pool.pool)
    .await;
    wrapper(res)
}

async fn create_sessions_table(pool: &AppPool) {
    let res = query!(
        "
        CREATE TABLE IF NOT EXISTS sessions (
        id TEXT NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL
        )
    "
    )
    .execute(&pool.pool)
    .await;

    wrapper(res)
}

async fn create_tables(pool: &AppPool) {
    create_user_table(pool).await;
    create_sessions_table(pool).await;
}

#[tokio::main]
async fn main() {
    let db_pool = connect_pg(5, &var("DATABASE_URL").unwrap()).await;
    let app_pool = AppPool { pool: db_pool };

    create_tables(&app_pool).await;
}
