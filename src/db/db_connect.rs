#[cfg(feature = "postgres")]
use sqlx::{PgPool, postgres::PgPoolOptions};

#[cfg(feature = "postgres")]
pub async fn connect_pg(max_conn: u32, db_uri: &str) -> PgPool {
    let pool = PgPoolOptions::new()
        .max_connections(max_conn)
        .connect(db_uri)
        .await
        .unwrap();

    println!("Postgres db connected");

    pool
}

#[cfg(feature = "mysql")]
use sqlx::{MySqlPool, mysql::MySqlPoolOptions};

#[cfg(feature = "mysql")]
pub async fn connect_pg(max_conn: u32, db_uri: &str) -> MySqlPool {
    let pool = MySqlPoolOptions::new()
        .max_connections(max_conn)
        .connect(db_uri)
        .await
        .unwrap();

    println!("MySQL db connected");

    pool
}

#[cfg(feature = "sqlite")]
use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

#[cfg(feature = "sqlite")]
pub async fn connect_pg(max_conn: u32, db_uri: &str) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(max_conn)
        .connect(db_uri)
        .await
        .unwrap();

    println!("SQLite db connected");

    pool
}
