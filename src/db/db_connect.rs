#[cfg(feature = "postgres")]
pub mod connect_mod {
    use sqlx::{PgPool, postgres::PgPoolOptions};

    #[derive(Clone)]
    pub struct AppPool {
        pub pool: PgPool,
    }

    pub async fn connect_pg(max_conn: u32, db_uri: &str) -> PgPool {
        let pool = match PgPoolOptions::new()
            .max_connections(max_conn)
            .connect(db_uri)
            .await
        {
            Ok(val) => val,
            Err(err) => {
                println!("Error connecting to db: {}", err.to_string());
                panic!("");
            }
        };
        println!("Postgres db connected");

        pool
    }
}

#[cfg(feature = "mysql")]
pub mod connect_mod {
    use sqlx::{MySqlPool, mysql::MySqlPoolOptions};

    #[derive(Clone)]
    pub struct AppPool {
        pub pool: MySqlPool,
    }

    pub async fn connect_pg(max_conn: u32, db_uri: &str) -> MySqlPool {
        let pool = match MySqlPoolOptions::new()
            .max_connections(max_conn)
            .connect(db_uri)
            .await
        {
            Ok(val) => val,
            Err(err) => {
                println!("Error connecting to db: {}", err.to_string());
                panic!("");
            }
        };
        println!("MySQL db connected");

        pool
    }
}

#[cfg(feature = "sqlite")]
pub mod connect_mod {
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

    #[derive(Clone)]
    pub struct AppPool {
        pub pool: SqlitePool,
    }

    pub async fn connect_pg(max_conn: u32, db_uri: &str) -> SqlitePool {
        let pool = match SqlitePoolOptions::new()
            .max_connections(max_conn)
            .connect(db_uri)
            .await
        {
            Ok(val) => val,
            Err(err) => {
                println!("Error connecting to db: {}", err.to_string());
                panic!("");
            }
        };
        println!("SQLite db connected");

        pool
    }
}
