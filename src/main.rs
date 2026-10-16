pub mod controllers;
pub mod models;
pub mod queries;
pub mod routes;
pub mod utils;

use std::{sync::Arc, time::Duration};

use auth_server::db::db_connect::connect_mod::{AppPool, connect_pg};
use axum::{Router, serve};
use tokio::{net::TcpListener, spawn, sync::RwLock, time::sleep};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    routes::{admin_routes::get_admin_router, client_routes::get_client_router},
    utils::{
        env_loader::{check_env_availability, load_env},
        utils::{Tokens, TokensList},
    },
};

#[tokio::main]
async fn main() {
    let env_hashmap = load_env().unwrap();
    let required = ["RUNTIME_ENV", "DATABASE_URL", "JWT_SECRET"];

    let (has_missing, missing) = check_env_availability(&env_hashmap, required.to_vec());

    if !has_missing {
        println!("Some required env vars are missing: {:?}", missing);
        panic!("")
    };

    let max_conn: u32 = match env_hashmap.get("MAX_DB_CONN") {
        Some(conn) => conn.parse().unwrap(),
        None => 5,
    };

    let db_pool = connect_pg(max_conn, env_hashmap.get("DATABASE_URL").unwrap()).await;
    let app_pool = AppPool { pool: db_pool };

    let port = match env_hashmap.get("PORT") {
        Some(port) => port.to_string(),
        None => "4000".to_string(),
    };

    let client_routes = get_client_router();
    let admin_routes = get_admin_router();

    let sessions = Arc::new(RwLock::new(Tokens::new()));
    let sessions_clone = sessions.clone();

    spawn(async move {
        loop {
            for (key, val) in sessions_clone.read().await.unsaved.iter() {}
            sleep(Duration::from_mins(5)).await;
        }
    });

    let app = Router::new()
        .with_state(env_hashmap)
        .with_state(app_pool)
        .with_state(sessions)
        .merge(client_routes)
        .merge(admin_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::new()),
        );

    let listener = TcpListener::bind(format!("0.0.0.0:{}", &port))
        .await
        .unwrap();

    println!("Server listening on port: {}", port);

    serve(listener, app).await.unwrap();
}
