pub mod controllers;
pub mod middlewares;
pub mod models;
pub mod queries;
pub mod routes;
pub mod utils;

use std::{sync::Arc, time::Duration};

use auth_server::db::db_connect::connect_mod::{AppPool, connect_pg};
use axum::{Router, http::HeaderValue, routing::get, serve};
use sqlx::query_as;
use tokio::{net::TcpListener, spawn, sync::RwLock, time::sleep};
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    controllers::admin_controllers::verify_tkn,
    queries::app_queries::save_tokens,
    routes::{admin_routes::get_admin_router, client_routes::get_client_router},
    utils::{
        env_loader::{check_env_availability, load_env},
        utils::{Tkns, Tokens, TokensList, handle_errs},
    },
};

#[tokio::main]
async fn main() {
    let env_hashmap = load_env().unwrap();
    let required = [
        "RUNTIME_ENV",
        "DATABASE_URL",
        "JWT_SECRET",
        "ADMIN_KEY",
        "SERVER_URL",
    ];

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

    struct GetDbTkns {
        id: String,
        access_token: String,
        refresh_token: String,
    }

    let res = handle_errs(
        query_as!(GetDbTkns, "SELECT * FROM sessions")
            .fetch_all(&app_pool.pool)
            .await,
        |_| (),
        "Error getting sessions from db",
    )
    .unwrap();

    let mut sess_tkns = Tokens::new();

    for val in res {
        let GetDbTkns {
            id,
            access_token,
            refresh_token,
        } = val;
        sess_tkns.add_token((
            id,
            Tkns {
                access: access_token,
                refresh: refresh_token,
            },
        ));
    }

    let sessions = Arc::new(RwLock::new(sess_tkns));
    let sessions_clone = sessions.clone();
    let app_pool_clone = app_pool.clone();

    spawn(async move {
        loop {
            let mut saved: Vec<String> = Vec::new();

            for (key, val) in sessions_clone.read().await.unsaved.iter() {
                let is_saved = save_tokens(
                    &app_pool_clone,
                    key.clone(),
                    (val.access.clone(), val.refresh.clone()),
                )
                .await;
                if is_saved {
                    saved.push(key.clone());
                }
            }
            let mut lock = sessions_clone.write().await;

            for key in saved {
                if let Some(val) = lock.unsaved.remove(&key) {
                    lock.saved.insert(key, val);
                };
            }
            drop(lock);

            sleep(Duration::from_mins(5)).await;
        }
    });

    let client_routes =
        get_client_router((env_hashmap.clone(), app_pool.clone(), sessions.clone()));
    let admin_routes = get_admin_router((env_hashmap.clone(), app_pool.clone(), sessions.clone()));

    let empty = serde_json::json!([]).to_string();
    let cors_origin: Vec<String> =
        serde_json::from_str(env_hashmap.get("CORS_ORIGIN").unwrap_or(&empty))
            .unwrap_or(Vec::new());

    let app = Router::new()
        .merge(client_routes)
        .merge(admin_routes)
        .route(
            "/verify",
            get(verify_tkn).with_state((env_hashmap, app_pool, sessions)),
        )
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(
                    CorsLayer::permissive().allow_origin(if cors_origin.len() == 0 {
                        vec![]
                    } else {
                        let parsed = cors_origin
                            .iter()
                            .filter(|v| v.parse::<HeaderValue>().is_ok())
                            .map(|v| {
                                v.parse::<HeaderValue>()
                                    .expect(&format!("Failed to parse cors origin: {}", v))
                            });
                        let collected: Vec<HeaderValue> = parsed.collect();
                        collected
                    }),
                ),
        );

    let listener = TcpListener::bind(format!("0.0.0.0:{}", &port))
        .await
        .unwrap();

    println!("Server listening on port: {}", port);

    serve(listener, app).await.unwrap();
}
