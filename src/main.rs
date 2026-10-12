pub mod routes;
pub mod utils;

use axum::{Router, serve};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    routes::{admin_routes::get_admin_router, client_routes::get_client_router},
    utils::env_loader::load_env,
};

#[tokio::main]
async fn main() {
    let env_hashmap = load_env().unwrap();

    let port = match env_hashmap.get("PORT") {
        Some(port) => port.to_string(),
        None => "4000".to_string(),
    };

    let client_routes = get_client_router();
    let admin_routes = get_admin_router();

    let app = Router::new()
        .with_state(env_hashmap)
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

    println!("Server running on port: {}", port);

    serve(listener, app).await.unwrap();
}
