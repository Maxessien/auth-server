use std::{collections::HashMap, sync::Arc};

use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{Router, routing::post};
use tokio::sync::RwLock;

use crate::{
    controllers::client_controllers::{login_user, register_user},
    utils::utils::Tokens,
};

pub type ClientRouterStates = (HashMap<String, String>, AppPool, Arc<RwLock<Tokens>>);

pub fn get_client_router(states: ClientRouterStates) -> Router {
    return Router::new()
        .route(
            "/client/register",
            post(register_user).with_state(states.1.clone()),
        )
        .route("/client/login", post(login_user).with_state(states));
}
