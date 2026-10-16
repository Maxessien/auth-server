use std::{collections::HashMap, sync::Arc};

use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Router, middleware,
    routing::{post, put},
};
use tokio::sync::RwLock;

use crate::{
    controllers::client_controllers::{login_user, register_user, update_user},
    middlewares::auth_middlewares::verify_access_token,
    utils::utils::Tokens,
};

pub type ClientRouterStates = (HashMap<String, String>, AppPool, Arc<RwLock<Tokens>>);

pub fn get_client_router(states: ClientRouterStates) -> Router {
    return Router::new()
        .route(
            "/client/register",
            post(register_user).with_state(states.1.clone()),
        )
        .route("/client/login", post(login_user).with_state(states.clone()))
        .route(
            "/client/update",
            put(update_user)
                .with_state(states.clone())
                .layer(middleware::from_fn_with_state(
                    states.clone(),
                    verify_access_token,
                )),
        );
}
