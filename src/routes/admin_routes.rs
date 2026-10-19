use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};

use crate::{
    controllers::admin_controllers::{
        delete_user, get_user, get_users, init_verification_url, update_user,
    },
    middlewares::auth_middlewares::verify_admin_key,
    routes::client_routes::ClientRouterStates,
};

pub fn get_admin_router(states: ClientRouterStates) -> Router {
    return Router::new()
        .layer(middleware::from_fn_with_state(
            states.0.clone(),
            verify_admin_key,
        ))
        .route("/admin/user", get(get_user).with_state(states.1.clone()))
        .route("/admin/users", get(get_users).with_state(states.1.clone()))
        .route("/admin/user", put(update_user).with_state(states.1.clone()))
        .route("/admin/user", delete(delete_user).with_state(states.1))
        .route(
            "/admin/verify",
            post(init_verification_url).with_state(states.0.clone()),
        );
}
