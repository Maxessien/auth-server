use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};

use crate::{models::api_requests::RegisterReqBody, queries::client_queries::register_user_query};

pub async fn register_user(
    Json(body): Json<RegisterReqBody>,
    State(pool): State<AppPool>,
) -> impl IntoResponse {
    let query_res = register_user_query(&body).execute(&pool.pool).await;

    if let Err(err) = query_res {
        return match err.as_database_error() {
            Some(error) => {
                if error.is_unique_violation() {
                    StatusCode::CONFLICT
                } else if error.is_check_violation() {
                    StatusCode::NOT_ACCEPTABLE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            }
            None => StatusCode::INTERNAL_SERVER_ERROR,
        };
    }

    StatusCode::CREATED
}
