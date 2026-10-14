use axum::{
    Json,
    extract::State,
    http::{Response, StatusCode, header},
    response::IntoResponse,
};
use sqlx::query;

use crate::{db::db_connect::connect_mod::AppPool, models::api_requests::RegisterReqBody};

pub async fn register_user(
    Json(body): Json<RegisterReqBody>,
    State(pool): State<AppPool>,
) -> impl IntoResponse {
    // query!("
    //         INSERT INTO users (user_name, password_hash, email, phone, is_verified, user_id, access_token,
    //         refresh_token, last_login, created_at, updated_at) VALUES
    //         ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    //     ");

    let res = Response::builder()
        .status(StatusCode::CREATED)
        .header(header::CONTENT_TYPE, "application/json")
        .body("body".to_string())
        .unwrap();
    res
}
