use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
};
use sqlx::query_as;

use crate::{models::api_requests::GetUserRes, utils::utils::handle_errs};

type GetUsersResType = (StatusCode, Json<Vec<GetUserRes>>);

pub async fn get_users(State(pool): State<AppPool>) -> Result<GetUsersResType, GetUsersResType> {
    let res = query_as!(
        GetUserRes,
        "
        SELECT user_name, email, phone, user_id,
        is_verified, last_login, created_at, updated_at FROM users
    "
    )
    .fetch_all(&pool.pool)
    .await;

    Ok((
        StatusCode::OK,
        Json(handle_errs(
            res,
            (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
            "Failed to get users",
        )?),
    ))
}

type GetUserResType = (StatusCode, Body);
struct GetUserQuery {
    user_id: String,
}
pub async fn get_user(
    State(pool): State<AppPool>,
    Query(user_id): Query<GetUserQuery>,
) -> Result<GetUserResType, GetUserResType> {
    let res = query_as!(
        GetUserRes,
        "
        SELECT user_name, email, phone, user_id,
        is_verified, last_login, created_at, updated_at FROM users
        WHERE user_id = $1
    ",
        user_id.user_id
    )
    .fetch_one(&pool.pool)
    .await;

    Ok((
        StatusCode::OK,
        Body::from(handle_errs(
            serde_json::to_vec(&handle_errs(
                res,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::new("Server err".to_string()),
                ),
                "Failed to get users",
            )?),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::new("Server err".to_string()),
            ),
            "Failed to get user",
        )?),
    ))
}
