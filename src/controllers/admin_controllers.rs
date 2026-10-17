use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::{query, query_as};

use crate::{
    models::{
        api_requests::{GetUserRes, UpdateUserAdminReq},
        users::User,
    },
    utils::utils::handle_errs,
};

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

pub type GetUserResType = (StatusCode, Body);
#[derive(Serialize, Deserialize)]
pub struct GetUserQuery {
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

pub async fn update_user(
    State(pool): State<AppPool>,
    Json(body): Json<UpdateUserAdminReq>,
) -> Result<StatusCode, StatusCode> {
    let UpdateUserAdminReq {
        user_name,
        email,
        phone,
        is_verified,
        password,
        user_id,
    } = body;
    let user = handle_errs(
        query_as!(
            User,
            "
        SELECT user_name, email, phone, user_id,
        is_verified, password_hash FROM users WHERE user_id = $1
        ",
            user_id.clone()
        )
        .fetch_one(&pool.pool)
        .await,
        StatusCode::NOT_FOUND,
        "User not found",
    )?;

    let password_hash = match password {
        Some(p) => {
            let argon2 = Argon2::default();
            let password_hash = handle_errs(
                argon2.hash_password(&p.as_bytes()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error decoding password",
            )?
            .to_string();
            password_hash
        }
        None => user.password_hash,
    };

    let res = query!(
        "
        UPDATE users SET user_name = $1, email = $2, phone = $3,
        password_hash = $4, is_verified = $5 WHERE user_id = $6
    ",
        user_name.unwrap_or(user.user_name),
        email.unwrap_or(user.email),
        phone.or(user.phone),
        password_hash,
        is_verified.unwrap_or(user.is_verified),
        user_id
    )
    .execute(&pool.pool)
    .await;

    handle_errs(
        res,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to update user",
    )?;

    Ok(StatusCode::OK)
}

pub async fn delete_user(
    State(pool): State<AppPool>,
    Query(user_id): Query<GetUserQuery>,
) -> Result<StatusCode, StatusCode> {
    handle_errs(
        query!("DELETE FROM users WHERE user_id = $1", user_id.user_id)
            .execute(&pool.pool)
            .await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Error deleting user",
    )?;
    Ok(StatusCode::OK)
}
