use std::collections::HashMap;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Json,
    body::Body,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, Redirect},
};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use sqlx::{query, query_as};

use crate::{
    models::{
        api_requests::{
            GetUserQuery, GetUserRes, GetUserResType, GetUsersResType, InitVerificationBody,
            InitVerificationClaims, InitVerificationRes, UpdateUserAdminReq, VerifyTknQuery,
        },
        users::User,
    },
    utils::{
        controller_helpers::get_html_content,
        utils::{JWT_ALGORITHM, handle_errs},
    },
};

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
            |_| (StatusCode::INTERNAL_SERVER_ERROR, Json(Vec::new())),
            "Failed to get users",
        )?),
    ))
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
                |_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Body::new("Server err".to_string()),
                    )
                },
                "Failed to get users",
            )?),
            |_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Body::new("Server err".to_string()),
                )
            },
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
        |_| StatusCode::NOT_FOUND,
        "User not found",
    )?;

    let password_hash = match password {
        Some(p) => {
            let argon2 = Argon2::default();
            let password_hash = handle_errs(
                argon2.hash_password(&p.as_bytes()),
                |_| StatusCode::INTERNAL_SERVER_ERROR,
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
        |_| StatusCode::INTERNAL_SERVER_ERROR,
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
        |_| StatusCode::INTERNAL_SERVER_ERROR,
        "Error deleting user",
    )?;
    Ok(StatusCode::OK)
}

pub async fn init_verification_url(
    State(env_map): State<HashMap<String, String>>,
    Json(body): Json<InitVerificationBody>,
) -> Result<(StatusCode, Json<InitVerificationRes>), StatusCode> {
    let InitVerificationBody {
        verification_type,
        value,
        redirect_uri,
    } = body;
    if verification_type != "email" && verification_type != "phone" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let jwt_secret = env_map
        .get("JWT_SECRET")
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let header = Header::new(JWT_ALGORITHM);
    let key = EncodingKey::from_secret(jwt_secret.as_bytes());

    let encoding = handle_errs(
        jsonwebtoken::encode(
            &header,
            &InitVerificationClaims {
                expires_at: Utc::now().timestamp() + (5 * 60),
                redirect_uri,
                value,
                verification_type,
            },
            &key,
        ),
        |_| StatusCode::INTERNAL_SERVER_ERROR,
        "Error encoding verification url",
    )?;

    let server_url = env_map
        .get("SERVER_URL")
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let url = format!("{}/verify?token={}", server_url, encoding);

    Ok((
        StatusCode::OK,
        Json(InitVerificationRes {
            verification_url: url,
        }),
    ))
}

pub async fn verify_tkn(
    State(env_map): State<HashMap<String, String>>,
    Query(tkn): Query<VerifyTknQuery>,
) -> Result<Redirect, Html<String>> {
    let jwt_secret = env_map
        .get("JWT_SECRET")
        .ok_or(Html(get_html_content("Server Error")))?;

    let key = DecodingKey::from_secret(jwt_secret.as_bytes());
    let validation = Validation::new(JWT_ALGORITHM);

    let decoded: InitVerificationClaims = handle_errs(
        jsonwebtoken::decode(tkn.token.as_bytes(), &key, &validation),
        |_| Html(get_html_content("Invalid Verfication url")),
        "Error decoding verification tkn",
    )?
    .claims;

    let now = Utc::now().timestamp();

    if now > decoded.expires_at {
        return Err(Html(get_html_content("Verification token has expired")));
    }

    Ok(Redirect::to(&decoded.redirect_uri))
}
