use std::collections::HashMap;

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use jsonwebtoken::{EncodingKey, Header};
use serde_json::json;
use sqlx::types::chrono::Utc;
use uuid::Uuid;

use crate::{
    models::{
        api_requests::{AvailableField, LoginReqBody, LoginResBody, RegisterReqBody},
        users::{DecodedAccessTkn, DecodedRefreshTkn},
    },
    queries::client_queries::{login_user_query, register_user_query},
};

pub async fn register_user(
    State(pool): State<AppPool>,
    Json(body): Json<RegisterReqBody>,
) -> impl IntoResponse {
    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(&body.password.as_bytes()) {
        Ok(hash) => hash.to_string(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let query_res = register_user_query(&body, password_hash)
        .execute(&pool.pool)
        .await;

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

pub async fn login_user(
    Json(body): Json<LoginReqBody>,
    State(pool): State<AppPool>,
    State(env_map): State<HashMap<String, String>>,
) -> impl IntoResponse {
    let info = match body.email {
        Some(email) => login_user_query(AvailableField::Email, email, &pool).await,
        None => match body.phone {
            Some(phone) => login_user_query(AvailableField::Phone, phone, &pool).await,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json("Email or phone required".to_string()),
                );
            }
        },
    };

    let user = match info {
        Ok(val) => val,
        Err(err) => {
            // Implement logger for err
            println!("Error querying db for user: {}", err.to_string());

            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Server error".to_string()),
            );
        }
    };

    let hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(err) => {
            println!("Error hashing password: {}", err.to_string());
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Server error".to_string()),
            );
        }
    };

    let argon = Argon2::default();

    if !argon
        .verify_password(body.password.as_bytes(), &hash)
        .is_ok()
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json("Invalid password".to_string()),
        );
    }

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            println!("Env var not found");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json("Server error".to_string()),
            );
        }
    };

    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let encoding_header = Header::default();

    let access_iss_id = Uuid::new_v4().to_string();
    let refresh_iss_id = Uuid::new_v4().to_string();

    let access_claims = DecodedAccessTkn {
        expires_at_sec: Utc::now().timestamp() + (60 * 60),
        issued_at_sec: Utc::now().timestamp(),
        iss_id: access_iss_id.clone(),
        user_info: user.clone(),
    };

    let refresh_claims = DecodedRefreshTkn {
        expires_at_sec: Utc::now().timestamp() + (60 * 60 * 24),
        issued_at_sec: Utc::now().timestamp(),
        iss_id: refresh_iss_id.clone(),
    };

    let access_token =
        jsonwebtoken::encode(&encoding_header, &access_claims, &encoding_key).unwrap();

    let refresh_token =
        jsonwebtoken::encode(&encoding_header, &refresh_claims, &encoding_key).unwrap();

    (
        StatusCode::OK,
        Json(
            json!(LoginResBody {
                user,
                access_token,
                refresh_token,
            })
            .to_string(),
        ),
    )
}
