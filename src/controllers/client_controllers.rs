use std::{collections::HashMap, sync::Arc};

use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Extensions, HeaderMap, HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use jsonwebtoken::{EncodingKey, Header};
use sqlx::types::chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    models::{
        api_requests::{AvailableField, LoginReqBody, LoginResBody, RegisterReqBody},
        users::{DecodedAccessTkn, DecodedRefreshTkn},
    },
    queries::client_queries::{login_user_query, register_user_query},
    utils::utils::{AppErrors, AuthServerErrors, Tkns, Tokens, TokensList},
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
    State(sessions): State<Arc<RwLock<Tokens>>>,
) -> impl IntoResponse {
    let mut res_header = HeaderMap::new();
    res_header.append(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let (mut res_parts, _) = Response::new(()).into_parts();

    res_parts.headers = res_header;
    res_parts.extensions = Extensions::default();

    let info = match body.email {
        Some(email) => login_user_query(AvailableField::Email, email, &pool).await,
        None => match body.phone {
            Some(phone) => login_user_query(AvailableField::Phone, phone, &pool).await,
            None => {
                res_parts.status = StatusCode::BAD_REQUEST;
                return Response::from_parts(
                    res_parts,
                    Body::new("Email or phone required".to_string()),
                );
            }
        },
    };

    let user = match info {
        Ok(val) => val,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Response::from_parts(res_parts, app_err.as_http_body());
        }
    };

    let hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Response::from_parts(res_parts, app_err.as_http_body());
        }
    };

    let argon = Argon2::default();

    if !argon
        .verify_password(body.password.as_bytes(), &hash)
        .is_ok()
    {
        res_parts.status = StatusCode::UNAUTHORIZED;
        return Response::from_parts(res_parts, Body::new("Invalid password".to_string()));
    }

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Response::from_parts(res_parts, Body::new("Server error".to_string()));
        }
    };

    let encoding_key = EncodingKey::from_secret(jwt_secret.as_bytes());
    let encoding_header = Header::default();

    let iss_id = Uuid::new_v4().to_string();

    let access_claims = DecodedAccessTkn {
        expires_at_sec: Utc::now().timestamp() + (60 * 60),
        issued_at_sec: Utc::now().timestamp(),
        iss_id: iss_id.clone(),
        user_info: user.clone(),
    };

    let refresh_claims = DecodedRefreshTkn {
        expires_at_sec: Utc::now().timestamp() + (60 * 60 * 24),
        issued_at_sec: Utc::now().timestamp(),
        iss_id: iss_id.clone(),
    };

    let access_token =
        jsonwebtoken::encode(&encoding_header, &access_claims, &encoding_key).unwrap();

    let refresh_token =
        jsonwebtoken::encode(&encoding_header, &refresh_claims, &encoding_key).unwrap();

    let acc_tkn_cookie = match HeaderValue::from_str(&access_token) {
        Ok(val) => val,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Response::from_parts(res_parts, app_err.as_http_body());
        }
    };

    res_parts.headers.append(header::COOKIE, acc_tkn_cookie);

    let mut lock = sessions.write().await;

    lock.add_token((
        iss_id,
        Tkns {
            access: access_token.clone(),
            refresh: refresh_token.clone(),
            algorithm: encoding_header.alg,
        },
    ));

    let login_res = LoginResBody {
        user,
        access_token,
        refresh_token,
    };

    let res_body = match serde_json::to_string(&login_res) {
        Ok(val) => val,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            return Response::from_parts(res_parts, app_err.as_http_body());
        }
    };

    res_parts.status = StatusCode::OK;
    Response::from_parts(res_parts, Body::from(res_body.as_bytes().to_owned()))
}
