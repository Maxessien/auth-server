use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use auth_server::db::db_connect::connect_mod::AppPool;
use axum::{
    Extension, Json,
    body::Body,
    extract::State,
    http::{Extensions, HeaderMap, HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use sqlx::query;

use crate::{
    models::{
        api_requests::{AvailableField, LoginReqBody, RegisterReqBody, UpdateUserReqBody},
        users::DecodedAccessTkn,
    },
    queries::client_queries::{login_user_query, register_user_query},
    routes::client_routes::ClientRouterStates,
    utils::{
        controller_helpers::{build_cookies, build_tokens},
        utils::{AppErrors, AuthServerErrors, TokensList},
    },
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

#[axum::debug_handler]
pub async fn login_user(
    jar: CookieJar,
    req_headers: HeaderMap,
    State(state): State<ClientRouterStates>,
    Json(body): Json<LoginReqBody>,
) -> (CookieJar, Response<Body>) {
    let (env_map, pool, sessions) = state;
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
                return (
                    jar,
                    Response::from_parts(
                        res_parts,
                        Body::new("Email or phone required".to_string()),
                    ),
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
            return (jar, Response::from_parts(res_parts, app_err.as_http_body()));
        }
    };

    let hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return (jar, Response::from_parts(res_parts, app_err.as_http_body()));
        }
    };

    let argon = Argon2::default();

    if !argon
        .verify_password(body.password.as_bytes(), &hash)
        .is_ok()
    {
        res_parts.status = StatusCode::UNAUTHORIZED;
        return (
            jar,
            Response::from_parts(res_parts, Body::new("Invalid password".to_string())),
        );
    }

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return (
                jar,
                Response::from_parts(res_parts, Body::new("Server error".to_string())),
            );
        }
    };

    let (access_token, refresh_token) = build_tokens(jwt_secret, &user, &sessions).await;

    let origin = match req_headers.get(header::ORIGIN) {
        Some(val) => match val.to_str() {
            Ok(v) => v.to_string(),
            Err(err) => {
                let app_err =
                    AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
                app_err.log();

                return (jar, Response::from_parts(res_parts, app_err.as_http_body()));
            }
        },
        None => {
            res_parts.status = StatusCode::BAD_REQUEST;
            return (
                jar,
                Response::from_parts(res_parts, Body::new(String::from("Bad request"))),
            );
        }
    };

    let res_body = match serde_json::to_string(&user) {
        Ok(val) => val,
        Err(err) => {
            let app_err =
                AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
            app_err.log();

            return (jar, Response::from_parts(res_parts, app_err.as_http_body()));
        }
    };

    let updated_jar = build_cookies(env_map, access_token, refresh_token, origin, jar).await;

    (
        updated_jar,
        Response::from_parts(res_parts, Body::from(res_body.as_bytes().to_owned())),
    )
}

pub async fn update_user(
    Extension(access_tkn): Extension<DecodedAccessTkn>,
    State(state): State<ClientRouterStates>,
    Json(body): Json<UpdateUserReqBody>,
) -> impl IntoResponse {
    let UpdateUserReqBody {
        user_name,
        password,
        email,
        phone,
    } = body;

    let password_hash = match password {
        Some(p) => {
            let argon2 = Argon2::default();
            let password_hash = match argon2.hash_password(&p.as_bytes()) {
                Ok(hash) => hash.to_string(),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
            };
            password_hash
        }
        None => access_tkn.user_info.password_hash,
    };

    match query!(
        "
        UPDATE users SET user_name = $1, password_hash = $2, email = $3, phone = $4
        WHERE user_id = $5
        ",
        user_name.unwrap_or(access_tkn.user_info.user_name),
        password_hash,
        email.unwrap_or(access_tkn.user_info.email),
        phone,
        access_tkn.user_info.user_id
    )
    .execute(&state.1.pool)
    .await
    {
        Ok(_) => (),
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Couldn't update user",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    StatusCode::OK
}

pub async fn refresh_access_token(
    Extension(access_tkn): Extension<DecodedAccessTkn>,
    State(state): State<ClientRouterStates>,
    req_headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    let (env_map, pool, sessions) = state;
    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            return (jar, StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let mut lock = sessions.write().await;

    lock.revoke(&access_tkn.iss_id);

    drop(lock);

    match query!("DELETE FROM sessions WHERE id = $1", access_tkn.iss_id)
        .execute(&pool.pool)
        .await
    {
        Ok(_) => (),
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Couldn't refresh user token",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            return (jar, StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let (access_token, refresh_token) =
        build_tokens(jwt_secret, &access_tkn.user_info, &sessions).await;

    let origin = match req_headers.get(header::ORIGIN) {
        Some(val) => match val.to_str() {
            Ok(v) => v.to_string(),
            Err(err) => {
                let app_err =
                    AppErrors::new(err.to_string(), "Server error", line!(), column!(), file!());
                app_err.log();

                return (jar, StatusCode::INTERNAL_SERVER_ERROR);
            }
        },
        None => {
            return (jar, StatusCode::BAD_REQUEST);
        }
    };

    let updated_jar = build_cookies(env_map, access_token, refresh_token, origin, jar).await;
    (updated_jar, StatusCode::OK)
}
