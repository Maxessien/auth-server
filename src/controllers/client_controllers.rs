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
use chrono::Utc;
use sqlx::{query, query_as};

use crate::{
    models::{
        api_requests::{
            AvailableField, LoginReqBody, LoginRes, RegisterReqBody, UpdateUserReqBody,
        },
        users::{DecodedAccessTkn, User, UserWithoutPassword},
    },
    queries::client_queries::{login_user_query, register_user_query},
    routes::client_routes::ClientRouterStates,
    utils::{
        controller_helpers::{build_cookies, build_tokens},
        utils::{TokensList, handle_errs, handle_errs_with_return},
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

    let query_res = register_user_query(body, password_hash, &pool).await;

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
    jar: CookieJar,
    req_headers: HeaderMap,
    State(state): State<ClientRouterStates>,
    Json(body): Json<LoginReqBody>,
) -> Result<LoginRes, LoginRes> {
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
                return Err((
                    jar,
                    Response::from_parts(
                        res_parts,
                        Body::new("Email or phone required".to_string()),
                    ),
                ));
            }
        },
    };

    let ser_err_msg = "Server error";
    let mut res_parts_clone = res_parts.clone();
    res_parts_clone.status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut ser_err: LoginRes = (
        jar.clone(),
        Response::from_parts(res_parts_clone, Body::new(ser_err_msg.to_string())),
    );

    let (user, err) = handle_errs_with_return(info, ser_err, ser_err_msg)?;
    let User {
        user_name,
        password_hash,
        email,
        phone,
        is_verified,
        user_id,
    } = user.clone();
    let user_without_password = UserWithoutPassword {
        user_id: user_id.clone(),
        email,
        user_name,
        is_verified,
        phone,
    };
    ser_err = err;

    let (hash, err) =
        handle_errs_with_return(PasswordHash::new(&password_hash), ser_err, ser_err_msg)?;
    ser_err = err;

    let argon = Argon2::default();

    if !argon
        .verify_password(body.password.as_bytes(), &hash)
        .is_ok()
    {
        res_parts.status = StatusCode::UNAUTHORIZED;
        return Err((
            jar,
            Response::from_parts(res_parts, Body::new("Invalid password".to_string())),
        ));
    }

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            res_parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Err((
                jar,
                Response::from_parts(res_parts, Body::new("Server error".to_string())),
            ));
        }
    };

    let (access_token, refresh_token) =
        build_tokens(jwt_secret, &user_without_password, &sessions).await;

    let origin = match req_headers.get(header::ORIGIN) {
        Some(val) => {
            let (v, err) = handle_errs_with_return(val.to_str(), ser_err, ser_err_msg)?;
            ser_err = err;
            v.strip_prefix("http://")
                .or_else(|| v.strip_prefix("https://"))
                .unwrap_or(v)
                .to_string()
        }
        None => {
            res_parts.status = StatusCode::BAD_REQUEST;
            return Err((
                jar,
                Response::from_parts(res_parts, Body::new(String::from("Bad request"))),
            ));
        }
    };

    let res_body = handle_errs(serde_json::to_vec(&user), ser_err, ser_err_msg)?;

    let updated_jar = build_cookies(env_map, access_token, refresh_token, origin, jar).await;

    let msg = "Failed last login update";
    let now = Utc::now();

    // Failed update shouldn't affect successful login
    let _ = handle_errs(
        query!(
            "UPDATE users SET last_login = $1 WHERE user_id = $2",
            now,
            user_id
        )
        .execute(&pool.pool)
        .await,
        msg.to_string(),
        msg,
    );

    Ok((
        updated_jar,
        Response::from_parts(res_parts, Body::from(res_body)),
    ))
}

pub struct GetPasswordHash {
    password_hash: String,
}

pub async fn update_user(
    Extension(access_tkn): Extension<DecodedAccessTkn>,
    State(state): State<ClientRouterStates>,
    Json(body): Json<UpdateUserReqBody>,
) -> Result<StatusCode, StatusCode> {
    let UpdateUserReqBody {
        user_name,
        password,
        email,
        phone,
    } = body;

    let password_hash = match password {
        Some(p) => {
            let argon2 = Argon2::default();
            let password_hash = handle_errs(
                argon2.hash_password(&p.as_bytes()),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error getting password hash",
            )?
            .to_string();
            password_hash
        }
        None => {
            let res = handle_errs(
                query_as!(
                    GetPasswordHash,
                    "SELECT password_hash FROM users WHERE user_id = $1",
                    access_tkn.user_info.user_id
                )
                .fetch_one(&state.1.pool)
                .await,
                StatusCode::NOT_FOUND,
                "Error getting stored user password hash",
            )?;
            res.password_hash
        }
    };

    handle_errs(
        query!(
            "
        UPDATE users SET user_name = $1, password_hash = $2, email = $3, phone = $4
        WHERE user_id = $5
        ",
            user_name.unwrap_or(access_tkn.user_info.user_name),
            password_hash,
            email.unwrap_or(access_tkn.user_info.email),
            phone.or(access_tkn.user_info.phone),
            access_tkn.user_info.user_id
        )
        .execute(&state.1.pool)
        .await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "Couldn't update user",
    )?;

    Ok(StatusCode::OK)
}

type RefreshAccessTknRes = (CookieJar, StatusCode);
pub async fn refresh_access_token(
    Extension(access_tkn): Extension<DecodedAccessTkn>,
    State(state): State<ClientRouterStates>,
    req_headers: HeaderMap,
    jar: CookieJar,
) -> Result<RefreshAccessTknRes, RefreshAccessTknRes> {
    let (env_map, pool, sessions) = state;
    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(secret) => secret,
        None => {
            return Err((jar, StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let mut lock = sessions.write().await;

    lock.revoke(&access_tkn.iss_id);

    drop(lock);

    handle_errs(
        query!("DELETE FROM sessions WHERE id = $1", access_tkn.iss_id)
            .execute(&pool.pool)
            .await,
        (jar.clone(), StatusCode::INTERNAL_SERVER_ERROR),
        "Couldn't refresh user token",
    )?;

    let (access_token, refresh_token) =
        build_tokens(jwt_secret, &access_tkn.user_info, &sessions).await;

    let origin = match req_headers.get(header::ORIGIN) {
        Some(val) => handle_errs(
            val.to_str(),
            (jar.clone(), StatusCode::INTERNAL_SERVER_ERROR),
            "Server Error",
        )?
        .to_string(),
        None => {
            return Err((jar, StatusCode::BAD_REQUEST));
        }
    };

    let updated_jar = build_cookies(env_map, access_token, refresh_token, origin, jar).await;
    Ok((updated_jar, StatusCode::OK))
}
