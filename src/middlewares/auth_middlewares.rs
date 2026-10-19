use std::collections::HashMap;

use crate::{
    models::users::DecodedRefreshTkn,
    utils::utils::{JWT_ALGORITHM, TokensList, handle_errs},
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode, header},
    middleware::Next,
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{DecodingKey, Validation};

use crate::{
    models::users::{DecodedAccessTkn, TknType},
    routes::client_routes::ClientRouterStates,
};

pub async fn verify_access_token(
    jar: CookieJar,
    State(state): State<ClientRouterStates>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    let (env_map, _, sessions) = state;
    let access_tkn = jar
        .get("access_token")
        .ok_or((StatusCode::UNAUTHORIZED, "Access token missing".to_string()))?;

    let jwt_secret = env_map
        .get("JWT_SECRET")
        .ok_or((StatusCode::UNAUTHORIZED, String::new()))?;

    let decoded: DecodedAccessTkn = handle_errs(
        jsonwebtoken::decode(
            access_tkn.value().as_bytes(),
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(JWT_ALGORITHM),
        ),
        |_| (StatusCode::UNAUTHORIZED, "Invalid access token".to_string()),
        "Error decoding token",
    )?
    .claims;

    let lock = sessions.read().await;

    if !lock.is_valid((
        &decoded.iss_id,
        access_tkn.value(),
        decoded.expires_at_sec,
        TknType::Access,
    )) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid access token".to_string()));
    };

    drop(lock);

    req.extensions_mut().insert(decoded);

    let response = next.run(req).await;

    Ok(response)
}

pub async fn verify_refresh_token(
    jar: CookieJar,
    State(state): State<ClientRouterStates>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let (env_map, _, sessions) = state;
    let access_tkn = jar.get("access_token").ok_or(StatusCode::UNAUTHORIZED)?;
    let refresh_tkn = jar.get("refresh_token").ok_or(StatusCode::UNAUTHORIZED)?;

    let jwt_secret = env_map
        .get("JWT_SECRET")
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let decoded_access_tkn: DecodedAccessTkn = handle_errs(
        jsonwebtoken::decode(
            access_tkn.value().as_bytes(),
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(JWT_ALGORITHM),
        ),
        |_| StatusCode::UNAUTHORIZED,
        "Invalid access token",
    )?
    .claims;

    let decoded_refresh_tkn: DecodedRefreshTkn = handle_errs(
        jsonwebtoken::decode(
            refresh_tkn.value().as_bytes(),
            &DecodingKey::from_secret(jwt_secret.as_bytes()),
            &Validation::new(JWT_ALGORITHM),
        ),
        |_| StatusCode::UNAUTHORIZED,
        "Invalid access token",
    )?
    .claims;

    let lock = sessions.read().await;

    if !lock.is_valid((
        &decoded_refresh_tkn.iss_id,
        refresh_tkn.value(),
        decoded_refresh_tkn.expires_at_sec,
        TknType::Refresh,
    )) {
        return Err(StatusCode::UNAUTHORIZED);
    };

    drop(lock);

    req.extensions_mut().insert(decoded_access_tkn);

    let response = next.run(req).await;

    Ok(response)
}

pub async fn verify_admin_key(
    State(env_map): State<HashMap<String, String>>,
    req: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let header = match req.headers().get(header::AUTHORIZATION) {
        Some(val) => handle_errs(
            val.to_str(),
            |_| StatusCode::INTERNAL_SERVER_ERROR,
            "Error converting header to string",
        )?
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_string(),
        None => {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let admin_key = env_map
        .get("ADMIN_KEY")
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    if *admin_key != header {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let response = next.run(req).await;

    Ok(response)
}
