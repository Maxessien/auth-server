use crate::{models::users::DecodedRefreshTkn, utils::utils::TokensList};
use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use jsonwebtoken::{DecodingKey, Validation};

use crate::{
    models::users::{DecodedAccessTkn, TknType},
    routes::client_routes::ClientRouterStates,
    utils::utils::{AppErrors, AuthServerErrors},
};

pub async fn verify_access_token(
    jar: CookieJar,
    State(state): State<ClientRouterStates>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let (env_map, _, sessions) = state;
    let (mut parts, _) = Response::new("").into_parts();
    let access_tkn = match jar.get("access_token") {
        Some(tkn) => tkn,
        None => {
            parts.status = StatusCode::UNAUTHORIZED;
            return Response::from_parts(parts, Body::from("Access token missing".to_string()));
        }
    };

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(jwt) => jwt,
        None => {
            return Response::from_parts(parts, Body::empty());
        }
    };

    let decoded: DecodedAccessTkn = match jsonwebtoken::decode(
        access_tkn.value().as_bytes(),
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(val) => val.claims,
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Invalid access token",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            return Response::from_parts(parts, app_err.as_http_body());
        }
    };

    let lock = sessions.read().await;

    if !lock.is_valid((
        &decoded.iss_id,
        access_tkn.value(),
        decoded.expires_at_sec,
        TknType::Access,
    )) {
        return Response::from_parts(parts, Body::new("Invalid access token".to_string()));
    };

    drop(lock);

    req.extensions_mut().insert(decoded);

    let response = next.run(req).await;

    response
}

pub async fn verify_refresh_token(
    jar: CookieJar,
    State(state): State<ClientRouterStates>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let (env_map, _, sessions) = state;
    let access_tkn = match jar.get("access_token") {
        Some(tkn) => tkn,
        None => {
            return (jar, StatusCode::UNAUTHORIZED);
        }
    };
    let refresh_tkn = match jar.get("refresh_token") {
        Some(tkn) => tkn,
        None => {
            return (jar, StatusCode::UNAUTHORIZED);
        }
    };

    let jwt_secret = match env_map.get("JWT_SECRET") {
        Some(jwt) => jwt,
        None => {
            return (jar, StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let decoded_access_tkn: DecodedAccessTkn = match jsonwebtoken::decode(
        access_tkn.value().as_bytes(),
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(val) => val.claims,
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Invalid access token",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            return (jar, StatusCode::UNAUTHORIZED);
        }
    };

    let decoded_refresh_tkn: DecodedRefreshTkn = match jsonwebtoken::decode(
        refresh_tkn.value().as_bytes(),
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &Validation::default(),
    ) {
        Ok(val) => val.claims,
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Invalid refresh token",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            return (jar, StatusCode::UNAUTHORIZED);
        }
    };

    let lock = sessions.read().await;

    if !lock.is_valid((
        &decoded_refresh_tkn.iss_id,
        access_tkn.value(),
        decoded_refresh_tkn.expires_at_sec,
        TknType::Access,
    )) {
        return (jar, StatusCode::UNAUTHORIZED);
    };

    drop(lock);

    req.extensions_mut().insert(decoded_access_tkn);

    let response = next.run(req).await;

    (
        CookieJar::from_headers(response.headers()),
        response.status(),
    )
}
