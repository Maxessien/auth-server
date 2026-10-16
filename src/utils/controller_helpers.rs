use std::{collections::HashMap, sync::Arc};

use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use jsonwebtoken::{EncodingKey, Header};
use sqlx::types::chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    models::users::{DecodedAccessTkn, DecodedRefreshTkn, User},
    utils::utils::{Tkns, Tokens, TokensList},
};

pub async fn build_tokens(
    jwt_secret: &str,
    user: &User,
    sessions: &Arc<RwLock<Tokens>>,
) -> (String, String) {
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

    let mut lock = sessions.write().await;

    lock.add_token((
        iss_id,
        Tkns {
            access: access_token.clone(),
            refresh: refresh_token.clone(),
            algorithm: encoding_header.alg,
        },
    ));

    return (access_token, refresh_token);
}

pub async fn build_cookies(
    env_map: HashMap<String, String>,
    access_token: String,
    refresh_token: String,
    origin: String,
    jar: CookieJar,
) -> CookieJar {
    let is_development = env_map
        .get("RUNTIME_ENV")
        .unwrap_or(&String::from("development"))
        == "development";

    let access_ck = Cookie::build(("access_token", access_token))
        .domain(origin.clone())
        .path("/")
        .same_site(SameSite::None)
        .secure(!is_development);

    let refresh_ck = Cookie::build(("refresh_token", refresh_token))
        .domain(origin)
        .path("/")
        .same_site(SameSite::None)
        .secure(!is_development);

    let mut updated_jar = jar.add(access_ck);
    updated_jar = updated_jar.add(refresh_ck);

    updated_jar
}
