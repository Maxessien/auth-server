use core::str;

use axum::{Json, body::Body, http::StatusCode, response::Response};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize)]
pub struct RegisterReqBody {
    pub user_name: String,
    pub password: String,
    pub email: String,
    pub phone: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct LoginReqBody {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateUserReqBody {
    pub user_name: Option<String>,
    pub password: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GetUserRes {
    pub user_name: String,
    pub email: String,
    pub phone: Option<String>,
    pub is_verified: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateUserAdminReq {
    pub user_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub is_verified: Option<String>,
    pub user_id: String,
    pub password: Option<String>,
}

pub type LoginRes = (CookieJar, Response<Body>);

pub enum AvailableField {
    Email,
    Phone,
}

#[derive(Serialize, Deserialize)]
pub struct InitVerificationBody {
    pub verification_type: String,
    pub value: String,
    pub redirect_uri: String,
}

#[derive(Serialize, Deserialize)]
pub struct InitVerificationClaims {
    pub verification_type: String,
    pub value: String,
    pub redirect_uri: String,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize)]
pub struct InitVerificationRes {
    pub verification_url: String,
}

pub type GetUserResType = (StatusCode, Body);

#[derive(Serialize, Deserialize)]
pub struct GetUserQuery {
    pub user_id: String,
}

pub type GetUsersResType = (StatusCode, Json<Vec<GetUserRes>>);

#[derive(Deserialize)]
pub struct VerifyTknQuery {
    pub token: String,
}
