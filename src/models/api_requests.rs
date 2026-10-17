use axum::{body::Body, response::Response};
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

#[derive(Serialize, Deserialize, Clone, PartialEq)]
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

pub type LoginRes = (CookieJar, Response<Body>);

pub enum AvailableField {
    Email,
    Phone,
}
