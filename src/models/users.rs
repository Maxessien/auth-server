use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum TknType {
    Access,
    Refresh,
}

#[derive(Serialize, Deserialize)]
pub struct IsVerified {
    pub email: bool,
    pub phone: bool,
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct User {
    pub user_name: String,
    pub password_hash: String,
    pub email: String,
    pub phone: Option<String>,
    pub is_verified: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct DecodedAccessTkn {
    pub user_info: User,
    pub expires_at_sec: i64,
    pub issued_at_sec: i64,
    pub iss_id: String,
}

#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct DecodedRefreshTkn {
    pub expires_at_sec: i64,
    pub issued_at_sec: i64,
    pub iss_id: String,
}
