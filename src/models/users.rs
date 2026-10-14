use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;

pub struct IsVerified {
    pub email: bool,
    pub phone: bool,
}

pub struct User {
    pub user_name: String,
    pub password_hash: String,
    pub email: String,
    pub phone: Option<String>,
    pub is_verified: IsVerified,
    pub user_id: Uuid,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub last_login: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
