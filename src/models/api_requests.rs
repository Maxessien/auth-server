use serde::Serialize;

use crate::models::users::User;

pub struct RegisterReqBody {
    pub user_name: String,
    pub password: String,
    pub email: String,
    pub phone: Option<String>,
}

pub struct LoginReqBody {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResBody {
    pub user: User,
    pub access_token: String,
    pub refresh_token: String,
}

pub enum AvailableField {
    Email,
    Phone,
}
