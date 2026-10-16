use serde::{Deserialize, Serialize};

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

pub enum AvailableField {
    Email,
    Phone,
}
