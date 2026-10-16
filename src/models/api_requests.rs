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

pub enum AvailableField {
    Email,
    Phone,
}
