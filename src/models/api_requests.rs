pub struct RegisterReqBody {
    pub user_name: String,
    pub password: String,
    pub email: String,
    pub phone: Option<String>,
}