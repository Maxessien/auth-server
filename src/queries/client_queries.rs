pub static REGISTER_SQL: &'static str = "
    INSERT INTO users (user_name, password_hash, email, phone, is_verified, user_id, access_token,
    refresh_token, last_login, created_at, updated_at) VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
";
