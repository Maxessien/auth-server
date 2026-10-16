use auth_server::db::db_connect::connect_mod::AppPool;
use sqlx::query;

use crate::utils::utils::{AppErrors, AuthServerErrors};

pub async fn save_tokens(pool: &AppPool, key: String, val: (String, String)) -> bool {
    let res = query!(
        "
        INSERT INTO sessions (id, access_token, refresh_token) VALUES ($1, $2, $3)
        ",
        key,
        val.0,
        val.1
    )
    .execute(&pool.pool)
    .await;

    match res {
        Ok(_) => true,
        Err(err) => {
            let app_err = AppErrors::new(
                err.to_string(),
                "Error saving token",
                line!(),
                column!(),
                file!(),
            );
            app_err.log();
            false
        }
    }
}
