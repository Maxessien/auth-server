use auth_server::db::db_connect::connect_mod::AppPool;
use sqlx::query;

pub async fn save_tokens(pool: &AppPool, key: String, val: (String, String)) -> () {
    // let q = query!(
    //     "
    //     INSERT INTO sessions (id, access_token, refresh_token) VALUES ()
    // "
    // );
    ()
}
