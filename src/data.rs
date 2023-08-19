use serde::{Serialize, Deserialize};
use sqlx::FromRow;
use sqlx::sqlite::SqlitePool;

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub removed: Option<bool>,
}

#[derive(FromRow, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: i64,
    pub name: String,
    pub mac_address: String,
    pub monitoring: bool,
    pub created_at: i64,
}

// #[derive(FromRow, Debug)]
// pub struct Traffic {
//     pub id: i32,
//     pub device_id: i32,
//     pub type: i32,
//     pub method: i32,
//     pub header: String,
//     pub body: String,
//     pub url: String,
//     pub time: NaiveDateTime,
// }

async fn user_exists(pool: &SqlitePool, username: &str) -> Result<bool, &'static str> {
    let query = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE username = ?", username)
        .fetch_one(pool)
        .await;

    match query {
        Ok(record) => {
            Ok(record.count > 0)
        },
        Err(e) => panic!("{:?}: {:?}", "db operation failed", e),
    }
}

pub async fn create_user(pool: &SqlitePool, username: &str) -> sqlx::Result<Option<User>> {
    match get_user(pool, username).await {
        Ok(None) => {
            let now = chrono::Utc::now().timestamp();

            let insert_result = sqlx::query!(
                "INSERT INTO users (username, created_at) VALUES (?, ?)",
                username,
                now
            )
            .execute(pool)
            .await;

            match insert_result {
                Ok(_records) => {},
                Err(e) => panic!("{:?}: {:?}", "db operation failed", e),
            };

            return get_user(pool, username).await;
        },
        Ok(user) => {
            return Ok(user);
        },
        Err(_e) => return Ok(None),
    }
}

pub async fn get_user(pool: &SqlitePool, username: &str) -> sqlx::Result<Option<User>> {
    match user_exists(pool, username).await {
        Ok(true) => {
            let result = sqlx::query_as!(
                    User,
                    "SELECT * FROM users WHERE username = ? AND (removed IS NULL OR removed != 1)",
                    username
                )
                .fetch_optional(pool)
                .await?;

            Ok(result)
        },
        Ok(false) => {
            Ok(None)
        },
        Err(e) => panic!("{:?}: {:?}", "this could not happen", e),
    }
}

pub async fn get_users(pool: &SqlitePool) -> sqlx::Result<Vec<User>> {
    let result = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE removed IS NULL OR removed != 1"
        )
        .fetch_all(pool)
        .await?;

    Ok(result)
}
