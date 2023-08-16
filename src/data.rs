use serde::Deserialize;
use std::error::Error;
use chrono::NaiveDateTime;
use sqlx::FromRow;
use sqlx::SqliteConnection;

#[derive(FromRow, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
    pub removed: Option<bool>,
}

#[derive(FromRow, Debug)]
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

async fn user_exists(conn: &mut SqliteConnection, username: &str) -> Result<bool, &'static str> {
    let query = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE username = ?", username)
        .fetch_one(conn)
        .await;

    match query {
        Ok(record) => {
            Ok(record.count > 0)
        },
        Err(e) => panic!("{:?}", "db operation failed"),
    }
}

pub async fn create_user(conn: &mut SqliteConnection, username: &str) -> sqlx::Result<u64> {
    match user_exists(conn, username).await {
        Ok(true) => {
            return Ok(0);
        },
        Ok(false) => {
            let now = chrono::Utc::now().timestamp();

            let insert_result = sqlx::query!(
                "INSERT INTO users (username, created_at) VALUES (?, ?)",
                username,
                now
            )
            .execute(conn)
            .await;

            match insert_result {
                Ok(records) => {
                    Ok(records.rows_affected())
                },
                Err(e) => panic!("{:?}", "db operation failed"),
            }
        },
        Err(e) => return Ok(0),
    }
}

pub async fn get_user(conn: &mut SqliteConnection, username: &str) -> sqlx::Result<Option<User>> {
    match user_exists(conn, username).await {
        Ok(true) => {
            Ok(None)
        },
        Ok(false) => {
            let result = sqlx::query_as!(
                    User,
                    "SELECT * FROM users WHERE username = ? AND (removed IS NULL OR removed != 1)",
                    username
                )
                .fetch_optional(conn)
                .await?;

            Ok(result)
        },
        Err(e) => panic!("{:?}", "this could not happen"),
    }
}
