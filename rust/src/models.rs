use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub password: String,
    pub full_name: Option<String>,
    pub is_active: Option<bool>,
    pub is_verified: Option<bool>,
    pub custom_claims: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub mfa_secret: Option<String>,
    pub mfa_enabled: Option<bool>,
}

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: i32,
    pub user_id: i32,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: Option<DateTime<Utc>>,
}
