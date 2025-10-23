use axum::{Json, http::StatusCode, Extension};
use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::auth::{hash_password, verify_password, create_access_token, create_refresh_token};
use crate::mfa::{generate_totp_secret, generate_qr_code_uri, verify_totp_code};
use crate::errors::AppError;
use sqlx::SqlitePool;

#[derive(Deserialize)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i64,
    pub email: String,
    pub full_name: Option<String>,
    pub mfa_secret: Option<String>,
    pub qr_code_uri: Option<String>,
}

pub async fn register(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<RegisterUser>,
) -> Result<(StatusCode, Json<UserResponse>), AppError> {
    let hashed_password = hash_password(&payload.password).map_err(|_| AppError::InternalServerError)?;
    let mfa_secret = generate_totp_secret();
    let qr_code_uri = generate_qr_code_uri(&payload.email, &mfa_secret);

    let result = sqlx::query!(
        "INSERT INTO users (email, password, full_name, mfa_secret) VALUES ($1, $2, $3, $4)",
        payload.email,
        hashed_password,
        payload.full_name,
        mfa_secret
    )
    .execute(&pool)
    .await
    .map_err(|_| AppError::InternalServerError)?;

    let last_insert_id = result.last_insert_rowid();
    let new_user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at, mfa_secret, mfa_enabled FROM users WHERE id = $1",
        last_insert_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::InternalServerError)?;

    let user_response = UserResponse {
        id: new_user.id,
        email: new_user.email,
        full_name: new_user.full_name,
        mfa_secret: Some(mfa_secret),
        qr_code_uri: Some(qr_code_uri),
    };
    Ok((StatusCode::CREATED, Json(user_response)))
}

#[derive(Deserialize)]
pub struct MfaVerifyPayload {
    pub user_id: i64,
    pub code: String,
}

pub async fn mfa_verify(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<MfaVerifyPayload>,
) -> Result<StatusCode, AppError> {
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at, mfa_secret, mfa_enabled FROM users WHERE id = $1",
        payload.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::Unauthorized)?;

    if let Some(secret) = user.mfa_secret {
        if verify_totp_code(&secret, &payload.code) {
            sqlx::query!(
                "UPDATE users SET mfa_enabled = TRUE WHERE id = $1",
                payload.user_id
            )
            .execute(&pool)
            .await
            .map_err(|_| AppError::InternalServerError)?;
            return Ok(StatusCode::OK);
        }
    }
    Err(AppError::Unauthorized)
}

#[derive(Deserialize)]
pub struct UpdateClaims {
    pub custom_claims: serde_json::Value,
}

pub async fn update_claims(Json(payload): Json<UpdateClaims>) -> StatusCode {
    // Lógica para atualizar claims será implementada aqui
    println!("Atualizando claims: {:?}", payload.custom_claims);
    StatusCode::OK
}

#[derive(Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn login(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<LoginUser>,
) -> Result<(StatusCode, Json<TokenResponse>), AppError> {
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at, mfa_secret, mfa_enabled FROM users WHERE email = $1",
        payload.email
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::Unauthorized)?;

    if verify_password(&payload.password, &user.password).unwrap_or(false) {
        if user.mfa_enabled.unwrap_or(false) {
            return Ok((StatusCode::OK, Json(TokenResponse {
                access_token: "mfa_required".to_string(),
                refresh_token: user.id.to_string(),
            })));
        }

        let access_token = create_access_token(&user.id.to_string()).map_err(|_| AppError::InternalServerError)?;
        let refresh_token = create_refresh_token(&user.id.to_string()).map_err(|_| AppError::InternalServerError)?;

        Ok((StatusCode::OK, Json(TokenResponse {
            access_token,
            refresh_token,
        })))
    } else {
        Err(AppError::Unauthorized)
    }
}

#[derive(Deserialize)]
pub struct MfaLoginPayload {
    pub user_id: i64,
    pub code: String,
}

pub async fn mfa_login(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<MfaLoginPayload>,
) -> Result<(StatusCode, Json<TokenResponse>), AppError> {
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at, mfa_secret, mfa_enabled FROM users WHERE id = $1",
        payload.user_id
    )
    .fetch_one(&pool)
    .await
    .map_err(|_| AppError::Unauthorized)?;

    if let Some(secret) = user.mfa_secret {
        if verify_totp_code(&secret, &payload.code) {
            let access_token = create_access_token(&user.id.to_string()).map_err(|_| AppError::InternalServerError)?;
            let refresh_token = create_refresh_token(&user.id.to_string()).map_err(|_| AppError::InternalServerError)?;

            return Ok((StatusCode::OK, Json(TokenResponse {
                access_token,
                refresh_token,
            })));
        }
    }
    Err(AppError::Unauthorized)
}