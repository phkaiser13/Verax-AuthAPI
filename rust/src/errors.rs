use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde_json::json;

pub enum AppError {
    InternalServerError,
    Unauthorized,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
            ),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
        };

        let body = Json(json!({ "error": error_message }));

        (status, body).into_response()
    }
}