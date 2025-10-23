use totp_rs::{TOTP, Algorithm, Secret};
use qrcode::QrCode;
use qrcode::render::svg;
use base64::Engine;
use base64::engine::general_purpose;
use base32;

const ISSUER_NAME: &str = "AuthAPI";

pub fn generate_totp_secret() -> String {
    let secret = Secret::generate_secret();
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &secret.to_bytes().unwrap())
}

pub fn generate_qr_code_uri(email: &str, secret: &str) -> String {
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .expect("Failed to decode secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER_NAME.to_string()),
        email.to_string(),
    )
    .unwrap();
    totp.get_url()
}

pub fn generate_qr_code_image(uri: &str) -> Result<String, String> {
    let code = QrCode::new(uri.as_bytes()).map_err(|e| e.to_string())?;
    let image = code.render::<svg::Color>().build();
    Ok(general_purpose::STANDARD.encode(image.as_bytes()))
}

pub fn verify_totp_code(secret: &str, code: &str) -> bool {
    let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
        .expect("Failed to decode secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(ISSUER_NAME.to_string()),
        "".to_string(),
    )
    .unwrap();
    totp.check_current(code).unwrap_or(false)
}