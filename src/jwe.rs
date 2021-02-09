use std::{collections::HashMap, fmt::Display};

use josekit::{
    jwe::{JweEncrypter, JweHeader},
    jws::{JwsHeader, JwsSigner},
    jwt::{self, JwtPayload},
};

#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    JWT(josekit::JoseError),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
        }
    }
}

pub fn sign_and_encrypt_attributes(
    attributes: &HashMap<String, String>,
    signer: &dyn JwsSigner,
    encrypter: &dyn JweEncrypter,
) -> Result<String, Error> {
    let mut sig_header = JwsHeader::new();
    sig_header.set_token_type("JWT");
    let mut sig_payload = JwtPayload::new();
    sig_payload.set_subject("id-contact-attributes");
    sig_payload.set_claim("attributes", Some(serde_json::to_value(attributes)?))?;

    let jws = jwt::encode_with_signer(&sig_payload, &sig_header, signer)?;

    let mut enc_header = JweHeader::new();
    enc_header.set_token_type("JWT");
    enc_header.set_content_type("JWT");
    enc_header.set_content_encryption("A128CBC-HS256");
    let mut enc_payload = JwtPayload::new();
    enc_payload.set_claim("njwt", Some(serde_json::to_value(jws)?))?;

    Ok(jwt::encode_with_encrypter(
        &enc_payload,
        &enc_header,
        encrypter,
    )?)
}
