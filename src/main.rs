use askama::Template;
use base64::URL_SAFE;
use id_contact_jwt::sign_and_encrypt_auth_result;
use id_contact_proto::{AuthResult, AuthStatus, StartAuthRequest, StartAuthResponse};
use irma::{IrmaDisclosureRequest, IrmaRequest};
use rocket::{get, launch, post, response::Redirect, routes, serde::json::Json, State};
use serde::Deserialize;
use std::{error::Error as StdError, fmt::Display, fs::File};

use josekit::{
    jws::JwsHeader,
    jwt::{self, JwtPayload},
};

mod config;
mod irma;

#[derive(Debug)]
enum Error {
    Irma(irma::Error),
    Config(config::Error),
    Decode(base64::DecodeError),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    Jwt(id_contact_jwt::Error),
    Template(askama::Error),
}

impl<'r, 'o: 'r> rocket::response::Responder<'r, 'o> for Error {
    fn respond_to(self, request: &'r rocket::Request<'_>) -> rocket::response::Result<'o> {
        let debug_error = rocket::response::Debug::from(self);
        debug_error.respond_to(request)
    }
}

impl From<irma::Error> for Error {
    fn from(e: irma::Error) -> Error {
        Error::Irma(e)
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Error {
        Error::Config(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Error {
        Error::Decode(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Error {
        Error::Utf(e)
    }
}

impl From<id_contact_jwt::Error> for Error {
    fn from(e: id_contact_jwt::Error) -> Error {
        Error::Jwt(e)
    }
}

impl From<askama::Error> for Error {
    fn from(e: askama::Error) -> Error {
        Error::Template(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Irma(e) => e.fmt(f),
            Error::Config(e) => e.fmt(f),
            Error::Decode(e) => e.fmt(f),
            Error::Utf(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::Jwt(e) => e.fmt(f),
            Error::Template(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Irma(e) => Some(e),
            Error::Config(e) => Some(e),
            Error::Decode(e) => Some(e),
            Error::Utf(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Jwt(e) => Some(e),
            Error::Template(e) => Some(e),
        }
    }
}

#[derive(Template)]
#[template(path = "auth.html", escape = "none")]
struct AuthTemplate<'a> {
    continuation: &'a str,
    qr: &'a str,
}

fn sign_irma_params(continuation: &str, qr: &str, config: &config::Config) -> String {
    let mut payload = JwtPayload::new();
    payload.set_issued_at(&std::time::SystemTime::now());
    payload
        .set_claim(
            "continuation",
            Some(serde_json::to_value(continuation).unwrap()),
        )
        .unwrap();
    payload
        .set_claim("qr", Some(serde_json::to_value(qr).unwrap()))
        .unwrap();
    jwt::encode_with_signer(&payload, &JwsHeader::new(), config.signer()).unwrap()
}

#[get("/auth/<qr>/<continuation>")]
async fn auth_ui(
    config: &State<config::Config>,
    qr: String,
    continuation: String,
) -> Result<Redirect, Error> {
    let continuation = base64::decode_config(continuation, URL_SAFE)?;
    let continuation = std::str::from_utf8(&continuation)?;

    let qr = base64::decode_config(qr, URL_SAFE)?;
    let qr = std::str::from_utf8(&qr)?;

    let token = sign_irma_params(continuation, qr, config);

    Ok(Redirect::to(
        format!("{}?{}", config.ui_irma_url(), &token,),
    ))
}

#[get("/decorated_continue/<attributes>/<continuation>?<token>")]
async fn decorated_continue(
    config: &State<config::Config>,
    token: String,
    attributes: String,
    continuation: String,
) -> Result<Redirect, Error> {
    let continuation = base64::decode_config(continuation, URL_SAFE)?;
    let continuation = std::str::from_utf8(&continuation)?;

    let attributes = base64::decode_config(attributes, URL_SAFE)?;
    let attributes = serde_json::from_slice::<Vec<String>>(&attributes)?;

    let session_result = config.irma_server().get_result(&token).await?;

    //let attributes = config.map_response(&attributes, session_result)?;
    let auth_result = AuthResult {
        status: AuthStatus::Succes,
        attributes: Some(config.map_response(&attributes, session_result)?),
        session_url: None,
    };
    let auth_result =
        sign_and_encrypt_auth_result(&auth_result, config.signer(), config.encrypter())?;

    if continuation.find('?') != None {
        Ok(Redirect::to(format!(
            "{}&result={}",
            continuation, auth_result
        )))
    } else {
        Ok(Redirect::to(format!(
            "{}?result={}",
            continuation, auth_result
        )))
    }
}

#[derive(Debug, Deserialize)]
struct IrmaServerPost {
    token: String,
}
#[post("/session_complete/<attributes>/<attr_url>", data = "<token>")]
async fn session_complete(
    config: &State<config::Config>,
    token: Json<IrmaServerPost>,
    attributes: String,
    attr_url: String,
) -> Result<(), Error> {
    let attr_url = base64::decode_config(attr_url, URL_SAFE)?;
    let attr_url = std::str::from_utf8(&attr_url)?;

    let attributes = base64::decode_config(attributes, URL_SAFE)?;
    let attributes = serde_json::from_slice::<Vec<String>>(&attributes)?;

    let session_result = config.irma_server().get_result(&token.token).await?;

    let auth_result = AuthResult {
        status: AuthStatus::Succes,
        attributes: Some(config.map_response(&attributes, session_result)?),
        session_url: None,
    };
    let auth_result =
        sign_and_encrypt_auth_result(&auth_result, config.signer(), config.encrypter())?;

    let client = reqwest::Client::new();
    let result = client
        .post(attr_url)
        .header("Content-Type", "application/jwt")
        .body(auth_result)
        .send()
        .await;
    if let Err(e) = result {
        // Log only
        println!("Failure reporting results: {}", e);
    }
    Ok(())
}

// start session with out-of-band return of attributes
async fn start_oob(
    config: &State<config::Config>,
    request: &Json<StartAuthRequest>,
    attr_url: &str,
) -> Result<Json<StartAuthResponse>, Error> {
    let session_request = IrmaRequest::Disclosure(IrmaDisclosureRequest {
        disclose: config.map_attributes(&request.attributes)?,
        return_url: Some(request.continuation.clone()),
        augment_return: false,
    });

    println!("With attr url");

    let callback_url = format!(
        "{}/session_complete/{}/{}",
        config.internal_url(),
        base64::encode_config(&serde_json::to_vec(&request.attributes)?, URL_SAFE),
        base64::encode_config(attr_url, URL_SAFE)
    );

    let session = config
        .irma_server()
        .start_with_callback(&session_request, &callback_url)
        .await?;

    Ok(Json(StartAuthResponse {
        client_url: format!(
            "{}/auth/{}/{}",
            config.server_url(),
            base64::encode_config(&session.qr, URL_SAFE),
            base64::encode_config(&request.continuation, URL_SAFE),
        ),
    }))
}

// start session with in-band return of attributes
async fn start_ib(
    config: &State<config::Config>,
    request: &Json<StartAuthRequest>,
) -> Result<Json<StartAuthResponse>, Error> {
    let continuation_url = format!(
        "{}/decorated_continue/{}/{}",
        config.server_url(),
        base64::encode_config(&serde_json::to_vec(&request.attributes)?, URL_SAFE),
        base64::encode_config(&request.continuation, URL_SAFE)
    );

    println!("Without attr url");

    let session_request = IrmaRequest::Disclosure(IrmaDisclosureRequest {
        disclose: config.map_attributes(&request.attributes)?,
        return_url: Some(continuation_url.clone()),
        augment_return: true,
    });

    let session = config.irma_server().start(&session_request).await?;

    Ok(Json(StartAuthResponse {
        client_url: format!(
            "{}/auth/{}/{}",
            config.server_url(),
            base64::encode_config(&session.qr, URL_SAFE),
            base64::encode_config(
                format!("{}?token={}", continuation_url, session.token),
                URL_SAFE
            ),
        ),
    }))
}

#[post("/start_authentication", data = "<request>")]
async fn start_authentication(
    config: &State<config::Config>,
    request: Json<StartAuthRequest>,
) -> Result<Json<StartAuthResponse>, Error> {
    match &request.attr_url {
        Some(attr_url) => start_oob(config, &request, attr_url).await,
        None => start_ib(config, &request).await,
    }
}

#[launch]
fn rocket() -> _ {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    let config = config::Config::from_reader(&configfile)
        // Drop error value, as it could contain secrets
        .unwrap_or_else(|_| panic!("Could not read configuration"));
    let mut base = rocket::build()
        .mount(
            "/",
            routes![
                start_authentication,
                decorated_continue,
                session_complete,
                auth_ui
            ],
        );
    if let Some(sentry_dsn) = config.sentry_dsn() {
        base = base.attach(id_contact_sentry::SentryFairing::new(sentry_dsn, "auth-irma"));
    }
    base.manage(
        config,
    )
}
