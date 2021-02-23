use askama::Template;
use id_contact_proto::{StartAuthRequest, StartAuthResponse, AuthResult, AuthStatus};
use irma::{IrmaDisclosureRequest, IrmaRequest};
use rocket::{get, launch, post, response::content, response::Redirect, routes, State};
use rocket_contrib::json::Json;
use serde::Deserialize;
use std::{error::Error as StdError, fmt::Display, fs::File};
use id_contact_jwe::sign_and_encrypt_attributes;

mod config;
mod irma;

#[derive(Debug)]
enum Error {
    Irma(irma::Error),
    Config(config::Error),
    Decode(base64::DecodeError),
    Json(serde_json::Error),
    Utf(std::str::Utf8Error),
    JWT(id_contact_jwe::Error),
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

impl From<id_contact_jwe::Error> for Error {
    fn from(e: id_contact_jwe::Error) -> Error {
        Error::JWT(e)
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
            Error::JWT(e) => e.fmt(f),
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
            Error::JWT(e) => Some(e),
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

#[get("/auth/<qr>/<continuation>")]
async fn auth_ui(qr: String, continuation: String) -> Result<content::Html<String>, Error> {
    let continuation = base64::decode(continuation)?;
    let continuation = std::str::from_utf8(&continuation)?;

    let qr = base64::decode(qr)?;
    let qr = std::str::from_utf8(&qr)?;

    let template = AuthTemplate { continuation, qr };

    Ok(content::Html(template.render()?))
}

#[get("/decorated_continue/<attributes>/<continuation>?<token>")]
async fn decorated_continue(
    config: State<'_, config::Config>,
    token: String,
    attributes: String,
    continuation: String,
) -> Result<Redirect, Error> {
    let continuation = base64::decode(continuation)?;
    let continuation = std::str::from_utf8(&continuation)?;

    let attributes = base64::decode(attributes)?;
    let attributes = serde_json::from_slice::<Vec<String>>(&attributes)?;

    let session_result = config.irma_server().get_result(&token).await?;

    let attributes = config.map_response(&attributes, session_result)?;
    let attributes =
        sign_and_encrypt_attributes(&attributes, config.signer(), config.encrypter())?;

    if continuation.find('?') != None {
        Ok(Redirect::to(format!(
            "{}&attributes={}&status=succes",
            continuation, attributes
        )))
    } else {
        Ok(Redirect::to(format!(
            "{}?attributes={}&status=succes",
            continuation, attributes            
        )))
    }
}

#[derive(Debug, Deserialize)]
struct IrmaServerPost {
    token: String,
}
#[post("/session_complete/<attributes>/<attr_url>", data = "<token>")]
async fn session_complete(
    config: State<'_, config::Config>,
    token: Json<IrmaServerPost>,
    attributes: String,
    attr_url: String,
) -> Result<(), Error> {
    let attr_url = base64::decode(attr_url)?;
    let attr_url = std::str::from_utf8(&attr_url)?;

    let attributes = base64::decode(attributes)?;
    let attributes = serde_json::from_slice::<Vec<String>>(&attributes)?;

    let session_result = config.irma_server().get_result(&token.token).await?;

    let attributes = config.map_response(&attributes, session_result)?;
    let attributes =
        sign_and_encrypt_attributes(&attributes, config.signer(), config.encrypter())?;

    let client = reqwest::Client::new();
    let result = client
        .post(attr_url)
        .json(&AuthResult {
            status: AuthStatus::Succes,
            attributes: Some(attributes),
            session_url: None
        })
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
    config: State<'_, config::Config>,
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
        base64::encode(&serde_json::to_vec(&request.attributes)?),
        base64::encode(attr_url)
    );

    let session = config
        .irma_server()
        .start_with_callback(&session_request, &callback_url)
        .await?;

    Ok(Json(StartAuthResponse {
        client_url: format!(
            "{}/auth/{}/{}",
            config.server_url(),
            base64::encode(&session.qr),
            base64::encode(&request.continuation),
        ),
    }))
}

// start session with in-band return of attributes
async fn start_ib(
    config: State<'_, config::Config>,
    request: &Json<StartAuthRequest>,
) -> Result<Json<StartAuthResponse>, Error> {
    let continuation_url = format!(
        "{}/decorated_continue/{}/{}",
        config.server_url(),
        base64::encode(&serde_json::to_vec(&request.attributes)?),
        base64::encode(&request.continuation)
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
            base64::encode(&session.qr),
            base64::encode(format!("{}?token={}", continuation_url, session.token)),
        ),
    }))
}

#[post("/start_authentication", data = "<request>")]
async fn start_authentication(
    config: State<'_, config::Config>,
    request: Json<StartAuthRequest>,
) -> Result<Json<StartAuthResponse>, Error> {
    match &request.attr_url {
        Some(attr_url) => start_oob(config, &request, attr_url).await,
        None => start_ib(config, &request).await,
    }
}

#[launch]
fn rocket() -> rocket::Rocket {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    rocket::ignite()
        .mount(
            "/",
            routes![
                start_authentication,
                decorated_continue,
                session_complete,
                auth_ui
            ],
        )
        .manage(config::Config::from_reader(&configfile).expect("Could not read configuration"))
}
