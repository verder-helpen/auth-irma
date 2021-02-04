use std::{error::Error as StdError, fmt::Display, fs::File};

use irma::IrmaRequest;
use rocket::{launch, post, routes, State};
use rocket_contrib::json::Json;

mod config;
mod idauth;
mod irma;

#[derive(Debug)]
enum Error {
    Irma(irma::Error),
    Config(config::Error),
}

impl From<irma::Error> for Error {
    fn from(e: irma::Error) -> Error {
        Error::Irma(e)
    }
}

impl From<irma::Error> for rocket::response::Debug<Error> {
    fn from(e: irma::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Error {
        Error::Config(e)
    }
}

impl From<config::Error> for rocket::response::Debug<Error> {
    fn from(e: config::Error) -> Self {
        Self::from(Error::from(e))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Irma(e) => e.fmt(f),
            Error::Config(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Irma(e) => Some(e),
            Error::Config(e) => Some(e),
            _ => None,
        }
    }
}

#[post("/start_authentication", data = "<request>")]
async fn start_authentication(
    config: State<'_, config::Config>,
    request: Json<idauth::AuthRequest>,
) -> Result<Json<idauth::StartAuthResponse>, rocket::response::Debug<Error>> {
    let disclosure = config.map_attributes(&request.attributes)?;
    let session = config
        .irma_server()
        .start(&IrmaRequest::disclosure(disclosure))
        .await?;
    Ok(Json(idauth::StartAuthResponse {
        client_url: format!(
            "https://irma.app/-/session#{}",
            urlencoding::encode(&session.qr)
        ),
    }))
}

#[launch]
fn rocket() -> rocket::Rocket {
    let configfile = File::open(std::env::var("CONFIG").expect("No configuration file specified"))
        .expect("Could not open configuration");
    rocket::ignite()
        .mount("/", routes![start_authentication])
        .manage(config::Config::from_reader(&configfile).expect("Could not read configuration"))
}
