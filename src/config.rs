use serde::Deserialize;
use std::{collections::HashMap, convert::TryFrom, error::Error as StdError, fmt::Display};
use verder_helpen_jwt::{EncryptionKeyConfig, SignKeyConfig};

use josekit::{jwe::JweEncrypter, jws::JwsSigner};

type AttributeMapping = HashMap<String, Vec<String>>;

#[derive(Debug)]
pub enum Error {
    UnknownAttribute(String),
    NotMatching(&'static str),
    InvalidResponse(&'static str),
    Yaml(serde_yaml::Error),
    Json(serde_json::Error),
    Jwt(verder_helpen_jwt::Error),
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::Yaml(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<verder_helpen_jwt::Error> for Error {
    fn from(e: verder_helpen_jwt::Error) -> Error {
        Error::Jwt(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownAttribute(a) => f.write_fmt(format_args!("Unknown attribute {}", a)),
            Error::Yaml(e) => e.fmt(f),
            Error::NotMatching(desc) => f.write_str(desc),
            Error::InvalidResponse(desc) => {
                f.write_fmt(format_args!("Invalid irma response: {}", desc))
            }
            Error::Json(e) => e.fmt(f),
            Error::Jwt(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Yaml(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::Jwt(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Deserialize, Debug)]
struct IrmaserverConfig {
    url: String,
    auth_token: Option<String>,
}

impl From<IrmaserverConfig> for super::irma::IrmaServer {
    fn from(config: IrmaserverConfig) -> Self {
        match config.auth_token {
            Some(token) => Self::new_with_auth(&config.url, &token),
            None => Self::new(&config.url),
        }
    }
}

#[derive(Deserialize, Debug)]
struct RawConfig {
    server_url: String,
    internal_url: String,
    sentry_dsn: Option<String>,
    ui_irma_url: String,
    attributes: AttributeMapping,
    irma_server: IrmaserverConfig,
    encryption_pubkey: EncryptionKeyConfig,
    signing_privkey: SignKeyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct Config {
    server_url: String,
    internal_url: String,
    sentry_dsn: Option<String>,
    ui_irma_url: String,
    attributes: AttributeMapping,
    irma_server: super::irma::IrmaServer,
    encrypter: Box<dyn JweEncrypter>,
    signer: Box<dyn JwsSigner>,
}

// This try_from will no longer be needed once support for field try_from lands in serde
impl TryFrom<RawConfig> for Config {
    type Error = Error;
    fn try_from(config: RawConfig) -> Result<Config, Error> {
        Ok(Config {
            server_url: config.server_url,
            internal_url: config.internal_url,
            sentry_dsn: config.sentry_dsn,
            ui_irma_url: config.ui_irma_url,
            attributes: config.attributes,
            irma_server: super::irma::IrmaServer::from(config.irma_server),
            encrypter: Box::<dyn JweEncrypter>::try_from(config.encryption_pubkey)?,
            signer: Box::<dyn JwsSigner>::try_from(config.signing_privkey)?,
        })
    }
}

impl Config {
    pub fn map_attributes(&self, attributes: &[String]) -> Result<crate::irma::ConDisCon, Error> {
        let mut result: super::irma::ConDisCon = vec![];
        for attribute in attributes {
            let mut dis: Vec<Vec<super::irma::Attribute>> = vec![];
            for request_attribute in self
                .attributes
                .get(attribute)
                .ok_or_else(|| Error::UnknownAttribute(attribute.clone()))?
            {
                dis.push(vec![super::irma::Attribute::Simple(
                    request_attribute.clone(),
                )]);
            }
            result.push(dis);
        }
        Ok(result)
    }

    pub fn map_response(
        &self,
        attributes: &[String],
        response: crate::irma::IrmaResult,
    ) -> Result<HashMap<String, String>, Error> {
        if attributes.len() != response.disclosed.len() {
            return Err(Error::NotMatching("mismatch between request and response"));
        }

        let mut result: HashMap<String, String> = HashMap::new();

        for (i, attribute) in attributes.iter().enumerate() {
            if response.disclosed[i].len() != 1 {
                return Err(Error::InvalidResponse(
                    "Incorrect number of attributes in inner conjunction",
                ));
            }
            let allowed_irma_attributes = self
                .attributes
                .get(attribute)
                .ok_or_else(|| Error::UnknownAttribute(attribute.clone()))?;
            if !allowed_irma_attributes.contains(&response.disclosed[i][0].id) {
                return Err(Error::InvalidResponse(
                    "Incorrect attribute in inner conjunction",
                ));
            }
            result.insert(attribute.clone(), response.disclosed[i][0].rawvalue.clone());
        }

        Ok(result)
    }

    pub fn irma_server(&self) -> &super::irma::IrmaServer {
        &self.irma_server
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    pub fn internal_url(&self) -> &str {
        &self.internal_url
    }

    pub fn sentry_dsn(&self) -> Option<&str> {
        self.sentry_dsn.as_deref()
    }

    pub fn ui_irma_url(&self) -> &str {
        &self.ui_irma_url
    }

    pub fn encrypter(&self) -> &dyn JweEncrypter {
        self.encrypter.as_ref()
    }

    pub fn signer(&self) -> &dyn JwsSigner {
        self.signer.as_ref()
    }

    pub fn _from_string(config: &str) -> Result<Config, Error> {
        Ok(serde_yaml::from_str(config)?)
    }

    pub fn from_reader<T: std::io::Read>(reader: T) -> Result<Config, Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
