use serde::Deserialize;
use std::{collections::HashMap, error::Error as StdError, fmt::Display};

type AttributeMapping = HashMap<String, Vec<String>>;

#[derive(Debug)]
pub enum Error {
    UnknownAttribute(String),
    YamlError(serde_yaml::Error),
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Error {
        Error::YamlError(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnknownAttribute(a) => f.write_fmt(format_args!("Unknown attribute {}", a)),
            Error::YamlError(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::YamlError(e) => Some(e),
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
    attributes: AttributeMapping,
    irma_server: IrmaserverConfig,
}

#[derive(Debug, Deserialize)]
#[serde(from = "RawConfig")]
pub struct Config {
    attributes: AttributeMapping,
    irma_server: super::irma::IrmaServer,
}

impl From<RawConfig> for Config {
    fn from(config: RawConfig) -> Config {
        Config {
            attributes: config.attributes,
            irma_server: super::irma::IrmaServer::from(config.irma_server),
        }
    }
}

impl Config {
    pub fn map_attributes(
        &self,
        attributes: &Vec<String>,
    ) -> Result<super::irma::ConDisCon, Error> {
        let mut result: super::irma::ConDisCon = vec![];
        for attribute in attributes {
            let mut dis: Vec<Vec<super::irma::Attribute>> = vec![];
            for request_attribute in self
                .attributes
                .get(attribute)
                .ok_or(Error::UnknownAttribute(attribute.clone()))?
            {
                dis.push(vec![super::irma::Attribute::Simple(
                    request_attribute.clone(),
                )]);
            }
            result.push(dis);
        }
        Ok(result)
    }

    pub fn irma_server(&self) -> &super::irma::IrmaServer {
        &self.irma_server
    }

    pub fn from_string(config: &str) -> Result<Config, Error> {
        Ok(serde_yaml::from_str(config)?)
    }

    pub fn from_reader<T: std::io::Read>(reader: T) -> Result<Config, Error> {
        Ok(serde_yaml::from_reader(reader)?)
    }
}
