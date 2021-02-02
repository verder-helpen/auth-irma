use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, error::Error as StdError, fmt::Display};

#[derive(Debug)]
pub enum Error {
    Reqwest(reqwest::Error),
    Json(serde_json::Error),
    Incomplete(),
    Cancelled(),
    Timeout(),
    Invalid(),
}

impl From<reqwest::Error> for Error {
    fn from(v: reqwest::Error) -> Error {
        Error::Reqwest(v)
    }
}

impl From<serde_json::Error> for Error {
    fn from(v: serde_json::Error) -> Error {
        Error::Json(v)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Reqwest(e) => e.fmt(f),
            Error::Json(e) => e.fmt(f),
            Error::Incomplete() => f.write_str("Incomplete session"),
            Error::Cancelled() => f.write_str("Cancelled session"),
            Error::Timeout() => f.write_str("Session timed out"),
            Error::Invalid() => f.write_str("Invalid proof"),
        }
    }
}
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Reqwest(e) => Some(e),
            Error::Json(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct SpecificAttribute {
    #[serde(rename = "type")]
    pub attribute_type: String,
    pub value: Option<String>,
    pub not_null: bool,
}

#[derive(Serialize, Debug, Clone)]
#[serde(untagged)]
pub enum Attribute {
    Simple(String),
    _Specific(SpecificAttribute),
}

pub type ConDisCon = Vec<Vec<Vec<Attribute>>>;

#[derive(Serialize, Debug, Clone)]
pub struct IrmaRequest {
    #[serde(rename = "@context")]
    pub context: &'static str,
    pub disclose: ConDisCon,
}

impl IrmaRequest {
    const DISCLOSURE: &'static str = "https://irma.app/ld/request/disclosure/v2";

    pub fn disclosure(cdc: ConDisCon) -> Self {
        IrmaRequest {
            context: Self::DISCLOSURE,
            disclose: cdc,
        }
    }

    pub fn disclosure_simple(attribute: String) -> Self {
        Self::disclosure(vec![vec![vec![Attribute::Simple(attribute)]]])
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
enum SessionType {
    Disclosing,
    Signing,
    Issuing,
}

#[derive(Deserialize, Serialize)]
struct SessionPointer {
    u: String,
    #[serde(rename = "irmaqr")]
    irma_qr: SessionType,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionResponse {
    token: String,
    session_ptr: SessionPointer,
}

#[derive(Deserialize, Serialize, PartialEq, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofStatus {
    Valid,
    Invalid,
    InvalidTimestamp,
    UnmatchedRequest,
    MissingAttributes,
    Expired,
}

#[derive(
    Deserialize, Serialize, PartialEq, Debug, strum_macros::EnumString, strum_macros::ToString,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[strum(serialize_all = "shouty_snake_case")]
pub enum SessionStatus {
    Initialized,
    Connected,
    Cancelled,
    Done,
    Timeout,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct AttributeResult {
    pub id: String,
    pub rawvalue: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct RawIrmaResult {
    status: SessionStatus,
    #[serde(rename = "proofStatus")]
    proof_status: ProofStatus,
    disclosed: Vec<Vec<AttributeResult>>
}

pub struct IrmaResult {
    pub disclosed: Vec<Vec<AttributeResult>>,
}

impl TryFrom<RawIrmaResult> for IrmaResult {
    type Error = Error;

    fn try_from(value: RawIrmaResult) -> Result<IrmaResult, Error> {
        match value.status {
            SessionStatus::Cancelled => Err(Error::Cancelled()),
            SessionStatus::Timeout => Err(Error::Timeout()),
            SessionStatus::Done => {
                match value.proof_status {
                    ProofStatus::Valid => Ok(IrmaResult{disclosed: value.disclosed}),
                    _ => Err(Error::Invalid()),
                }
            }
            _ => Err(Error::Incomplete())
        }
    }
}


pub struct IrmaSession {
    pub qr: String,
    pub token: String,
}

impl IrmaSession {
    pub async fn start(request: &IrmaRequest) -> Result<IrmaSession, Error> {
        let client = reqwest::Client::new();

        let session_response: SessionResponse = client
            .post("http://localhost:8088/session")
            .json(request)
            .send()
            .await?
            .json()
            .await?;
        
        let qr = serde_json::to_string(&session_response.session_ptr)?;

        Ok(IrmaSession {
            qr,
            token: session_response.token,
        })
    }

    pub async fn get_result(&self) -> Result<IrmaResult, Error> {
        let client = reqwest::Client::new();
        let session_result: RawIrmaResult = client
            .get(&format!("http://localhost:8088/session/{}/result", self.token))
            .send()
            .await?
            .json()
            .await?;
        
        IrmaResult::try_from(session_result)
    }
}
