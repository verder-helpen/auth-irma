use irma::IrmaRequest;
use rocket::{get, post, launch, routes};
use rocket_contrib::json::Json;

mod idauth;
mod irma;

#[post("/start_authentication", data = "<request>")]
async fn start_authentication(request: Json<idauth::AuthRequest>) -> Json<idauth::StartAuthResponse> {
    let session = irma::IrmaSession::start(&IrmaRequest::disclosure_simple("pbdf.pbdf.email.email".to_string())).await.unwrap();
    Json(idauth::StartAuthResponse {
        client_url: format!("https://irma.app/-/session#{}", urlencoding::encode(&session.qr)),
    })
}

#[launch]
fn rocket() -> rocket::Rocket {
    rocket::ignite().mount("/", routes![start_authentication])
}
