use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{Body, Request, Response},
    tokio_tungstenite::tungstenite::Message,
    *,
};
use rustls_pemfile as pemfile;
use std::net::SocketAddr;
use log::*;
use actix_web::{cookie::{self, Key}, web, App, HttpServer};
use actix_session::{
    config::PersistentSession, storage::CookieSessionStore, SessionMiddleware,
};
use actix_files::Files;
use tera::{Tera};
use systemd_journal_logger::JournalLog;

use sqlx::sqlite::SqlitePool;

mod web_funs;
mod data;

use crate::web_funs::AppState;

#[derive(Clone)]
struct LogHandler;

#[async_trait]
impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        debug!("{:?}", req);
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        println!("{:?}", res);
        res
    }
}

#[async_trait]
impl WebSocketHandler for LogHandler {
    async fn handle_message(&mut self, _ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        debug!("{:?}", msg);
        Some(msg)
    }
}

async fn proxy_handler() -> Result<(), Box<dyn std::error::Error>> {
    let mut private_key_bytes: &[u8] = include_bytes!("ca/localhost.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/localhost.crt");

    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .expect("Failed to parse private key")
            .remove(0),
    );

    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .expect("Failed to parse CA certificate")
            .remove(0),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy_address = ([127, 0, 0, 1], 7788);
    println!("starting tonleh proxy at: {:?}", proxy_address);

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from(proxy_address))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(LogHandler)
        .with_websocket_handler(LogHandler)
        .build();

    if let Err(e) = proxy.start(shutdown_signal()).await {
        error!("{}", e);
    }

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Create hudsucker Proxy server
    JournalLog::default().install().unwrap();
    log::set_max_level(LevelFilter::Debug);

    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }

    tokio::spawn(async move {
        if let Err(e) = proxy_handler().await {
            eprintln!("Proxy server error: {:?}", e);
        }
    });

    // connect to db
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = SqlitePool::connect(&database_url).await.unwrap();

    // Create Actix Web server
    let web_address = ([127, 0, 0, 1], 5566);
    let addr = SocketAddr::from(web_address);
    println!("starting tonleh web at: {:?}", web_address);

    HttpServer::new(move || {
        let tera = Tera::new("templates/**/*").expect("Error readding html templates");

        App::new()
            // cookie session middleware
            .wrap(
                SessionMiddleware::builder(CookieSessionStore::default(), Key::from(&[0; 64]))
                    .cookie_secure(false)
                    // customize session and cookie expiration
                    .session_lifecycle(
                        PersistentSession::default().session_ttl(cookie::time::Duration::hours(2)),
                    )
                    .build(),
            )
            .app_data(web::Data::new(AppState { db: pool.clone(), tmpl: tera }))
            .service(web::resource("/").route(web::get().to(web_funs::render_index)))

            .service(web::resource("/login").route(web::get().to(web_funs::render_login)))
            .service(web::resource("/login.do").route(web::post().to(web_funs::login)))

            .service(web::resource("/signup").route(web::get().to(web_funs::render_signup)))
            .service(web::resource("/signup.do").route(web::post().to(web_funs::signup)))

            .service(web::resource("/users").route(web::get().to(web_funs::render_users)))
            .service(web::resource("/devices").route(web::get().to(web_funs::render_devices)))
            .service(web::resource("/history").route(web::get().to(web_funs::render_history)))
            .route("/api", web::get().to(web_funs::actix_web_handler))
            .service(Files::new("/", "static"))
    })
    .bind(addr)
    .expect("Unable to bind address")
    .run()
    .await
    .expect("Server error");

    Ok(())
}
