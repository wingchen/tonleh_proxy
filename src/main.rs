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
use actix_web::{web, App, HttpServer, Responder, HttpResponse, HttpRequest};
use actix_files::Files;
use tera::{Tera, Context};
use systemd_journal_logger::JournalLog;


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

async fn actix_web_handler() -> impl Responder {
    "Hello from Actix Web!"
}

async fn render_login(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("auth_login.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

async fn render_signup(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("auth_signup.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create hudsucker Proxy server
    JournalLog::default().install().unwrap();
    log::set_max_level(LevelFilter::Debug);

    tokio::spawn(async move {
        if let Err(e) = proxy_handler().await {
            eprintln!("Proxy server error: {:?}", e);
        }
    });

    // Create Actix Web server
    let web_address = ([127, 0, 0, 1], 5566);
    let addr = SocketAddr::from(web_address);
    println!("starting tonleh web at: {:?}", web_address);

    HttpServer::new(|| {
        let tera = Tera::new("templates/**/*").expect("Error readding html templates");

        App::new()
            .app_data(web::Data::new(tera))
            .service(web::resource("/login").route(web::get().to(render_login)))
            .service(web::resource("/signup").route(web::get().to(render_signup)))
            .route("/api", web::get().to(actix_web_handler))
            .service(Files::new("/", "static"))
    })
    .bind(addr)
    .expect("Unable to bind address")
    .run()
    .await
    .expect("Server error");

    Ok(())
}
