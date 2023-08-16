use serde::Deserialize;
use actix_web::{web, App, HttpServer, Responder, HttpResponse, HttpRequest};
use actix_session::Session;
use actix_files::Files;
use tera::{Tera, Context};

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::SqliteConnection;
use sqlx::ConnectOptions;

use crate::data::get_user;

const DB_FILE_PATH: &str = "sqlite://./tonleh_db.sqlite3";

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
}

pub async fn actix_web_handler() -> impl Responder {
    "Hello from Tonleh proxy!"
}

pub async fn render_login(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("auth_login.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn login(form: web::Form<LoginForm>, session: Session) -> impl Responder {
    let mut conn = SqliteConnectOptions::new()
        .filename(DB_FILE_PATH)
        .connect()
        .await.ok().unwrap();

    let user_query = get_user(&mut conn, &form.username).await;

    match user_query {
        Ok(None) => {
            HttpResponse::SeeOther()
                .header("Location", "/login")
                .finish()
        }
        Ok(user) => {
            HttpResponse::SeeOther()
                .header("Location", "/")
                .finish()
        }
        Err(e) => panic!("{:?}", "login impossible route. this could not happen"),
    }
}

pub async fn render_signup(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("auth_signup.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_users(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("users.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_devices(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("devices.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_history(data: web::Data<Tera>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.render("history.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}
