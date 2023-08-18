use serde::Deserialize;
use actix_web::{web, App, HttpServer, Responder, HttpResponse, HttpRequest};
use actix_session::Session;
use actix_files::Files;
use tera::{Context, Tera};

use crate::data::{get_user, create_user};
use sqlx::sqlite::SqlitePool;

pub struct AppState {
    pub db: SqlitePool,
    pub tmpl: Tera,
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
}

pub async fn actix_web_handler() -> impl Responder {
    "Hello from Tonleh proxy!"
}

pub async fn render_login(data: web::Data<AppState>, req:HttpRequest, session: Session) -> impl Responder {
    let mut ctx = Context::new();

    match session.get::<String>("msg_alert") {
        Ok(message_option) => {
            match message_option {
                None => {}
                Some(msg_alert) => {
                    ctx.insert("msg_alert", &msg_alert);
                    session.remove("msg_alert");
                }
            }
        }
        Err(e) => panic!("{:?}", "cannot access session data"),
    }

    let rendered = data.tmpl.render("auth_login.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn login(data: web::Data<AppState>, form: web::Form<LoginForm>, session: Session) -> impl Responder {
    println!("{:?}", &form.username);
    let user_query = get_user(&data.db, &form.username).await;

    match user_query {
        Ok(None) => {
            session.insert("msg_alert", "User does not exist!").unwrap();

            HttpResponse::SeeOther()
                .header("Location", "/login")
                .finish()
        }
        Ok(user) => {
            session.insert("user", user).unwrap();

            HttpResponse::SeeOther()
                .header("Location", "/")
                .finish()
        }
        Err(e) => panic!("{:?}", "login impossible route. this could not happen"),
    }
}

pub async fn render_signup(data: web::Data<AppState>, req:HttpRequest, session: Session) -> impl Responder {
    let mut ctx = Context::new();

    match session.get::<String>("msg_alert") {
        Ok(message_option) => {
            match message_option {
                None => {}
                Some(msg_alert) => {
                    ctx.insert("msg_alert", &msg_alert);
                    session.remove("msg_alert");
                }
            }
        }
        Err(e) => panic!("{:?}", "cannot access session data"),
    }

    let rendered = data.tmpl.render("auth_signup.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn signup(data: web::Data<AppState>, form: web::Form<LoginForm>, session: Session) -> impl Responder {
    println!("{:?}", &form.username);
    let user_query = get_user(&data.db, &form.username).await;

    match user_query {
        Ok(None) => {
            let user = create_user(&data.db, &form.username).await.ok().unwrap();
            session.insert("user", user).unwrap();

            HttpResponse::SeeOther()
                .header("Location", "/")
                .finish()
        }
        Ok(user) => {
            session.insert("msg_alert", format!("User {} already exists!", &form.username)).unwrap();

            HttpResponse::SeeOther()
                .header("Location", "/login")
                .finish()
        }
        Err(e) => panic!("{:?}", "login impossible route. this could not happen"),
    }
}

pub async fn render_users(data: web::Data<AppState>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("users.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_devices(data: web::Data<AppState>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("devices.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_history(data: web::Data<AppState>, req:HttpRequest) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("history.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}
