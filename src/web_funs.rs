use serde::Deserialize;
use actix_web::{web, Responder, HttpResponse};
use actix_session::Session;
use tera::{Context, Tera};

use crate::data::{get_user, create_user, get_users, User};
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

pub async fn render_login(data: web::Data<AppState>, session: Session) -> impl Responder {
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
        Err(e) => panic!("{:?}: {:?}", "cannot access session data", e),
    }

    let rendered = data.tmpl.render("auth_login.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn login(data: web::Data<AppState>, form: web::Form<LoginForm>, session: Session) -> impl Responder {
    let user_query = get_user(&data.db, &form.username).await;

    match user_query {
        Ok(None) => {
            session.insert("msg_alert", "User does not exist!").unwrap();

            HttpResponse::SeeOther()
                .append_header(("Location", "/login"))
                .finish()
        }
        Ok(user) => {
            session.insert("user", user).unwrap();

            HttpResponse::SeeOther()
                .append_header(("Location", "/"))
                .finish()
        }
        Err(e) => panic!("{:?}: {:?}", "login impossible route. this could not happen", e),
    }
}

pub async fn render_signup(data: web::Data<AppState>, session: Session) -> impl Responder {
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
        Err(e) => panic!("{:?}: {:?}", "cannot access session data", e),
    }

    let rendered = data.tmpl.render("auth_signup.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn signup(data: web::Data<AppState>, form: web::Form<LoginForm>, session: Session) -> impl Responder {
    let user_query = get_user(&data.db, &form.username).await;

    match user_query {
        Ok(None) => {
            let user = create_user(&data.db, &form.username).await.ok().unwrap();
            session.insert("user", user).unwrap();

            HttpResponse::SeeOther()
                .append_header(("Location", "/"))
                .finish()
        }
        Ok(_user) => {
            session.insert("msg_alert", format!("User {} already exists!", &form.username)).unwrap();

            HttpResponse::SeeOther()
                .append_header(("Location", "/login"))
                .finish()
        }
        Err(e) => panic!("{:?}: {:?}", "login impossible route. this could not happen", e),
    }
}

pub async fn render_users(data: web::Data<AppState>, session: Session) -> impl Responder {
    match session.get::<User>("user") {
        Ok(None) => {
            // user not logged in, got to login page
            HttpResponse::SeeOther()
                .append_header(("Location", "/login"))
                .finish()
        }
        Ok(_user) => {
            // user logged in, see the results
            let mut ctx = Context::new();
            let users_query = get_users(&data.db).await;

            match users_query {
                Ok(users) => {
                    ctx.insert("users", &users);
                }
                Err(e) => panic!("{:?}: {:?}", "not able to get users from the db", e),
            }

            let rendered = data.tmpl.render("users.html", &ctx).unwrap();
            HttpResponse::Ok().body(rendered)
        }
        Err(e) => panic!("{:?}: {:?}", "cannot access session data", e),
    }
}

pub async fn render_devices(data: web::Data<AppState>) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("devices.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_history(data: web::Data<AppState>) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("history.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}

pub async fn render_index(data: web::Data<AppState>) -> impl Responder {
    let mut ctx = Context::new();
    let rendered = data.tmpl.render("index.html", &ctx).unwrap();
    HttpResponse::Ok().body(rendered)
}
