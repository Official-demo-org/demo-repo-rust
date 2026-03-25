use actix_web::{web, App, HttpServer, Responder, HttpResponse};
mod vuln;

// =====================
// SQL INJECTION (SIMULATED)
// =====================
async fn login(info: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let username = info.get("username").unwrap();
    let password = info.get("password").unwrap();

    let query = format!(
        "SELECT * FROM users WHERE username = '{}' AND password = '{}'",
        username, password
    ); // ⚠️ SQL injection pattern

    HttpResponse::Ok().body(query)
}

// =====================
// COMMAND INJECTION API
// =====================
async fn exec(cmd: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let input = cmd.get("cmd").unwrap().to_string();
    vuln::command_injection(input);
    HttpResponse::Ok().body("Executed")
}

// =====================
// FILE READ API
// =====================
async fn file(path: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let p = path.get("path").unwrap().to_string();
    let content = vuln::read_file(p);
    HttpResponse::Ok().body(content)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting vulnerable server...");

    HttpServer::new(|| {
        App::new()
            .route("/login", web::get().to(login))
            .route("/exec", web::get().to(exec))
            .route("/file", web::get().to(file))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
