use std::process::Command;
use std::fs::{self, File};
use std::io::Read;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};

// ==========================
// 1. Command Injection
// ==========================
fn command_injection(user_input: String) {
    // Semgrep: security-audit / owasp
    let _ = Command::new("sh")
        .arg("-c")
        .arg(user_input) // 🚨 user-controlled command
        .output()
        .expect("failed to execute process");
}

// ==========================
// 2. Hardcoded Secret
// ==========================
fn hardcoded_secret() {
    // Semgrep: generic secrets / audit rules
    let api_key = "AKIAIOSFODNN7EXAMPLE"; // 🚨 hardcoded AWS-like key
    println!("{}", api_key);
}

// ==========================
// 3. Insecure File Read (Path Traversal)
// ==========================
fn read_file(user_path: String) -> String {
    // Semgrep: owasp-top-ten
    let mut file = File::open(user_path).unwrap(); // 🚨 no validation
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    contents
}

// ==========================
// 4. Unsafe Deserialization
// ==========================
fn unsafe_deserialization(input: &str) {
    // Semgrep: security-audit
    let _data: serde_json::Value = serde_json::from_str(input).unwrap(); 
    // 🚨 untrusted JSON directly parsed without validation
}

// ==========================
// 5. XSS (Actix Web)
// ==========================
async fn xss_handler(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let name = query.get("name").unwrap_or(&"guest".to_string());

    // Semgrep: xss rules
    HttpResponse::Ok().body(format!(
        "<html><body>Hello {}</body></html>", // 🚨 unsanitized user input
        name
    ))
}

// ==========================
// 6. Weak Crypto (MD5)
// ==========================
fn weak_crypto(password: &str) -> String {
    // Semgrep: security-audit
    format!("{:x}", md5::compute(password)) // 🚨 MD5 is weak
}

// ==========================
// 7. Insecure Temp File Usage
// ==========================
fn insecure_temp_file() {
    // Semgrep: owasp / audit
    let path = "/tmp/mytempfile"; // 🚨 predictable temp file
    fs::write(path, "sensitive data").unwrap();
}

// ==========================
// 8. SSRF (Basic Pattern)
// ==========================
async fn ssrf(url: String) -> Result<String, reqwest::Error> {
    // Semgrep: owasp-top-ten
    let body = reqwest::get(&url).await?.text().await?;
    // 🚨 user-controlled URL
    Ok(body)
}

// ==========================
// 9. Open Redirect
// ==========================
async fn open_redirect(query: web::Query<std::collections::HashMap<String, String>>) -> impl Responder {
    let url = query.get("redirect").unwrap();

    // 🚨 unvalidated redirect
    HttpResponse::Found()
        .append_header(("Location", url.to_string()))
        .finish()
}

// ==========================
// Main (for completeness)
// ==========================
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    command_injection("ls -la".to_string());
    hardcoded_secret();
    read_file("/etc/passwd".to_string());
    unsafe_deserialization("{\"key\": \"value\"}");
    weak_crypto("password123");
    insecure_temp_file();

    HttpServer::new(|| {
        App::new()
            .route("/xss", web::get().to(xss_handler))
            .route("/redirect", web::get().to(open_redirect))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
