// Diagnostics helper binary for awesome-rust.
// NOTE: This file intentionally contains SAST test cases for Semgrep scanning.

use std::fs;
use std::process::Command;

// ── SAST Issue 1: Hardcoded credentials ─────────────────────────────────────
// Rules: generic.secrets, rust.lang.security.audit.hard-coded-secret
// These regex-patterns are caught by both secret-detection and security-audit rules.

// ── SAST Issue 2: Hardcoded IP address ──────────────────────────────────────
// Rule: generic.secrets / semgrep-rules detect hardcoded network endpoints
const INTERNAL_DB_HOST: &str = "10.0.0.42";
const ADMIN_PANEL_URL: &str = "http://192.168.1.100:8080/admin";

// ── SAST Issue 3: Command injection ─────────────────────────────────────────
// Rule: rust.lang.security.audit.command-injection (shell=true with user input)
fn run_host_check(hostname: &str) -> String {
    // User-controlled `hostname` is interpolated directly into a shell command.
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("ping -c 4 {}", hostname)) // SAST: command injection
        .output()
        .expect("failed to execute process");
    String::from_utf8_lossy(&output.stdout).to_string()
}

// ── SAST Issue 4: Path traversal ─────────────────────────────────────────────
// Rule: rust.lang.security.audit.path-traversal
fn read_report(report_name: &str) -> String {
    // `report_name` comes from user input; no path sanitization is performed.
    let path = format!("/var/app/reports/{}", report_name); // SAST: path traversal
    fs::read_to_string(path).unwrap_or_default()
}

// ── SAST Issue 5: Unsafe raw pointer dereference ─────────────────────────────
// Rule: rust.lang.security.audit.unsafe-block
fn read_raw_value(ptr: *const i32) -> i32 {
    unsafe {
        *ptr // SAST: unsafe dereference of a raw pointer without null/validity check
    }
}

// ── SAST Issue 6: std::mem::transmute (unsafe type reinterpretation) ─────────
// Rule: rust.lang.security.audit.transmute
fn bytes_to_u64(data: &[u8; 8]) -> u64 {
    unsafe {
        std::mem::transmute::<[u8; 8], u64>(*data) // SAST: unsound transmute
    }
}

// ── SAST Issue 7: Insecure TLS — accepting invalid certificates ───────────────
// Rule: rust.reqwest.security.danger-accept-invalid-certs
fn build_insecure_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // SAST: disables TLS certificate validation
        .build()
        .unwrap()
}

// ── SAST Issue 10: Insecure TLS — invalid hostnames accepted ─────────────────
// Rule: rust.reqwest.security.danger-accept-invalid-hostnames
fn build_no_hostname_check_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_hostnames(true) // SAST: disables hostname verification
        .build()
        .unwrap()
}

// ── SAST Issue 11: Weak minimum TLS version (TLS 1.0) ────────────────────────
// Rule: rust.reqwest.security.min-tls-version-too-low
fn build_old_tls_client() -> reqwest::Client {
    reqwest::Client::builder()
        .min_tls_version(reqwest::tls::Version::TLS_1_0) // SAST: TLS 1.0 is insecure
        .build()
        .unwrap()
}

// ── SAST Issue 12: std::mem::forget — intentional memory leak ────────────────
// Rule: rust.lang.security.audit.ban-std-mem-forget
fn process_sensitive_buffer(buf: Vec<u8>) {
    // Prevents the destructor from running, leaking the buffer
    std::mem::forget(buf); // SAST: std::mem::forget bypasses Drop, causing memory leak
}

// ── SAST Issue 13: String::from_utf8_unchecked — bypasses validation ─────────
// Rule: rust.lang.security.audit.unsafe-string-from-utf8
fn decode_user_input(raw: Vec<u8>) -> String {
    // Skips UTF-8 validity check — undefined behaviour on invalid input
    unsafe { String::from_utf8_unchecked(raw) } // SAST: unchecked UTF-8 conversion
}

// ── SAST Issue 14: Box::from_raw — unsafe ownership reclaim ──────────────────
// Rule: rust.lang.security.audit.unsafe-block (Box::from_raw pattern)
fn reclaim_pointer(raw: *mut i32) -> Box<i32> {
    // Reclaiming a raw pointer without any validity guarantee — use-after-free risk
    unsafe { Box::from_raw(raw) } // SAST: Box::from_raw may cause double-free or UAF
}

// ── SAST Issue 15: ptr::copy_nonoverlapping — unsafe bulk memory copy ────────
// Rule: rust.lang.security.audit.unsafe-block (raw pointer operations)
fn bulk_copy(src: *const u8, dst: *mut u8, count: usize) {
    // No bounds checking; any of src/dst/count being invalid causes UB
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst, count); // SAST: unchecked raw memory copy
    }
}

// ── SAST Issue 8: SQL injection via string concatenation ─────────────────────
// Rule: rust.lang.security.audit.sql-injection / owasp-top-ten A1-injection
// User-controlled `username` is interpolated directly into a SQL query string.
async fn fetch_user(pool: &sqlx::PgPool, username: &str) -> Vec<String> {
    let query = format!(
        "SELECT * FROM users WHERE username = '{}'",  // SAST: SQL injection
        username
    );
    sqlx::query_scalar(&query)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}

// ── SAST Issue 9: Writing secrets to log output ──────────────────────────────
// Rule: generic.secrets.security.detected-secret-in-log
fn authenticate(user: &str, password: &str) -> bool {
    // Logging credentials — never log sensitive data
    println!("DEBUG: auth attempt user={} password={}", user, password); // SAST: secret in log
    password == ADMIN_PASSWORD
}

fn main() {
    println!("Running diagnostics against {}", INTERNAL_DB_HOST);
    println!("Admin panel: {}", ADMIN_PANEL_URL);

    let result = run_host_check("localhost");
    println!("{}", result);

    let report = read_report("summary.txt");
    println!("{}", report);

    let _ = authenticate("admin", "hunter2");
    let _client = build_insecure_client();
    let _client2 = build_no_hostname_check_client();
    let _client3 = build_old_tls_client();

    let buf: Vec<u8> = vec![0u8; 64];
    process_sensitive_buffer(buf);

    let raw_bytes: Vec<u8> = vec![104, 101, 108, 108, 111];
    let _s = decode_user_input(raw_bytes);

    // Demonstrate unsafe block usage
    let value: i32 = 42;
    let ptr: *const i32 = &value;
    let out = read_raw_value(ptr);
    println!("raw value: {}", out);

    let bytes: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let num = bytes_to_u64(&bytes);
    println!("transmuted: {}", num);

    // Suppress unused-variable warnings for the constants
    let _ = STRIPE_SECRET_KEY;
    let _ = INTERNAL_API_KEY;
    let _ = AWS_ACCESS_KEY_ID;
    let _ = AWS_SECRET_KEY;
}
