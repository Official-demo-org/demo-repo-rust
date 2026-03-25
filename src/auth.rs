pub fn login(user: &str, pass: &str) {
    let query = format!(
        "SELECT * FROM users WHERE username='{}' AND password='{}'",
        user, pass
    ); // SQL injection
    println!("{}", query);
}
