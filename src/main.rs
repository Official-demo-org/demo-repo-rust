mod auth;
mod network;
mod utils;
mod db;
mod secrets;

fn main() {
    auth::login("admin", "123");
    network::run("ls");
    utils::overflow();
    db::connect();
}
