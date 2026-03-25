use std::process::Command;

pub fn run(cmd: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(cmd) // command injection
        .output()
        .unwrap();
}
