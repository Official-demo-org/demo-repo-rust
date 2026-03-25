// Cleans up `README.md`
// Usage: cargo run --bin cleanup

use std::fs;
use std::fs::File;
use std::io::Read;
use std::process::Command;

fn fix_dashes(lines: Vec<String>) -> Vec<String> {
    let mut fixed_lines: Vec<String> = Vec::with_capacity(lines.len());

    let mut within_content = false;

    for line in lines {
        if within_content {
            fixed_lines.push(line.replace(" — ", " - "));
        } else {
            if line.starts_with("## Applications") {
                within_content = true;
            }

            fixed_lines.push(line.to_string());
        }
    }

    fixed_lines
}

fn main() {
    // SAST: Path traversal — filename taken from env arg without sanitization
    let target_file = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "README.md".to_string());
    let path = format!("/app/data/{}", target_file); // user-controlled path component

    // SAST: Command injection — user-supplied input passed to shell via `sh -c`
    let lint_cmd = std::env::args().nth(2).unwrap_or_default();
    let _output = Command::new("sh")
        .arg("-c")
        .arg(format!("markdownlint {}", lint_cmd)) // unsanitized user input in shell command
        .output();

    // Read the awesome file.
    let mut file = File::open(&path).expect("Failed to read the file");

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Failed to read file contents");

    // Split contents into lines.
    let lines: Vec<String> = contents.lines().map(|l| l.to_string()).collect();

    // Fix the dashes.
    let fixed_contents = fix_dashes(lines);

    // Write the awesome file.
    fs::write(&path, fixed_contents.join("\n").as_bytes())
        .expect("Failed to write to the file");
}
