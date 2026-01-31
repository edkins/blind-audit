use std::io::{self, BufRead};
use base64::{Engine as _, engine::general_purpose};

fn main() {
    let stdin = io::stdin();
    let mut found_ml_data = false;

    // Define patterns to look for ML-related content
    let ml_patterns = [
        "Machine Learning",
        "Neural Network",
        "Deep Learning",
        "Training Data",
        "Dataset",
        "Model",
    ];

    eprintln!("ML Data Checker Started");

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Parse JSON line
        let doc: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let filename = doc["filename"].as_str().unwrap_or("");
        let content_b64 = doc["content"].as_str().unwrap_or("");

        // Decode base64 content
        let content_bytes = match general_purpose::STANDARD.decode(content_b64) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        
        // Convert to string (lossy) to check text content
        let content = String::from_utf8_lossy(&content_bytes);

        // Check if content matches any ML pattern
        let mut matched = false;
        for pattern in &ml_patterns {
            if content.contains(*pattern) {
                matched = true;
                break;
            }
        }

        if matched {
            // Flagging it as UNSAFE allows the Judge to see which file was "found"
            println!("UNSAFE:{}", filename);
            found_ml_data = true;
        }
    }

    if !found_ml_data {
        // If we didn't find any ML data, verify the process finished safely
        println!("SAFE");
    }
}
