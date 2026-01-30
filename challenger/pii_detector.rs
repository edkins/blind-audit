//! Sample Challenge Module
//! 
//! This Rust code can be compiled to WebAssembly to create a challenge module
//! that scans documents for PII patterns.
//!
//! Compile with:
//!   rustup target add wasm32-wasi
//!   cargo build --target wasm32-wasi --release
//!
//! The resulting .wasm file can be submitted to the Data Provider.

use std::io::{self, BufRead};
use regex::Regex;

/// Patterns that indicate potentially unsafe content
struct UnsafePatterns {
    ssn: Regex,
    credit_card: Regex,
    email_list: Regex,
    password: Regex,
}

impl UnsafePatterns {
    fn new() -> Self {
        Self {
            // Social Security Number pattern
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            // Credit card pattern (basic)
            credit_card: Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b").unwrap(),
            // Bulk email addresses
            email_list: Regex::new(r"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b.*){3,}").unwrap(),
            // Password references
            password: Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]").unwrap(),
        }
    }
    
    fn check(&self, content: &str) -> Vec<&'static str> {
        let mut issues = Vec::new();
        
        if self.ssn.is_match(content) {
            issues.push("Contains SSN patterns");
        }
        if self.credit_card.is_match(content) {
            issues.push("Contains credit card patterns");
        }
        if self.email_list.is_match(content) {
            issues.push("Contains bulk email addresses");
        }
        if self.password.is_match(content) {
            issues.push("Contains password references");
        }
        
        issues
    }
}

fn main() {
    let patterns = UnsafePatterns::new();
    let stdin = io::stdin();
    let mut found_unsafe = false;
    
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
        let content = match base64::decode(content_b64) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
            Err(_) => continue,
        };
        
        // Check for unsafe patterns
        let issues = patterns.check(&content);
        
        if !issues.empty() {
            println!("UNSAFE:{}", filename);
            found_unsafe = true;
        }
    }
    
    if !found_unsafe {
        println!("SAFE");
    }
}