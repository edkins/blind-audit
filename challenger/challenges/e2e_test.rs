
    use std::io::{self, BufRead};
    fn main() {
        let stdin = io::stdin();
        for line in stdin.lock().lines() {
            if let Ok(_) = line {
                // Do nothing, safe
            }
        }
    }
    