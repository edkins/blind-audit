#!/bin/bash
set -e

CHALLENGES_DIR="/challenges"
OUTPUT_DIR="/output"

TARGET=wasm32-wasip1
export CARGO_TARGET_DIR=/tmp/cargo-target
mkdir -p $CARGO_TARGET_DIR

echo "=== Challenger WASM Compiler ==="
echo ""
echo "Looking for Rust projects in $CHALLENGES_DIR"
echo "Compiled WASM files will be placed in $OUTPUT_DIR"
echo ""

compile_project() {
    local project_dir="$1"
    local project_name=$(basename "$project_dir")
    
    echo "----------------------------------------"
    echo "Compiling: $project_name"
    echo "----------------------------------------"
    
    cd "$project_dir"
    
    # Build
    if cargo build --target $TARGET --release 2>&1; then
        # Find the output wasm file
        local wasm_file=$(find "$CARGO_TARGET_DIR/$TARGET/release" -name "*.wasm" -type f | head -1)
        
        if [ -n "$wasm_file" ]; then
            local output_name="${project_name}.wasm"
            cp "$wasm_file" "$OUTPUT_DIR/$output_name"
            echo "✅ Success: $output_name"
            echo "   Size: $(du -h "$OUTPUT_DIR/$output_name" | cut -f1)"
        else
            echo "❌ No .wasm file found in target directory: $CARGO_TARGET_DIR/$TARGET/release"
        fi
    else
        echo "❌ Build failed for $project_name"
    fi
    
    echo ""
}

compile_single_file() {
    local rs_file="$1"
    local filename=$(basename "$rs_file" .rs)
    local log_file="$OUTPUT_DIR/${filename}.log"
    
    echo "----------------------------------------"
    echo "Compiling single file: $filename.rs"
    echo "----------------------------------------"
    
    # Create a temporary Cargo project
    local temp_dir=$(mktemp -d)
    
    mkdir -p "$temp_dir/src"
    cp "$rs_file" "$temp_dir/src/main.rs"
    
    # Generate Cargo.toml
    cat > "$temp_dir/Cargo.toml" << EOF
[package]
name = "$filename"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
base64 = "0.21"
regex = "1.10"

[profile.release]
opt-level = "s"
lto = true
EOF
    
    cd "$temp_dir"
    
    echo "Compiling $filename.rs..." > "$log_file"
    date >> "$log_file"
    echo "----------------------------------------" >> "$log_file"

    if cargo build --target $TARGET --release >> "$log_file" 2>&1; then
        local wasm_file="$CARGO_TARGET_DIR/$TARGET/release/${filename}.wasm"
        
        if [ -f "$wasm_file" ]; then
            cp "$wasm_file" "$OUTPUT_DIR/${filename}.wasm"
            echo "✅ Success: ${filename}.wasm"
            echo "   Size: $(du -h "$OUTPUT_DIR/${filename}.wasm" | cut -f1)"
            echo "----------------------------------------" >> "$log_file"
            echo "✅ Compilation Successful" >> "$log_file"
        else
            echo "❌ No .wasm file generated"
            echo "❌ No .wasm file generated despite successful build exit code" >> "$log_file"
        fi
    else
        echo "❌ Build failed for $filename.rs"
        echo "----------------------------------------" >> "$log_file"
        echo "❌ Compilation Failed" >> "$log_file"
    fi
    
    # Cleanup
    rm -rf "$temp_dir"
    echo ""
}

# Main compilation loop
compile_all() {
    echo "Scanning for Rust projects and files..."
    echo ""
    
    local found_something=false
    
    # First, look for Cargo.toml projects
    for cargo_file in $(find "$CHALLENGES_DIR" -name "Cargo.toml" -type f 2>/dev/null); do
        local project_dir=$(dirname "$cargo_file")
        compile_project "$project_dir"
        found_something=true
    done
    
    # Then, look for standalone .rs files (not in a Cargo project)
    for rs_file in $(find "$CHALLENGES_DIR" -name "*.rs" -type f 2>/dev/null); do
        # Skip if this file is inside a Cargo project (has Cargo.toml in parent dirs)
        local dir=$(dirname "$rs_file")
        if [ -f "$dir/Cargo.toml" ] || [ -f "$dir/../Cargo.toml" ]; then
            continue
        fi
        
        compile_single_file "$rs_file"
        found_something=true
    done
    
    if [ "$found_something" = false ]; then
        echo "No Rust files or Cargo projects found in $CHALLENGES_DIR"
        echo ""
        echo "To add a challenge:"
        echo "  1. Create a .rs file in the challenges directory"
        echo "  2. Or create a Cargo project with 'cargo new my_challenge'"
        echo ""
        echo "The WASM module should:"
        echo "  - Read JSON lines from stdin: {\"filename\": \"...\", \"hash\": \"...\", \"content\": \"<base64>\"}"
        echo "  - Output 'UNSAFE:<filename>' for unsafe documents"
        echo "  - Output 'SAFE' if no unsafe documents found"
    fi
}

# Run initial compilation
compile_all

echo ""
echo "========================================="
echo "Initial compilation complete!"
echo ""
echo "Compiled WASM files:"
ls -la "$OUTPUT_DIR"/*.wasm 2>/dev/null || echo "  (none)"
echo ""
echo "========================================="

# If WATCH mode is enabled, keep watching for changes
if [ "${WATCH:-false}" = "true" ]; then
    echo ""
    echo "Watch mode enabled. Monitoring for changes..."
    echo "(Press Ctrl+C to stop)"
    echo ""
    
    while true; do
        inotifywait -r -e modify,create,delete "$CHALLENGES_DIR" 2>/dev/null
        echo ""
        echo "Changes detected, recompiling..."
        echo ""
        compile_all
    done
else
    echo "Container will exit. Run with WATCH=true to keep monitoring."
fi
