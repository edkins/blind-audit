#!/bin/bash
# TEE Harness - Build and Run Script

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IMAGE_NAME="tee-harness"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_help() {
    cat << EOF
TEE Dataset Safety Harness - Build and Run Script

Usage: $0 <command> [options]

Commands:
  build           Build the Docker image
  build-dev       Build development image (includes build tools)
  run             Run a challenge
  compile         Compile a WASM challenger
  shell           Open shell in dev container
  test            Run tests with sample data
  clean           Remove Docker images

Run options:
  --wasm <file>       WASM challenger module
  --dataset <dir>     Dataset directory
  --output <file>     Output attestation JSON
  --key <file>        Signing key PEM (optional)

Compile options:
  --source <file>     C source file to compile
  --output <file>     Output WASM file

Examples:
  # Build the container
  $0 build

  # Compile a custom challenger
  $0 compile --source my_checker.c --output my_checker.wasm

  # Run a challenge
  $0 run --wasm ./challengers/pii_detector.wasm --dataset ./my-dataset

  # Run included test
  $0 test
EOF
}

cmd_build() {
    log_info "Building TEE harness Docker image..."
    docker build -t "$IMAGE_NAME" --target runtime "$SCRIPT_DIR"
    log_info "Build complete: $IMAGE_NAME"
}

cmd_build_dev() {
    log_info "Building TEE harness development image..."
    docker build -t "${IMAGE_NAME}:dev" --target development "$SCRIPT_DIR"
    log_info "Build complete: ${IMAGE_NAME}:dev"
}

cmd_run() {
    local wasm=""
    local dataset=""
    local output=""
    local key=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --wasm)
                wasm="$2"
                shift 2
                ;;
            --dataset)
                dataset="$2"
                shift 2
                ;;
            --output)
                output="$2"
                shift 2
                ;;
            --key)
                key="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$wasm" ]] || [[ -z "$dataset" ]]; then
        log_error "Missing required options. Use: $0 run --wasm <file> --dataset <dir>"
        exit 1
    fi
    
    # Resolve to absolute paths
    wasm="$(cd "$(dirname "$wasm")" && pwd)/$(basename "$wasm")"
    dataset="$(cd "$dataset" && pwd)"
    
    log_info "Running challenge..."
    log_info "  WASM: $wasm"
    log_info "  Dataset: $dataset"
    
    local docker_args="-v $wasm:/data/challenger.wasm:ro"
    docker_args="$docker_args -v $dataset:/data/dataset:ro"
    
    local cli_args="--wasm /data/challenger.wasm --dataset /data/dataset"
    
    if [[ -n "$output" ]]; then
        output_dir="$(cd "$(dirname "$output")" && pwd)"
        output_file="$(basename "$output")"
        docker_args="$docker_args -v $output_dir:/data/output"
        cli_args="$cli_args --output /data/output/$output_file"
    fi
    
    if [[ -n "$key" ]]; then
        key="$(cd "$(dirname "$key")" && pwd)/$(basename "$key")"
        docker_args="$docker_args -v $key:/data/key.pem:ro"
        cli_args="$cli_args --key /data/key.pem"
    fi
    
    docker run --rm $docker_args "$IMAGE_NAME" $cli_args
}

cmd_compile() {
    local source=""
    local output=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --source)
                source="$2"
                shift 2
                ;;
            --output)
                output="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$source" ]] || [[ -z "$output" ]]; then
        log_error "Missing required options. Use: $0 compile --source <file> --output <file>"
        exit 1
    fi
    
    source="$(cd "$(dirname "$source")" && pwd)/$(basename "$source")"
    output_dir="$(cd "$(dirname "$output")" && pwd)"
    output_file="$(basename "$output")"
    
    log_info "Compiling $source -> $output_file"
    
    docker run --rm \
        -v "$source:/build/source.c:ro" \
        -v "$output_dir:/build/output" \
        "$IMAGE_NAME" \
        /opt/wasi-sdk/bin/clang \
            -O2 --target=wasm32-wasi \
            -Wl,--export=check_document \
            -Wl,--no-entry \
            -Wl,--allow-undefined \
            -o "/build/output/$output_file" \
            /build/source.c
    
    log_info "Compiled: $output_dir/$output_file"
}

cmd_shell() {
    log_info "Opening shell in development container..."
    docker run -it --rm \
        -v "$SCRIPT_DIR:/workspace" \
        "${IMAGE_NAME}:dev" \
        /bin/bash
}

cmd_test() {
    log_info "Running test with sample data..."
    
    # Create test dataset
    local test_dir=$(mktemp -d)
    mkdir -p "$test_dir/dataset"
    
    # Safe document
    cat > "$test_dir/dataset/safe_doc.txt" << 'EOF'
This is a perfectly safe document.
It contains no personally identifiable information.
Just some regular text about cooking recipes.
EOF
    
    # Unsafe document with PII
    cat > "$test_dir/dataset/unsafe_doc.txt" << 'EOF'
CONFIDENTIAL - Employee Records

John Smith
Social Security: 123-45-6789
Credit Card: 4532015112830366
Email: john.smith@example.com

Please keep this information secure.
EOF
    
    log_info "Test dataset created in $test_dir"
    
    # Run the challenge
    docker run --rm \
        -v "$test_dir/dataset:/data/dataset:ro" \
        "$IMAGE_NAME" \
        --wasm /usr/local/share/challengers/pii_detector.wasm \
        --dataset /data/dataset
    
    # Cleanup
    rm -rf "$test_dir"
    
    log_info "Test complete!"
}

cmd_clean() {
    log_info "Removing Docker images..."
    docker rmi "$IMAGE_NAME" "${IMAGE_NAME}:dev" 2>/dev/null || true
    log_info "Clean complete"
}

# Main command dispatch
case "${1:-}" in
    build)
        shift
        cmd_build "$@"
        ;;
    build-dev)
        shift
        cmd_build_dev "$@"
        ;;
    run)
        shift
        cmd_run "$@"
        ;;
    compile)
        shift
        cmd_compile "$@"
        ;;
    shell)
        shift
        cmd_shell "$@"
        ;;
    test)
        shift
        cmd_test "$@"
        ;;
    clean)
        shift
        cmd_clean "$@"
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        log_error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac