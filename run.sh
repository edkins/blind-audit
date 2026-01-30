#!/bin/bash
set -e

echo "=== TEE Hackathon Infrastructure ==="
echo ""

case "$1" in
    build)
        echo "Building all containers..."
        docker-compose build
        ;;
    
    start)
        echo "Starting infrastructure..."
        docker-compose up -d
        echo ""
        echo "Services started:"
        echo "  - Data Provider:  http://localhost:8080"
        echo "  - Judge API:      http://localhost:8081"
        echo "  - Results Board:  http://localhost:8082"
        echo ""
        echo "Run './run.sh logs' to see output"
        ;;
    
    stop)
        echo "Stopping infrastructure..."
        docker-compose down
        ;;
    
    logs)
        docker-compose logs -f
        ;;
    
    clean)
        echo "Removing all containers and volumes..."
        docker-compose down -v
        ;;
    
    reset-pki)
        echo "Regenerating PKI certificates..."
        docker-compose down -v
        docker volume rm tee-hackathon_pki-certs 2>/dev/null || true
        docker-compose up pki-init
        ;;
    
    test)
        echo "Running a simple test..."
        
        # Check if services are running
        if ! curl -s http://localhost:8080/health > /dev/null; then
            echo "Error: Data Provider not running. Run './run.sh start' first."
            exit 1
        fi
        
        echo "Services are healthy!"
        echo ""
        echo "Open http://localhost:8080 in your browser to submit a challenge."
        ;;
    
    *)
        echo "Usage: $0 {build|start|stop|logs|clean|reset-pki|test}"
        echo ""
        echo "Commands:"
        echo "  build      - Build all Docker images"
        echo "  start      - Start all services"
        echo "  stop       - Stop all services"
        echo "  logs       - Follow logs from all services"
        echo "  clean      - Remove all containers and volumes"
        echo "  reset-pki  - Regenerate PKI certificates"
        echo "  test       - Check if services are running"
        exit 1
        ;;
esac
