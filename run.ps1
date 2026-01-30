param (
    [string]$Command
)

$ErrorActionPreference = "Stop"

function Show-Usage {
    Write-Host "Usage: .\run.ps1 {build|start|stop|logs|clean|reset-pki|test}"
    Write-Host ""
    Write-Host "Commands:"
    Write-Host "  build      - Build all Docker images"
    Write-Host "  start      - Start all services"
    Write-Host "  stop       - Stop all services"
    Write-Host "  logs       - Follow logs from all services"
    Write-Host "  clean      - Remove all containers and volumes"
    Write-Host "  reset-pki  - Regenerate PKI certificates"
    Write-Host "  test       - Check if services are running"
}

if ([string]::IsNullOrEmpty($Command)) {
    Show-Usage
    exit 1
}

Write-Host "=== TEE Hackathon Infrastructure ==="
Write-Host ""

switch ($Command) {
    "build" {
        Write-Host "Building all containers..."
        docker-compose build
    }

    "start" {
        Write-Host "Starting infrastructure..."
        docker-compose up -d
        Write-Host ""
        Write-Host "Services started:"
        Write-Host "  - Data Provider:  http://localhost:8080"
        Write-Host "  - Judge API:      http://localhost:8081"
        Write-Host "  - Results Board:  http://localhost:8082"
        Write-Host ""
        Write-Host "Run '.\run.ps1 logs' to see output"
    }

    "stop" {
        Write-Host "Stopping infrastructure..."
        docker-compose down
    }

    "logs" {
        docker-compose logs -f
    }

    "clean" {
        Write-Host "Removing all containers and volumes..."
        docker-compose down -v
    }

    "reset-pki" {
        Write-Host "Regenerating PKI certificates..."
        docker-compose down -v
        try {
            docker volume rm tee-hackathon_pki-certs -ErrorAction Stop
        } catch {
            Write-Host "Volume might not exist, verifying..."
        }
        docker-compose up pki-init
    }

    "test" {
        Write-Host "Running a simple test..."
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -ErrorAction Stop
            if ($response.StatusCode -eq 200) {
                Write-Host "Services are healthy!"
                Write-Host ""
                Write-Host "Open http://localhost:8080 in your browser to submit a challenge."
            } else {
                Write-Host "Error: Service returned status $($response.StatusCode)"
                exit 1
            }
        } catch {
            Write-Host "Error: Data Provider not running. Run '.\run.ps1 start' first."
            exit 1
        }
    }

    Default {
        Show-Usage
        exit 1
    }
}
