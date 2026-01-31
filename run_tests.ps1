# PowerShell script to run tests
Write-Host "Starting e2e tests..."

# Ensure python is available
if (-not (Get-Command "python" -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found! Please install Python."
    exit 1
}

# Install requests if not installed (basic check)
try {
    python -c "import requests" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing requests package..."
        pip install requests
    }
}
catch {
    Write-Host "Installing requests package..."
    pip install requests
}

# Run the test
Write-Host "Running tests/e2e_test.py..."
python tests/e2e_test.py

if ($LASTEXITCODE -eq 0) {
    Write-Host -ForegroundColor Green "TESTS PASSED"
}
else {
    Write-Host -ForegroundColor Red "TESTS FAILED"
    exit 1
}
