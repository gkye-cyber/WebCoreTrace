param (
    [Parameter(Position=0)]
    [ValidateSet("help", "install", "test", "run", "run-core", "html", "json", "clean")]
    [string]$Task = "help"
)

$VenvPython = ".\.venv\Scripts\python.exe"
$VenvPip    = ".\.venv\Scripts\pip.exe"
$VenvPytest = ".\.venv\Scripts\pytest.exe"

switch ($Task) {
    # Display help menu
    "help" {
        Write-Host "Available commands:" -ForegroundColor Cyan
        Write-Host "  .\wlt-setup.ps1 install  - Create .venv and install all dependencies in editable mode"
        Write-Host "  .\wlt-setup.ps1 test     - Run test suite with pytest"
        Write-Host "  .\wlt-setup.ps1 run      - Run CLI console summary on sample log"
        Write-Host "  .\wlt-setup.ps1 html     - Generate HTML forensic report"
        Write-Host "  .\wlt-setup.ps1 json     - Generate JSON forensic report"
        Write-Host "  .\wlt-setup.ps1 clean    - Remove virtualenv, caches, and report files"
    }
    
    # Setup virtual environment and install dependencies
    "install" {
        Write-Host "[-] Creating virtual environment and installing dependencies..." -ForegroundColor Cyan
        python -m venv .venv
        & $VenvPip install --upgrade pip
        & $VenvPip install -r requirements.txt
        & $VenvPip install -e .
        Write-Host "[+] Installation complete!" -ForegroundColor Green
    }

    # Run the test suite
    "test" {
        Write-Host "[-] Running pytest test suite..." -ForegroundColor Cyan
        & $VenvPytest
    }

    # Run triage on sample logs
    "run" {
        Write-Host "[-] Running WebCoreTrace web-log-triage mode on sample log..." -ForegroundColor Cyan
        & $VenvPython -m web_core_trace.cli sample_data\access_sample.log
    }

    # Run 'core mode' on sample memory
    "run-core" {
        Write-Host "[-] Running WebCoreTrace core mode on sample memory dump..." -ForegroundColor Cyan
        & $VenvPython -m web_core_trace.cli --mode core --memory-dump sample_data\memory_sample.json
    }

    # Generate visual HTML report
    "html" {
        Write-Host "[-] Generating HTML forensic report..." -ForegroundColor Cyan
        & $VenvPython -m web_core_trace.cli sample_data\access_sample.log --format html --output report.html
        Write-Host "[+] Generated report.html" -ForegroundColor Green
    }

    # Generate JSON report
    "json" {
        Write-Host "[-] Generating JSON forensic report..." -ForegroundColor Cyan
        & $VenvPython -m web_core_trace.cli sample_data\access_sample.log --format json --output report.json
        Write-Host "[+] Generated report.json" -ForegroundColor Green
    }

    # Remove virtualenv, caches, and report files
    "clean" {
        Write-Host "[-] Cleaning environment and report files..." -ForegroundColor Yellow
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue .venv, .pytest_cache, dist, report.html, report.json
        Get-ChildItem -Path "src" -Filter "*.egg-info" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
        Write-Host "[+] Clean complete!" -ForegroundColor Green
    }
}