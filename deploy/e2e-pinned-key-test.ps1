# e2e-pinned-key-test.ps1 — Runs the DPoP pinned key rotation E2E test.
# This script manages port-forwards and kubectl operations between test phases.
#
# Prerequisites:
#   - Kind cluster 'lwauth-dev' with lwauth + lwauth-idp deployed
#   - go, kubectl, kind in PATH

$ErrorActionPreference = "Continue"
$context = "kind-lwauth-dev"

function Start-PortForwards {
    # Kill any existing port-forwards on our ports.
    Get-Process -Name kubectl -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -match "port-forward"
    } | Stop-Process -Force -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 1

    # Start port-forwards as background jobs.
    $script:pfLwauth = Start-Process -FilePath kubectl -ArgumentList "port-forward svc/lwauth 8080:8080 --context $context" -PassThru -WindowStyle Hidden
    $script:pfIdp = Start-Process -FilePath kubectl -ArgumentList "port-forward svc/lwauth-idp 9091:9090 --context $context" -PassThru -WindowStyle Hidden

    # Wait for them to be ready.
    Start-Sleep -Seconds 3

    # Verify connectivity.
    for ($i = 0; $i -lt 10; $i++) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:8080/healthz" -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Seconds 1
    }
    Write-Host "WARNING: lwauth healthz not responding" -ForegroundColor Yellow
}

function Stop-PortForwards {
    if ($script:pfLwauth) { Stop-Process -Id $script:pfLwauth.Id -Force -ErrorAction SilentlyContinue }
    if ($script:pfIdp) { Stop-Process -Id $script:pfIdp.Id -Force -ErrorAction SilentlyContinue }
}

# Run the Go test which handles kubectl apply/restart internally.
Write-Host "Building and running pinned key E2E test..." -ForegroundColor Cyan
Start-PortForwards

Push-Location "d:\coding\lightweightauth-idp"
go run ./cmd/e2e-pinned-test/ -idp http://localhost:9091 -lwauth http://localhost:8080 -context $context
$exitCode = $LASTEXITCODE
Pop-Location

Stop-PortForwards
exit $exitCode
