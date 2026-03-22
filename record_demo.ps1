param(
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [string]$ApiKey = "dev-api-key",
    [string]$ClientId = "record-demo-client",
    [switch]$AutoAdvance,
    [switch]$RunFullAttackSuite
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$StdOutLog = Join-Path $RepoRoot "demo_api_out.log"
$StdErrLog = Join-Path $RepoRoot "demo_api_err.log"

if (-not $PSBoundParameters.ContainsKey("ClientId")) {
    $ClientId = "record-demo-" + (Get-Date -Format "yyyyMMddHHmmss")
}

if (-not (Test-Path $Python)) {
    throw "Missing virtual environment Python at $Python"
}

Set-Location $RepoRoot

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkGray
    Write-Host $Title -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkGray
}

function Pause-Step {
    param([string]$Prompt = "Press Enter to continue")
    if ($AutoAdvance) {
        Start-Sleep -Seconds 2
    }
    else {
        Read-Host $Prompt | Out-Null
    }
}

function Parse-CurlResponse {
    param([string]$Raw)

    $marker = "`nHTTP_STATUS:"
    $idx = $Raw.LastIndexOf($marker)
    if ($idx -lt 0) {
        throw "Unable to parse HTTP status from curl output.`n$Raw"
    }

    $bodyText = $Raw.Substring(0, $idx).Trim()
    $statusText = $Raw.Substring($idx + $marker.Length).Trim()
    $statusCode = [int]$statusText
    $json = $null

    if ($bodyText) {
        try {
            $json = $bodyText | ConvertFrom-Json
        }
        catch {
            $json = $null
        }
    }

    return @{
        Status = $statusCode
        Text = $bodyText
        Json = $json
    }
}

function Show-Response {
    param(
        [string]$Label,
        [hashtable]$Response
    )

    Write-Host ""
    Write-Host $Label -ForegroundColor Yellow
    Write-Host ("HTTP " + $Response.Status) -ForegroundColor DarkYellow
    if ($Response.Json) {
        $Response.Json | ConvertTo-Json -Depth 100
    }
    elseif ($Response.Text) {
        $Response.Text
    }
    else {
        Write-Host "<empty response>"
    }
}

function Invoke-JsonApi {
    param(
        [string]$Method,
        [string]$Url,
        [hashtable]$Headers,
        [string]$Body = ""
    )

    $args = @("-sS", "-X", $Method, $Url)
    foreach ($entry in $Headers.GetEnumerator()) {
        $args += @("-H", "$($entry.Key): $($entry.Value)")
    }

    $tempBodyPath = $null
    if ($Body) {
        $tempBodyPath = Join-Path $env:TEMP ("secure-dedup-api-body-" + [guid]::NewGuid().ToString("N") + ".json")
        [System.IO.File]::WriteAllText($tempBodyPath, $Body, (New-Object System.Text.UTF8Encoding($false)))
        $args += @("-H", "Content-Type: application/json", "--data-binary", "@$tempBodyPath")
    }

    try {
        $raw = (& curl.exe @args -w "`nHTTP_STATUS:%{http_code}") -join "`n"
        return Parse-CurlResponse -Raw $raw
    }
    finally {
        if ($tempBodyPath -and (Test-Path $tempBodyPath)) {
            Remove-Item $tempBodyPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-UploadApi {
    param(
        [string]$FilePath,
        [string]$PowProofsJson = "",
        [string]$PowProofsFilePath = ""
    )

    $args = @(
        "-sS",
        "-X", "POST",
        "$BaseUrl/upload",
        "-H", "X-API-Key: $ApiKey",
        "-H", "X-Client-ID: $ClientId",
        "-F", "file=@$FilePath"
    )

    if ($PowProofsFilePath) {
        $args += @("-F", "pow_proofs_json=<$PowProofsFilePath")
    }
    elseif ($PowProofsJson) {
        $args += @("-F", "pow_proofs_json=$PowProofsJson")
    }

    $raw = (& curl.exe @args -w "`nHTTP_STATUS:%{http_code}") -join "`n"
    return Parse-CurlResponse -Raw $raw
}

function Ensure-DemoServer {
    try {
        $health = Invoke-JsonApi -Method "GET" -Url "$BaseUrl/health" -Headers @{}
        if ($health.Status -eq 200) {
            Write-Host "Demo server already running at $BaseUrl" -ForegroundColor Green
            return
        }
    }
    catch {
    }

    Write-Host "Starting local demo server..." -ForegroundColor Yellow
    $env:API_KEYS = $ApiKey
    $env:REQUIRE_API_KEY = "true"
    $env:MODEL_DIR = "advanced_artifacts"
    $env:RATE_LIMIT_THRESHOLD = "0.70"
    $env:BLOCK_THRESHOLD = "0.90"
    $env:DEMO_MODE = "true"
    $env:CHUNK_ENCRYPTION_DEFAULT_ON = "true"
    $env:DEDUP_FINGERPRINT_MODE = "secret_hmac"
    $env:DEDUP_FINGERPRINT_DEFAULT_ON = "true"
    $env:STORAGE_BACKEND = "filesystem"

    Start-Process `
        -FilePath $Python `
        -ArgumentList "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000" `
        -WorkingDirectory $RepoRoot `
        -RedirectStandardOutput $StdOutLog `
        -RedirectStandardError $StdErrLog | Out-Null

    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $health = Invoke-JsonApi -Method "GET" -Url "$BaseUrl/health" -Headers @{}
            if ($health.Status -eq 200) {
                Write-Host "Demo server is ready." -ForegroundColor Green
                return
            }
        }
        catch {
        }
    }

    throw "Server did not become healthy in time. Check $StdOutLog and $StdErrLog"
}

function New-ControlledDemoFiles {
    $dir = Join-Path $env:TEMP "secure-dedup-record-demo"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $fileA = Join-Path $dir "duplicate_a.txt"
    $fileB = Join-Path $dir "duplicate_b.txt"
    $ascii = [System.Text.Encoding]::ASCII

    $runTag = [guid]::NewGuid().ToString("N")

    function Expand-Pattern {
        param(
            [string]$Pattern,
            [int]$Length
        )

        $builder = New-Object System.Text.StringBuilder
        while ($builder.Length -lt $Length) {
            [void]$builder.Append($Pattern)
        }
        return $builder.ToString(0, $Length)
    }

    $prefix = Expand-Pattern -Pattern "$runTag-prefix-" -Length 32768
    $middle = Expand-Pattern -Pattern "$runTag-middle-" -Length 32768
    $suffix = Expand-Pattern -Pattern "$runTag-suffix-" -Length 32768
    $payload = $prefix + $middle + $suffix

    [System.IO.File]::WriteAllBytes($fileA, $ascii.GetBytes($payload))
    [System.IO.File]::WriteAllBytes($fileB, $ascii.GetBytes($payload))

    return @{
        Directory = $dir
        FileA = $fileA
        FileB = $fileB
    }
}

function Solve-PowLocally {
    param(
        [string]$ChallengeResponseJson,
        [string]$WorkDir
    )

    $challengePath = Join-Path $WorkDir "pow_challenge_response.json"
    $proofPath = Join-Path $WorkDir "pow_proofs.json"
    $solverPath = Join-Path $WorkDir "solve_pow_local.py"

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($challengePath, $ChallengeResponseJson, $utf8NoBom)

    $pythonSnippet = @"
import sys
import json
from pow import compute_proof
from storage import get_chunk

challenge_path, proof_path = sys.argv[1], sys.argv[2]
proofs = {}
with open(challenge_path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

for challenge in payload.get("detail", {}).get("required_challenges", []):
        chunk_hash = challenge["chunk_hash"]
        challenge_id = challenge["challenge_id"]
        nonce_hex = challenge["nonce_hex"]
        offset = int(challenge["offset"])
        length = int(challenge["length"])
        stored_chunk = get_chunk(chunk_hash)
        nonce = bytes.fromhex(nonce_hex)
        proof = compute_proof(
            stored_chunk,
            nonce,
            offset,
            length,
        )
        proofs[chunk_hash] = {
            "challenge_id": challenge_id,
            "proof": proof,
        }

with open(proof_path, "w", encoding="utf-8") as fh:
    json.dump(proofs, fh, ensure_ascii=True)
"@

    [System.IO.File]::WriteAllText($solverPath, $pythonSnippet, $utf8NoBom)

    $previousPythonPath = $env:PYTHONPATH
    $previousStorageBackend = $env:STORAGE_BACKEND
    $previousLocalChunkDir = $env:LOCAL_CHUNK_DIR
    $previousDemoMode = $env:DEMO_MODE
    $previousChunkEncryption = $env:CHUNK_ENCRYPTION_DEFAULT_ON
    try {
        if ($previousPythonPath) {
            $env:PYTHONPATH = "$RepoRoot;$previousPythonPath"
        }
        else {
            $env:PYTHONPATH = $RepoRoot
        }
        $env:STORAGE_BACKEND = "filesystem"
        $env:LOCAL_CHUNK_DIR = (Join-Path $RepoRoot "local_chunks")
        $env:DEMO_MODE = "true"
        $env:CHUNK_ENCRYPTION_DEFAULT_ON = "true"

        & $Python $solverPath $challengePath $proofPath
        if ($LASTEXITCODE -ne 0) {
            throw "Local PoW solve helper failed."
        }
    }
    finally {
        if ($null -eq $previousPythonPath) {
            Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
        }
        else {
            $env:PYTHONPATH = $previousPythonPath
        }

        if ($null -eq $previousStorageBackend) {
            Remove-Item Env:STORAGE_BACKEND -ErrorAction SilentlyContinue
        }
        else {
            $env:STORAGE_BACKEND = $previousStorageBackend
        }

        if ($null -eq $previousLocalChunkDir) {
            Remove-Item Env:LOCAL_CHUNK_DIR -ErrorAction SilentlyContinue
        }
        else {
            $env:LOCAL_CHUNK_DIR = $previousLocalChunkDir
        }

        if ($null -eq $previousDemoMode) {
            Remove-Item Env:DEMO_MODE -ErrorAction SilentlyContinue
        }
        else {
            $env:DEMO_MODE = $previousDemoMode
        }

        if ($null -eq $previousChunkEncryption) {
            Remove-Item Env:CHUNK_ENCRYPTION_DEFAULT_ON -ErrorAction SilentlyContinue
        }
        else {
            $env:CHUNK_ENCRYPTION_DEFAULT_ON = $previousChunkEncryption
        }
    }

    $proofJson = Get-Content $proofPath -Raw
    $proofObject = $proofJson | ConvertFrom-Json
    return @{
        Status = 200
        Text = $proofJson
        ProofPath = $proofPath
        Json = @{
            pow_proofs = $proofObject
        }
    }
}

Write-Section "Secure Dedup Demo Recorder Helper"
Write-Host "Repo root: $RepoRoot"
Write-Host "Client ID:  $ClientId"

Ensure-DemoServer

Pause-Step "Press Enter to run the frequency-attack test suite"
Write-Section "1. Frequency Attack Resistance"
& $Python -m pytest tests\test_frequency_attack_resistance.py -v -s
if ($LASTEXITCODE -ne 0) {
    throw "Frequency-attack test suite failed."
}

Pause-Step "Press Enter to run the encryption comparison table"
Write-Section "2. Encryption Comparison Table"
& $Python compare_dedup_encryption_schemes.py --print-table
if ($LASTEXITCODE -ne 0) {
    throw "Encryption comparison benchmark failed."
}

Pause-Step "Press Enter to run the live API flow"
Write-Section "3. Live API Flow"
$files = New-ControlledDemoFiles
$headers = @{
    "X-API-Key" = $ApiKey
    "X-Client-ID" = $ClientId
}

$health = Invoke-JsonApi -Method "GET" -Url "$BaseUrl/health" -Headers @{}
Show-Response -Label "GET /health" -Response $health

$uploadA = Invoke-UploadApi -FilePath $files.FileA
if ($uploadA.Status -ne 200) {
    throw "Initial upload did not succeed."
}
Show-Response -Label "POST /upload (file A)" -Response $uploadA

$uploadBFirst = Invoke-UploadApi -FilePath $files.FileB
if ($uploadBFirst.Status -ne 409) {
    throw "Expected file B first upload to return HTTP 409 for PoW."
}
Show-Response -Label "POST /upload (file B, first attempt)" -Response $uploadBFirst

$solve = Solve-PowLocally -ChallengeResponseJson $uploadBFirst.Text -WorkDir $files.Directory
Show-Response -Label "Local PoW solve helper" -Response $solve

$uploadBRetry = Invoke-UploadApi -FilePath $files.FileB -PowProofsFilePath $solve.ProofPath
Show-Response -Label "POST /upload (file B, retry with PoW proofs)" -Response $uploadBRetry
if ($uploadBRetry.Status -ne 200) {
    throw "File B retry with PoW proofs did not succeed."
}

$fileIdA = $uploadA.Json.file.file_id
$fileIdB = $uploadBRetry.Json.file.file_id
$compareUrl = "$BaseUrl/demo/compare-files?file_id_a=$([uri]::EscapeDataString($fileIdA))&file_id_b=$([uri]::EscapeDataString($fileIdB))"
$compare = Invoke-JsonApi -Method "GET" -Url $compareUrl -Headers $headers
if ($compare.Status -ne 200) {
    throw "Compare-files endpoint did not succeed."
}
Show-Response -Label "GET /demo/compare-files" -Response $compare

$forcePayload = @{
    client_id = $ClientId
    action = "RATE_LIMIT"
} | ConvertTo-Json -Compress
$force = Invoke-JsonApi -Method "POST" -Url "$BaseUrl/demo/force-policy" -Headers @{ "X-API-Key" = $ApiKey } -Body $forcePayload
Show-Response -Label "POST /demo/force-policy (RATE_LIMIT)" -Response $force
if ($force.Status -ne 200) {
    throw "Force-policy endpoint did not succeed."
}

$rateLimited = Invoke-UploadApi -FilePath $files.FileA
if ($rateLimited.Status -ne 429) {
    throw "Expected upload after RATE_LIMIT to return HTTP 429."
}
Show-Response -Label "POST /upload after RATE_LIMIT" -Response $rateLimited

$highlights = Invoke-JsonApi -Method "GET" -Url "$BaseUrl/demo/highlights/$ClientId" -Headers $headers
if ($highlights.Status -ne 200) {
    throw "Highlights endpoint did not succeed."
}
Show-Response -Label "GET /demo/highlights/$ClientId" -Response $highlights

$clearPayload = @{
    client_id = $ClientId
} | ConvertTo-Json -Compress
$clear = Invoke-JsonApi -Method "POST" -Url "$BaseUrl/demo/clear-policy" -Headers @{ "X-API-Key" = $ApiKey } -Body $clearPayload
Show-Response -Label "POST /demo/clear-policy" -Response $clear

Pause-Step "Press Enter to run the behavioural detection demo"
Write-Section "4. Behavioural Detection"
if ($RunFullAttackSuite) {
    & $Python -m pytest tests\test_attack_detection_demo.py -v -s
}
else {
    & $Python -m pytest tests\test_attack_detection_demo.py::TestREFAGapDemonstration::test_gap2_refa_has_no_behaviour_detection -v -s
}
if ($LASTEXITCODE -ne 0) {
    throw "Behavioural detection demo failed."
}

Pause-Step "Press Enter to show the dataset answer"
Write-Section "5. Dataset Answer"
Write-Host "Point to these files during the viva:" -ForegroundColor Green
Write-Host "  - multisource_dense_detection_results.csv"
Write-Host "  - dense_artifacts\training_metrics.json"
Write-Host "  - dense_artifacts\evaluation_report.md"
Write-Host ""
Write-Host "Key numbers to say out loud:" -ForegroundColor Green
Write-Host "  - Raw events: 1,026,034"
Write-Host "  - Clients: 72"
Write-Host "  - Dense labelled windows: 221"
Write-Host "  - Best model: random_forest"
Write-Host "  - Best CV macro F1: 0.9652"

Write-Section "Recording Helper Complete"
Write-Host "For narration, open VIDEO_NARRATION.md"
