# Demo Command Sheet (Windows PowerShell)

Use this during your live demo. Commands are copy-paste ready.

## 1) Quick Health Check

```powershell
curl.exe -s http://127.0.0.1:8000/health
```

Expected: `{"status":"ok"}`

## 2) Main Demo Flow (PoW on Duplicate)

### 2.1 Create demo file

```powershell
$f = "demo_main.txt"
[System.IO.File]::WriteAllText((Join-Path (Get-Location) $f), "hello dedup demo " + (Get-Date).ToString("o"))
```

### 2.2 First upload (should succeed)

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/upload" `
  -H "X-API-Key: dev-api-key" `
  -H "X-Client-ID: demo-client-1" `
  -F "file=@demo_main.txt"
```

Expected:
- `"status":"Upload successful"`
- `anomaly_result.detection_mode` should be `"supervised"`

### 2.3 Second upload same file (should require PoW)

```powershell
curl.exe -s -X POST "http://127.0.0.1:8000/upload" `
  -H "X-API-Key: dev-api-key" `
  -H "X-Client-ID: demo-client-1" `
  -F "file=@demo_main.txt"
```

Expected:
- HTTP-level behavior shows duplicate path
- Body contains `detail.error = "PoW verification required for duplicate chunks"`
- Body includes `required_challenges`

## 3) Abnormal Behavior Demo (Show It Stops Requests)

This mode is stricter so enforcement is visible in 2 calls.

### 3.1 Restart API in strict mode

```powershell
Get-Process | Where-Object {
  $_.ProcessName -eq "python" -and $_.Path -eq "E:\secure-dedup\.venv\Scripts\python.exe"
} | ForEach-Object {
  Stop-Process -Id $_.Id -Force
}

$env:API_KEYS="dev-api-key"
$env:MODEL_DIR="advanced_artifacts"
$env:STORAGE_BACKEND="localstack"
$env:LOCALSTACK_ENDPOINT="http://127.0.0.1:4566"
$env:AWS_ACCESS_KEY_ID="test"
$env:AWS_SECRET_ACCESS_KEY="test"
$env:AWS_REGION="us-east-1"
$env:S3_BUCKET="chunks"
$env:RATE_LIMIT_THRESHOLD="0.55"
$env:BLOCK_THRESHOLD="0.80"

Start-Process -FilePath ".\.venv\Scripts\python.exe" `
  -ArgumentList "-m","uvicorn","app:app","--host","0.0.0.0","--port","8000" `
  -WorkingDirectory (Get-Location)
```

### 3.2 Run attacker simulation (2 requests)

```powershell
[System.IO.File]::WriteAllText((Join-Path (Get-Location) "attack_sim_demo.txt"), "attack simulation payload")

curl.exe -s -X POST "http://127.0.0.1:8000/upload" `
  -H "X-API-Key: dev-api-key" `
  -H "X-Client-ID: demo-attacker-live" `
  -F "file=@attack_sim_demo.txt"

curl.exe -s -X POST "http://127.0.0.1:8000/upload" `
  -H "X-API-Key: dev-api-key" `
  -H "X-Client-ID: demo-attacker-live" `
  -F "file=@attack_sim_demo.txt"
```

Expected:
- First response: upload may still return success but `policy_decision.action` is `RATE_LIMIT`
- Second response: `detail.error = "Rate limited by anomaly policy"` with status behavior `429`

## 4) Restore Main Demo Mode After Attack Simulation

```powershell
Get-Process | Where-Object {
  $_.ProcessName -eq "python" -and $_.Path -eq "E:\secure-dedup\.venv\Scripts\python.exe"
} | ForEach-Object {
  Stop-Process -Id $_.Id -Force
}

$env:API_KEYS="dev-api-key"
$env:MODEL_DIR="advanced_artifacts"
$env:STORAGE_BACKEND="localstack"
$env:LOCALSTACK_ENDPOINT="http://127.0.0.1:4566"
$env:AWS_ACCESS_KEY_ID="test"
$env:AWS_SECRET_ACCESS_KEY="test"
$env:AWS_REGION="us-east-1"
$env:S3_BUCKET="chunks"
$env:RATE_LIMIT_THRESHOLD="0.70"
$env:BLOCK_THRESHOLD="0.90"

Start-Process -FilePath ".\.venv\Scripts\python.exe" `
  -ArgumentList "-m","uvicorn","app:app","--host","0.0.0.0","--port","8000" `
  -WorkingDirectory (Get-Location)

curl.exe -s http://127.0.0.1:8000/health
```

## 5) Optional Cleanup

```powershell
Remove-Item demo_main.txt -ErrorAction SilentlyContinue
Remove-Item attack_sim_demo.txt -ErrorAction SilentlyContinue
```
