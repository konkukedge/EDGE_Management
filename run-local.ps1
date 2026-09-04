# 로컬 개발 서버 실행 (PowerShell). .env.local 의 값을 읽어 부팅한다.
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

if (-not (Test-Path .env.local)) {
  Write-Error "'.env.local' 이 없습니다. .env.example 을 복사해 값을 채우세요."
}

Get-Content .env.local | ForEach-Object {
  if ($_ -match '^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)$') {
    Set-Item -Path "env:$($Matches[1])" -Value $Matches[2].Trim()
  }
}

$missing = @()
foreach ($v in 'GOOGLE_OAUTH_CLIENT_ID','GOOGLE_OAUTH_CLIENT_SECRET','AUTH_DRIVE_FOLDER_ID','APP_JWT_SECRET') {
  if (-not (Get-Item "env:$v" -ErrorAction SilentlyContinue).Value) { $missing += $v }
}
if ($missing.Count -gt 0) {
  Write-Error ".env.local 에 다음 값이 비어 있습니다:`n      - $($missing -join "`n      - ")"
}

$key = $env:GOOGLE_APPLICATION_CREDENTIALS
if (-not $key) { $key = 'credentials/service-account.json' }
if (-not $env:GOOGLE_SERVICE_ACCOUNT_KEY_JSON -and -not (Test-Path $key)) {
  Write-Error "서비스 계정 키 파일이 없습니다: $key"
}

# 시스템 기본 JVM 이 Java 8 이면 Gradle 이 돌지 않는다.
$jbr = 'C:\Program Files\Android\Android Studio\jbr'
if (-not $env:JAVA_HOME -and (Test-Path "$jbr\bin\java.exe")) { $env:JAVA_HOME = $jbr }
Write-Host "[i] JAVA_HOME=$env:JAVA_HOME"

& .\gradlew.bat --no-daemon bootRun
