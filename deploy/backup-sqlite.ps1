# PhishTide SQLite 备份（Windows）
#
# 有 sqlite3 CLI 时用 .backup 做在线一致性备份；
# 没有时直接复制 db/-wal/-shm，建议先停掉 phishsim.exe。
#
# 用法：
#   .\backup-sqlite.ps1
#   .\backup-sqlite.ps1 -DataDir 'C:\path\to\data' -Keep 30

param(
    [string]$DataDir = (Join-Path $PSScriptRoot "..\data"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\backups"),
    [int]$Keep = 14
)

$ErrorActionPreference = "Stop"
$db = Join-Path $DataDir "phishsim.db"
if (-not (Test-Path $db)) { throw "database not found: $db" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$file = Join-Path $OutDir "phishsim-$stamp.db"

$sqlite = Get-Command sqlite3 -ErrorAction SilentlyContinue
if ($sqlite) {
    & $sqlite.Source $db ".backup '$file'"
    if ($LASTEXITCODE -ne 0) { throw "sqlite3 .backup failed" }
}
else {
    Write-Warning "sqlite3 not found; copying files. Stop phishsim.exe first for a consistent snapshot."
    Copy-Item $db $file
    foreach ($suffix in @("-wal", "-shm")) {
        $side = "$db$suffix"
        if (Test-Path $side) { Copy-Item $side "$file$suffix" }
    }
}

Get-ChildItem $OutDir -Filter "phishsim-*.db" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $Keep |
    Remove-Item -Force

Write-Host "backup ok: $file"
