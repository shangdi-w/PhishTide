# PhishTide MySQL 备份（Windows）
#
# 用法：
#   .\backup-mysql.ps1
#   .\backup-mysql.ps1 -Password '你的密码' -Keep 30
#   .\backup-mysql.ps1 -MysqlBin 'C:\path\to\mysql\bin'
#
# 建议用「任务计划程序」每天运行一次：
#   程序：powershell.exe
#   参数：-NoProfile -ExecutionPolicy Bypass -File "C:\path\to\deploy\backup-mysql.ps1"
#
# 密码通过 MYSQL_PWD 环境变量传给 mysqldump，不出现在命令行；
# 同一用户下的其他进程仍可能读取该环境变量，敏感环境建议改用
# --defaults-extra-file 指向一个 ACL 受限的选项文件。
# 数据库账号建议使用最小权限账号，不要用 root。

param(
    [string]$MysqlBin = "",
    [string]$Database = "phishsim",
    [string]$User = "phishsim",
    [string]$Password = "",
    [string]$OutDir = (Join-Path $PSScriptRoot "..\backups"),
    [int]$Keep = 14
)

$ErrorActionPreference = "Stop"
if ($MysqlBin -eq "") {
    $dump = (Get-Command mysqldump.exe -ErrorAction Stop).Source
} else {
    $dump = Join-Path $MysqlBin "mysqldump.exe"
}
if (-not (Test-Path $dump)) { throw "mysqldump not found: $dump" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$file = Join-Path $OutDir "$Database-$stamp.sql"

if ($Password -ne "") { $env:MYSQL_PWD = $Password }
try {
    & $dump --single-transaction --quick --routines --triggers `
        --default-character-set=utf8mb4 --databases $Database --result-file="$file"
    if ($LASTEXITCODE -ne 0) { throw "mysqldump exited with $LASTEXITCODE" }
}
finally {
    Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue
}

$zip = "$file.zip"
Compress-Archive -Path $file -DestinationPath $zip -Force
Remove-Item $file

Get-ChildItem $OutDir -Filter "$Database-*.sql.zip" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $Keep |
    Remove-Item -Force

Write-Host "backup ok: $zip"
