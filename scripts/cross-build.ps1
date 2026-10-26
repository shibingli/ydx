# Cross-build every module for Linux, Windows and macOS on amd64 and arm64.
# | 交叉编译仓库内所有模块：Linux、Windows、macOS × amd64、arm64。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($env:TARGETS) {
    $targets = $env:TARGETS -split '\s+'
} else {
    $targets = @(
        'linux/amd64', 'linux/arm64',
        'windows/amd64', 'windows/arm64',
        'darwin/amd64', 'darwin/arm64'
    )
}

$env:GOWORK = 'off'
$env:CGO_ENABLED = '0'
$failed = @()

Get-ChildItem -Path $root -Filter go.mod -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\.git\\' } |
    Sort-Object FullName |
    ForEach-Object {
        $dir = Split-Path -Parent $_.FullName
        $rel = [System.IO.Path]::GetRelativePath($root, $dir)
        foreach ($target in $targets) {
            $parts = $target -split '/'
            $env:GOOS = $parts[0]
            $env:GOARCH = $parts[1]
            Write-Host "==> $rel $target"
            Push-Location $dir
            try {
                go build ./...
                if ($LASTEXITCODE -ne 0) {
                    $failed += "$rel $target"
                }
            } finally {
                Pop-Location
            }
        }
    }

if ($failed.Count -gt 0) {
    Write-Error "cross-build failed: $($failed -join ', ')"
    exit 1
}
Write-Host "cross-build ok: $($targets -join ', ')"
