# Run build, vet and race tests for every module in the repository.
# | 对仓库内每个模块依次执行构建、静态检查与 race 测试。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$failed = @()
Get-ChildItem -Path $root -Filter go.mod -Recurse -File |
    Where-Object { $_.FullName -notmatch '\\.git\\' } |
    ForEach-Object {
        $dir = Split-Path -Parent $_.FullName
        Write-Host "==> $dir"
        Push-Location $dir
        try {
            $env:GOWORK = 'off'
            go build ./...
            if ($LASTEXITCODE -ne 0) { $failed += $dir; return }
            go vet ./...
            if ($LASTEXITCODE -ne 0) { $failed += $dir; return }
            go test ./... -race
            if ($LASTEXITCODE -ne 0) { $failed += $dir; return }
        } finally {
            Pop-Location
        }
    }
if ($failed.Count -gt 0) {
    Write-Error "failed: $($failed -join ', ')"
    exit 1
}
