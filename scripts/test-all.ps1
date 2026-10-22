# Run build, vet and race tests for every module in the repository.
# | 对仓库内每个模块依次执行构建、静态检查与 race 测试。
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# The race detector needs cgo. When the caller did not choose a compiler, prefer clang on
# Windows; it avoids requiring gcc/msys2. | race 检测器需要 cgo。调用方未指定编译器时，
# Windows 上优先使用 clang，避免依赖 gcc/msys2。
if (-not $env:CC) {
    if (Get-Command clang -ErrorAction SilentlyContinue) {
        $env:CC = 'clang'
    }
}
if ($env:CC) {
    $env:CGO_ENABLED = '1'
}
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
