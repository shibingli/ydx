#!/usr/bin/env bash
# Run build, vet and race tests for every module in the repository.
# | 对仓库内每个模块依次执行构建、静态检查与 race 测试。
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
status=0
while IFS= read -r gomod; do
  dir="$(dirname "$gomod")"
  echo "==> $dir"
  ( cd "$dir" && GOWORK=off go build ./... && GOWORK=off go vet ./... && GOWORK=off go test ./... -race ) || status=1
done < <(find "$root" -name go.mod -not -path '*/.git/*' | sort)
exit "$status"
