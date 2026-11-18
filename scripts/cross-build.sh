#!/usr/bin/env bash
# Cross-build every module for Linux, Windows and macOS on amd64 and arm64.
# Builds and vets are independent per module/target, so run them concurrently.
# | 交叉编译仓库内所有模块：Linux、Windows、macOS × amd64、arm64。
# 每个模块/目标相互独立，因此并发执行。
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets="${TARGETS:-linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64}"
jobs="${JOBS:-4}"
case "$jobs" in
  ''|*[!0-9]*|0) echo "JOBS must be a positive integer | JOBS 必须为正整数" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
failed="$tmp/failed"
: >"$failed"

run_task() {
  local dir="$1" rel="$2" target="$3" os arch
  os="${target%/*}"
  arch="${target#*/}"
  printf '==> %s %s\n' "$rel" "$target"
  if ! (cd "$dir" &&
    GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build ./... &&
    GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go vet ./...); then
    printf '%s %s\n' "$rel" "$target" >>"$failed"
  fi
}
export -f run_task
export failed

# One task per module and target, three NUL-separated fields per task.
# | 每个模块/目标一个任务，每个任务三个 NUL 分隔字段。
find "$root" -name go.mod -not -path '*/.git/*' -print0 |
  while IFS= read -r -d '' gomod; do
    dir="$(dirname "$gomod")"
    rel="${dir#"$root"/}"
    for target in $targets; do
      printf '%s\0%s\0%s\0' "$dir" "$rel" "$target"
    done
  done |
  xargs -0 -r -n3 -P "$jobs" bash -c 'run_task "$@"' _

if [[ -s "$failed" ]]; then
  printf 'cross-build failed:\n' >&2
  sort -u "$failed" >&2
  exit 1
fi
printf 'cross-build ok: %d modules, targets: %s, jobs: %d\n' \
  "$(find "$root" -name go.mod -not -path '*/.git/*' | wc -l)" "$targets" "$jobs"