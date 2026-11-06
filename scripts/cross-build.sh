#!/usr/bin/env bash
# Cross-build every module for Linux, Windows and macOS on amd64 and arm64.
# | 交叉编译仓库内所有模块：Linux、Windows、macOS × amd64、arm64。
set -u

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
targets="${TARGETS:-linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64}"
failed=()

while IFS= read -r gomod; do
  dir="$(dirname "$gomod")"
  rel="${dir#"$root"/}"
  for target in $targets; do
    os="${target%/*}"
    arch="${target#*/}"
    printf '==> %s %s\n' "$rel" "$target"
    # vet also type-checks _test.go files, which a plain build does not. | vet
    # 同时类型检查 _test.go 文件，而普通 build 不会。
    if ! (cd "$dir" && GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build ./... &&
      GOWORK=off CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go vet ./...); then
      failed+=("$rel $target")
    fi
  done
done < <(find "$root" -name go.mod -not -path '*/.git/*' | sort)

if ((${#failed[@]})); then
  printf 'cross-build failed: %s\n' "${failed[*]}" >&2
  exit 1
fi
printf 'cross-build ok: %d modules, targets: %s\n' \
  "$(find "$root" -name go.mod -not -path '*/.git/*' | wc -l)" "$targets"
