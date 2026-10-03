#!/bin/sh
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3가 없습니다. Termux에서는 pkg install python 을 실행하세요." >&2
  exit 1
fi
exec python3 -m requestguard "$@"
