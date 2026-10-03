"""Command line entry for the Termux request gate."""

from __future__ import annotations

import logging
import sys
import threading
import time

from requestguard.abuseipdb import AbuseIPDB
from requestguard.config import Config, load_env_files
from requestguard.country import rank_for, score_threshold
from requestguard.gate import Gate
from requestguard.net import normalize_ip
from requestguard.proxy import serve
from requestguard.store import Store

HELP = """\
RequestGuard — Termux에서 앱 앞에 두는 요청 검문

  python3 -m requestguard              프록시를 실행합니다
  python3 -m requestguard bans         남은 차단을 봅니다
  python3 -m requestguard reputation   블랙리스트 조회 캐시를 봅니다
  python3 -m requestguard purge        만료된 기록을 지웁니다
  python3 -m requestguard check <ip>   AbuseIPDB 점수만 조회합니다

처음 보는 공개 IP의 첫 요청은 AbuseIPDB로 국가와 점수를 확인합니다.
한국·일본은 신뢰라 초당 60개, 점수 90부터 막습니다.
미국은 애매해서 초당 30개, 점수 75부터 막습니다.
중국과 그 외 나라는 초당 10개, 점수 25부터 막습니다.
국가를 모르거나 조회가 실패하면 미국과 같은 기본 기준으로 판단합니다.
저장된 차단, 속도, 형식은 그때도 그대로 적용됩니다.
더 빠른 연결은 그 기준에 비례해 차단 일수가 늘어납니다.
하나라도 차단이면 막습니다. 라우터 너머의 MAC은 보이지 않습니다.
LISTEN_PORTS=all 이면 바깥 주소의 모든 포트를 검사하고, 같은 번호의 127.0.0.1으로 넘깁니다.
앱은 127.0.0.1에서만 받으세요.
블랙리스트와 비정상 형식은 30일 뒤에 지워집니다.
설정 파일은 실행 디렉터리의 requestguard.env 입니다.
API 키는 https://www.abuseipdb.com/account/api 에서 발급합니다.
가입 확인 링크는 API 키가 아닙니다.
"""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"-h", "--help", "help"}:
        print(HELP)
        return 0

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    load_env_files()
    config = Config.from_env()
    store = Store(config.db_path)
    command = args[0] if args else "serve"

    if command == "bans":
        _print_bans(store)
        store.close()
        return 0
    if command == "reputation":
        _print_reputation(store, config)
        store.close()
        return 0
    if command == "purge":
        removed = store.purge(time.time())
        print(f"removed {removed}")
        store.close()
        return 0
    if command == "check":
        if len(args) != 2:
            print(HELP, file=sys.stderr)
            store.close()
            return 2
        code = _check(config, args[1])
        store.close()
        return code
    if command != "serve":
        print(HELP, file=sys.stderr)
        store.close()
        return 2

    removed = store.purge(time.time())
    if removed:
        logging.getLogger("requestguard").info("purged %s", removed)
    abuse = AbuseIPDB(config.api_key, config.abuse_max_age_days, config.abuse_timeout)
    gate = Gate(config, store, abuse)
    stop = threading.Event()

    def _purge_loop() -> None:
        while not stop.wait(3600):
            count = store.purge(time.time())
            if count:
                logging.getLogger("requestguard").info("purged %s", count)

    threading.Thread(target=_purge_loop, name="requestguard-purge", daemon=True).start()
    try:
        serve(config, gate)
    finally:
        stop.set()
        store.close()
    return 0


def _print_bans(store: Store) -> None:
    now = time.time()
    rows = store.list_bans(now)
    if not rows:
        print("no bans")
        return
    for ban in rows:
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ban.expires_at))
        print(f"{ban.ip}\t{ban.reason}\t{when}\t{ban.detail}")


def _print_reputation(store: Store, config: Config) -> None:
    rows = store.list_reputation(time.time())
    if not rows:
        print("no reputation cache")
        return
    for row in rows:
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row.expires_at))
        rank = rank_for(row.country, config) or "-"
        country = row.country or "-"
        print(f"{row.ip}\tscore={row.score}\tcountry={country}\trank={rank}\texpires={when}\t{row.detail}")


def _check(config: Config, raw_ip: str) -> int:
    try:
        ip = normalize_ip(raw_ip)
    except ValueError:
        print("invalid ip", file=sys.stderr)
        return 2
    result = AbuseIPDB(config.api_key, config.abuse_max_age_days, config.abuse_timeout).check(ip)
    if not result.ok:
        print(f"check failed: {result.error}", file=sys.stderr)
        return 1
    rank = rank_for(result.country, config)
    threshold = score_threshold(rank, config)
    blocked = result.score >= threshold
    country = result.country or "-"
    print(
        f"{ip} score={result.score} country={country} rank={rank or '-'} "
        f"threshold={threshold} block={blocked}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
