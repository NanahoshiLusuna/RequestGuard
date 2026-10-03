# RequestGuard

Termux나 로컬 기기에서 앱 앞에 두는 HTTP 검문 프록시다. 바깥에서 들어온 요청의 IP, 같은 망의 MAC, AbuseIPDB 점수, 국가를 보고 막은 뒤, 통과한 요청만 앱으로 넘긴다.

## 실행

Python 3.10 이상이 필요하다. Termux에서는 `pkg install python`을 먼저 실행한다.

```sh
cp requestguard.env.example requestguard.env
# ABUSEIPDB_API_KEY에 계정 페이지에서 발급한 키를 넣는다.
# 가입 확인 링크는 키가 아니다.
sh run.sh
```

설정 파일은 실행 디렉터리의 `requestguard.env`다. 키는 [AbuseIPDB API](https://www.abuseipdb.com/account/api)에서 발급한다.

## 포트

`LISTEN_PORTS=all`이면 이 기기의 루프백이 아닌 주소에서 1–65535 포트를 연다. 클라이언트가 접속한 포트 번호 그대로 `UPSTREAM_HOST`(기본 `127.0.0.1`)로 넘긴다.

앱은 `127.0.0.1`에만 바인드한다. `0.0.0.0`에 이미 열린 포트는 프록시가 가져가지 못한다.

```bash
HOST=127.0.0.1
PORT=8080
PUBLIC_BASE_URL=http://공개주소:8080
```

`PUBLIC_BASE_URL`은 브라우저와 OAuth가 돌아올 공개 주소다. 앱의 수신 주소와 같지 않아도 된다. 기기 주소가 바뀌면 프록시를 다시 켠다.

특정 포트만 검사하려면 `LISTEN_PORTS=80,443,8000-8010`처럼 적는다. `LISTEN_PORTS`를 비우면 `LISTEN_PORT` 하나만 받아서 `UPSTREAM_PORT`로 넘긴다.

## 판단

처음 보는 공개 IP는 AbuseIPDB로 국가와 점수를 확인한다. 조회가 실패하거나 키가 거부되면 그 요청을 503으로 막지 않고, 이미 저장한 차단, 속도, 형식으로만 판단한다.

| 순위 | 국가 | 막히는 점수 | 초당 연결 |
|---|---|---|---|
| 신뢰 | 한국, 일본 | 90 | 60 |
| 애매 | 미국 | 75 | 30 |
| 엄격 | 중국과 그 외 | 25 | 10 |

국가를 아직 모르면 미국과 같은 기본 기준을 쓴다. 점수가 0인 주소는 국가만으로 바로 막지 않는다. 더 빠른 연결은 기준 속도에 비례해 차단 일수가 늘고, 365일을 넘지 않는다.

같은 망에서 MAC이 보이면 IP와 함께 센다. 둘 중 하나라도 차단이면 막는다. 라우터 너머의 MAC은 여기까지 오지 않는다. `WHITELIST`에 적은 IP나 MAC은 검사와 차단에서 빠진다.

블랙리스트, 비정상 형식, 기본 속도 초과는 30일 동안 저장된다. 헤더 한 줄이 빠지는 정도의 실수는 그 요청만 거절한다.

## 명령

```sh
sh run.sh                  # 프록시 실행
sh run.sh bans             # 남은 차단
sh run.sh reputation       # 조회 캐시
sh run.sh purge            # 만료된 기록 삭제
sh run.sh check 8.8.8.8    # AbuseIPDB 점수만 조회
```

차단된 클라이언트는 `403`과 `reason`(`blacklist`, `rate`, `format`)을 받는다. `expires_at`은 차단이 끝나는 시각이다.
