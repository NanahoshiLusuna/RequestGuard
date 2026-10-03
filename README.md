# RequestGuard

**Lightweight Python HTTP reverse proxy for IP filtering, IP reputation, country-based policies, rate limiting, and temporary bans.**

> **HTTP 요청 검사 및 차단 프록시 · HTTP Request Inspection & Blocking Proxy · HTTPリクエスト検査・ブロッキングプロキシ**

**언어 / Language / 言語**

[🇰🇷 한국어](#한국어) · [🇺🇸 English](#english) · [🇯🇵 日本語](#日本語)

---

# 한국어

RequestGuard는 원치 않는 외부 요청으로부터 로컬 애플리케이션과 셀프호스팅 서비스를 보호하기 위한 **경량 HTTP 요청 검사 및 차단 프록시**입니다.

애플리케이션 앞에 위치하여 들어오는 연결을 여러 기준으로 분석하고, 검사 조건을 통과한 요청만 애플리케이션으로 전달합니다.

## 주요 기능

* **IP 평판 조회** — [AbuseIPDB](https://www.abuseipdb.com/)를 이용한 공개 IP 평판 확인
* **국가별 정책** — 감지된 국가에 따라 서로 다른 차단 기준 적용
* **요청 속도 분석** — 설정된 연결 속도를 초과하는 클라이언트 탐지
* **요청 형식 검사** — 잘못되거나 비정상적인 HTTP 요청 거부
* **IP + MAC 분석** — 로컬 네트워크에서 확인 가능한 MAC 주소를 IP와 함께 분석
* **차단 기록** — 이전 차단을 저장하고 만료될 때까지 적용
* **화이트리스트** — 신뢰하는 IP와 MAC 주소를 검사 및 차단에서 제외
* **평판 캐시** — 불필요한 반복적인 평판 조회 방지
* **다중 신호 차단** — 여러 정보를 종합하여 차단 여부 판단
* **Termux 지원** — Android 및 기타 경량 환경에서 실행 가능

## 작동 방식

```text
                 들어오는 요청
                       │
                       ▼
              ┌─────────────────────┐
              │     RequestGuard    │
              ├─────────────────────┤
              │ IP 평판              │
              │ 국가 정책             │
              │ 요청 속도 분석         │
              │ 요청 형식 검사         │
              │ IP / MAC 기록        │
              └──────────┬──────────┘
                         │
                     허용 / 차단
                    │           │
                    ▼           ▼
                   앱          403
```

RequestGuard는 하나의 블랙리스트에만 의존하지 않습니다.

IP 평판, 국가, 요청 속도, 요청 형식 및 기존 차단 기록을 함께 사용하여 판단합니다.

외부 평판 조회가 실패하더라도 기존 차단 기록과 속도 및 형식 검사는 계속 사용할 수 있습니다.

## 요구 사항

* **Python 3.10 이상**
* IP 평판 조회를 위한 **AbuseIPDB API 키**
* Termux 지원

Termux:

```sh
pkg install python
```

## 빠른 시작

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard.git
cd RequestGuard
```

설정 파일을 생성합니다.

```sh
cp requestguard.env.example requestguard.env
```

API 키를 설정합니다.

```env
ABUSEIPDB_API_KEY=your_api_key
```

실행합니다.

```sh
sh run.sh
```

> **중요:** AbuseIPDB 계정 인증 링크는 API 키가 아닙니다. AbuseIPDB 계정 페이지에서 API 키를 생성해야 합니다.

## 설정

설정은 현재 작업 디렉터리의 `requestguard.env`에서 읽습니다.

### 포트 설정

특정 포트:

```env
LISTEN_PORTS=80,443,8000-8010
```

모든 포트:

```env
LISTEN_PORTS=all
```

기본 업스트림 주소:

```env
UPSTREAM_HOST=127.0.0.1
```

클라이언트가 접속한 포트 번호는 업스트림으로 전달될 때 유지됩니다.

`LISTEN_PORTS`가 비어 있으면 `LISTEN_PORT`를 사용하고 `UPSTREAM_PORT`로 전달합니다.

### 애플리케이션 바인딩

애플리케이션을 루프백에 바인딩할 수 있습니다.

```env
HOST=127.0.0.1
PORT=8080
```

공개 주소:

```env
PUBLIC_BASE_URL=http://your-public-address:8080
```

`PUBLIC_BASE_URL`은 브라우저 및 OAuth 콜백에서 사용하는 공개 주소입니다.

애플리케이션의 로컬 수신 주소와 같을 필요는 없습니다.

## 요청 검사

### IP 평판

새로운 공개 IP는 AbuseIPDB를 통해 조회할 수 있습니다.

조회 결과에는 다음 정보가 포함될 수 있습니다.

* Abuse Confidence Score
* 국가
* 신고된 악성 활동 정보

조회 결과는 캐시됩니다.

### 국가별 정책

기본 정책:

| 정책 | 국가         | 평판 기준 | 초당 연결 |
| -- | ---------- | ----: | ----: |
| 신뢰 | 대한민국, 일본   |    90 |    60 |
| 일반 | 미국         |    75 |    30 |
| 엄격 | 중국 및 기타 국가 |    25 |    10 |

국가를 확인할 수 없으면 미국 정책을 기본값으로 사용합니다.

평판 점수가 `0`이라고 해서 국가만으로 차단하지는 않습니다.

### 요청 속도

RequestGuard는 클라이언트의 연결 속도를 추적합니다.

설정된 속도를 반복적으로 초과하면 차단될 수 있습니다.

빠른 연결일수록 더 긴 차단 기간이 적용될 수 있으며 최대 **365일**입니다.

### 요청 형식

비정상적인 HTTP 요청은 애플리케이션에 전달되기 전에 거부될 수 있습니다.

헤더 한 줄 누락과 같은 일부 가벼운 형식 오류는 해당 요청만 거부하고 장기 차단을 생성하지 않을 수 있습니다.

## IP 및 MAC 검사

로컬 네트워크에서 MAC 주소를 확인할 수 있는 경우 IP와 MAC을 함께 검사할 수 있습니다.

둘 중 하나라도 차단되어 있으면 요청이 차단됩니다.

> 라우터 뒤에 있는 클라이언트의 MAC 주소는 일반적으로 수신 장치에서 확인할 수 없습니다.

## 화이트리스트

신뢰하는 IP와 MAC 주소는 `WHITELIST`에 추가할 수 있습니다.

화이트리스트에 등록된 클라이언트는 검사 및 차단을 우회합니다.

## 외부 서비스 장애 처리

AbuseIPDB 조회가 실패하거나 시간 초과되거나 API 키가 거부되어도 해당 이유만으로 요청을 `503`으로 차단하지 않습니다.

기존 차단 기록, 요청 속도 검사 및 요청 형식 검사는 계속 사용할 수 있습니다.

## 차단 기록

기본적으로 다음 이벤트가 **30일** 동안 저장될 수 있습니다.

* 블랙리스트 또는 평판 기반 차단
* 비정상 요청 형식
* 속도 제한 위반

만료된 기록은 다음 명령으로 삭제할 수 있습니다.

```sh
sh run.sh purge
```

차단 기간은 감지된 행동과 설정에 따라 달라질 수 있으며 최대 **365일**입니다.

## 명령어

```sh
sh run.sh                  # 프록시 시작
sh run.sh bans             # 현재 차단 목록
sh run.sh reputation       # 평판 캐시
sh run.sh purge            # 만료된 기록 삭제
sh run.sh check 8.8.8.8   # IP 평판 조회
```

## 차단 응답

차단된 클라이언트는 HTTP `403` 응답을 받습니다.

차단 이유에는 다음과 같은 값이 사용됩니다.

```text
blacklist
rate
format
```

`expires_at`에는 차단 만료 시간이 포함됩니다.

예:

```json
{
  "reason": "rate",
  "expires_at": "2026-10-10T12:00:00Z"
}
```

## 보안 모델

RequestGuard는 **경량 요청 검사 및 차단 계층**입니다.

전용 WAF, 방화벽 또는 DDoS 보호 서비스를 완전히 대체하기 위한 프로그램은 아닙니다.

```text
IP 평판
   +
국가 정책
   +
요청 속도
   +
요청 형식
   +
IP / MAC 기록
   ↓
RequestGuard
   ↓
허용 / 차단
```

## 사용 사례

* 셀프호스팅 웹 애플리케이션
* 로컬 HTTP 서비스
* Termux 서버
* 개발 서버
* 개인 홈 서버
* 개인 API
* OAuth를 사용하는 로컬 애플리케이션
* 소규모 셀프호스팅 서비스

## 제한 사항

* AbuseIPDB의 가용성과 정확성에 의존합니다.
* MAC 주소는 확인 가능한 네트워크에서만 사용할 수 있습니다.
* 국가 정보는 외부 IP 평판 조회를 기반으로 합니다.
* 전용 방화벽이나 DDoS 보호 서비스를 대체하지 않습니다.
* 매우 많은 공개 포트를 동시에 검사하면 리소스 사용량이 증가할 수 있습니다.

---

# English

RequestGuard is a lightweight **HTTP request inspection and blocking proxy** for protecting local applications and self-hosted services from unwanted incoming requests.

It sits in front of your application, analyzes incoming connections using multiple signals, and forwards only requests that pass the configured checks.

## Features

* **IP reputation** — checks public IP reputation through [AbuseIPDB](https://www.abuseipdb.com/)
* **Country-based policy** — applies different thresholds depending on the detected country
* **Rate analysis** — detects clients sending connections faster than the configured limit
* **Request format inspection** — rejects malformed or invalid HTTP requests
* **IP + MAC analysis** — evaluates IP and visible local-network MAC addresses
* **Block history** — remembers previous blocks until they expire
* **Whitelist** — trusted IP and MAC addresses can bypass inspection
* **Reputation cache** — reduces repeated reputation lookups
* **Multi-signal blocking** — combines reputation, country, traffic rate, request format, and block history
* **Termux friendly** — designed for Android and other lightweight environments

## How it works

```text
                 Incoming connection
                         │
                         ▼
              ┌─────────────────────┐
              │     RequestGuard    │
              ├─────────────────────┤
              │ IP reputation       │
              │ Country policy      │
              │ Rate analysis       │
              │ Request format      │
              │ IP / MAC history    │
              └──────────┬──────────┘
                         │
                  Allow / Block
                    │         │
                    ▼         ▼
                  App        403
```

RequestGuard combines multiple signals instead of relying on a single blacklist.

If the external reputation service is unavailable, existing block history, rate checks, and request-format checks can still be used.

## Requirements

* **Python 3.10+**
* **AbuseIPDB API key**
* Termux is supported

```sh
pkg install python
```

## Quick start

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard.git
cd RequestGuard
cp requestguard.env.example requestguard.env
```

Set your API key:

```env
ABUSEIPDB_API_KEY=your_api_key
```

Start RequestGuard:

```sh
sh run.sh
```

> **Important:** The AbuseIPDB account verification link is not an API key. Create an API key from your AbuseIPDB account page.

## Configuration

### Ports

Specific ports:

```env
LISTEN_PORTS=80,443,8000-8010
```

All ports:

```env
LISTEN_PORTS=all
```

Default upstream:

```env
UPSTREAM_HOST=127.0.0.1
```

The client's destination port is preserved when forwarding.

If `LISTEN_PORTS` is empty, RequestGuard uses `LISTEN_PORT` and forwards to `UPSTREAM_PORT`.

### Application binding

```env
HOST=127.0.0.1
PORT=8080
PUBLIC_BASE_URL=http://your-public-address:8080
```

`PUBLIC_BASE_URL` is used for browser and OAuth callbacks and does not have to match the application's local listening address.

## Request inspection

### IP reputation

New public IP addresses can be checked through AbuseIPDB.

Results may include:

* Abuse Confidence Score
* Country
* Previously reported abuse information

Results are cached to reduce unnecessary API requests.

### Country policy

| Policy  | Countries                 | Reputation threshold | Connections / second |
| ------- | ------------------------- | -------------------: | -------------------: |
| Trusted | South Korea, Japan        |                   90 |                   60 |
| Normal  | United States             |                   75 |                   30 |
| Strict  | China and other countries |                   25 |                   10 |

If the country is unknown, the United States policy is used by default.

A reputation score of `0` does not block an address based on country alone.

### Rate analysis

RequestGuard tracks incoming connection rates.

Clients that repeatedly exceed the configured limit can be blocked.

Higher connection rates can result in longer block periods, up to **365 days**.

### Request format

Malformed or invalid HTTP requests can be rejected before reaching the application.

Minor format errors may only reject the current request without creating a long-term block.

## IP and MAC inspection

When a MAC address is visible on the local network, RequestGuard can evaluate it together with the source IP.

If either identity is blocked, the request is blocked.

> MAC addresses behind a router are generally not visible to the receiving device.

## Whitelist

Trusted IP and MAC addresses can be added to `WHITELIST`.

Whitelisted clients bypass inspection and blocking.

## Failure handling

If the AbuseIPDB lookup fails, times out, or the API key is rejected, the request is not automatically blocked with `503` solely because of that failure.

Existing block history, rate analysis, and request-format inspection can still be used.

## Block records

The following events can be stored for **30 days** by default:

* Blacklist or reputation-based blocks
* Abnormal request formats
* Rate-limit violations

Remove expired records with:

```sh
sh run.sh purge
```

Block durations can vary depending on the detected behavior and configuration, up to **365 days**.

## Commands

```sh
sh run.sh                  # Start the proxy
sh run.sh bans             # Show active blocks
sh run.sh reputation       # Show reputation cache
sh run.sh purge            # Remove expired records
sh run.sh check 8.8.8.8   # Check an IP through AbuseIPDB
```

## Block responses

Blocked clients receive an HTTP `403` response.

Possible reasons include:

```text
blacklist
rate
format
```

The `expires_at` field contains the block expiration time.

Example:

```json
{
  "reason": "rate",
  "expires_at": "2026-10-10T12:00:00Z"
}
```

## Security model

RequestGuard is a **lightweight request inspection and blocking layer**.

It is not intended to replace a dedicated WAF, firewall, or DDoS protection service.

```text
IP reputation
      +
Country policy
      +
Rate analysis
      +
Request format
      +
IP / MAC history
      ↓
RequestGuard
      ↓
ALLOW / BLOCK
```

## Use cases

* Self-hosted web applications
* Local HTTP services
* Termux servers
* Development servers
* Small home servers
* Personal APIs
* OAuth-enabled local applications
* Lightweight self-hosted services

## Limitations

* AbuseIPDB availability and accuracy affect reputation checks.
* MAC addresses are only available on networks where they can be observed.
* Country detection depends on the external IP reputation lookup.
* RequestGuard does not replace a dedicated firewall or DDoS protection service.
* Monitoring many public ports can increase resource usage.

---

# 日本語

RequestGuardは、ローカルアプリケーションやセルフホストサービスを不要な外部リクエストから保護するための、**軽量なHTTPリクエスト検査・ブロッキングプロキシ**です。

アプリケーションの前段に配置し、複数の情報を使用して受信接続を分析します。設定された検査を通過したリクエストだけをアプリケーションへ転送します。

## 主な機能

* **IPレピュテーション** — [AbuseIPDB](https://www.abuseipdb.com/) による公開IPの評価
* **国別ポリシー** — 検出された国に応じて異なる基準を適用
* **レート分析** — 設定された接続速度を超えるクライアントを検出
* **リクエスト形式検査** — 不正または不正な形式のHTTPリクエストを拒否
* **IP + MAC分析** — MACアドレスを確認できるローカルネットワークでIPとMACを分析
* **ブロック履歴** — 過去のブロックを保存し、期限まで適用
* **ホワイトリスト** — 信頼されたIPおよびMACアドレスを検査・ブロックから除外
* **レピュテーションキャッシュ** — 不要なAPIへの繰り返しアクセスを削減
* **複数シグナルによるブロック** — 複数の情報を組み合わせて判定
* **Termux対応** — Androidなどの軽量な環境で実行可能

## 動作方式

```text
                 受信接続
                     │
                     ▼
              ┌─────────────────────┐
              │     RequestGuard    │
              ├─────────────────────┤
              │ IPレピュテーション │
              │ 国別ポリシー        │
              │ レート分析          │
              │ リクエスト形式      │
              │ IP / MAC履歴        │
              └──────────┬──────────┘
                         │
                    許可 / ブロック
                    │             │
                    ▼             ▼
                  アプリ          403
```

RequestGuardは単一のブラックリストだけに依存しません。

IPレピュテーション、国、接続速度、リクエスト形式、過去のブロック履歴などを組み合わせて判定します。

外部レピュテーションサービスが利用できない場合でも、既存のブロック履歴、レート検査、リクエスト形式検査を継続できます。

## 必要環境

* **Python 3.10以上**
* **AbuseIPDB APIキー**
* Termux対応

Termux:

```sh
pkg install python
```

## クイックスタート

```sh
git clone https://github.com/NanahoshiLusuna/RequestGuard.git
cd RequestGuard
```

設定ファイルを作成します。

```sh
cp requestguard.env.example requestguard.env
```

APIキーを設定します。

```env
ABUSEIPDB_API_KEY=your_api_key
```

起動します。

```sh
sh run.sh
```

> **重要:** AbuseIPDBのアカウント確認リンクはAPIキーではありません。AbuseIPDBのアカウントページからAPIキーを作成してください。

## 設定

設定は作業ディレクトリの `requestguard.env` から読み込まれます。

### ポート設定

特定のポート:

```env
LISTEN_PORTS=80,443,8000-8010
```

すべてのポート:

```env
LISTEN_PORTS=all
```

デフォルトのアップストリーム:

```env
UPSTREAM_HOST=127.0.0.1
```

クライアントが接続した宛先ポートは転送時にも維持されます。

`LISTEN_PORTS` が空の場合、`LISTEN_PORT` を使用して `UPSTREAM_PORT` に転送します。

### アプリケーションのバインド

```env
HOST=127.0.0.1
PORT=8080
PUBLIC_BASE_URL=http://your-public-address:8080
```

`PUBLIC_BASE_URL` はブラウザおよびOAuthコールバックで使用する公開URLです。

アプリケーションのローカル待受アドレスと同じである必要はありません。

## リクエスト検査

### IPレピュテーション

新しい公開IPアドレスはAbuseIPDBを使用して確認できます。

取得できる情報には以下が含まれます。

* Abuse Confidence Score
* 国
* 過去に報告された不正行為情報

結果はキャッシュされ、不要なAPIリクエストを削減します。

### 国別ポリシー

デフォルトのポリシー:

| ポリシー    | 国          | レピュテーション基準 | 1秒あたりの接続数 |
| ------- | ---------- | ---------: | --------: |
| Trusted | 韓国、日本      |         90 |        60 |
| Normal  | 米国         |         75 |        30 |
| Strict  | 中国およびその他の国 |         25 |        10 |

国を判定できない場合は、米国のポリシーをデフォルトとして使用します。

レピュテーションスコアが `0` であることだけを理由に、国情報だけでブロックすることはありません。

### レート分析

RequestGuardは受信接続速度を追跡します。

設定された上限を繰り返し超えるクライアントはブロックされる場合があります。

高い接続速度ではより長いブロック期間が設定される場合があり、最大 **365日**です。

### リクエスト形式

不正または不正な形式のHTTPリクエストは、アプリケーションに到達する前に拒否できます。

軽微な形式エラーの場合、そのリクエストだけを拒否し、長期的なブロックを作成しない場合があります。

## IPおよびMAC検査

ローカルネットワーク上でMACアドレスを確認できる場合、送信元IPとMACアドレスを組み合わせて検査できます。

どちらか一方がブロックされている場合、リクエストはブロックされます。

> ルーターの背後にあるクライアントのMACアドレスは、通常、受信側のデバイスから確認できません。

## ホワイトリスト

信頼されたIPおよびMACアドレスは `WHITELIST` に追加できます。

ホワイトリストに登録されたクライアントは検査とブロックを回避します。

## 外部サービス障害への対応

AbuseIPDBの検索が失敗、タイムアウト、またはAPIキーが拒否された場合でも、その理由だけで自動的に `503` を返すことはありません。

既存のブロック履歴、レート分析、リクエスト形式検査は引き続き使用できます。

## ブロック記録

デフォルトでは、以下のイベントを **30日間** 保存できます。

* ブラックリストまたはレピュテーションによるブロック
* 異常なリクエスト形式
* レート制限違反

期限切れの記録は次のコマンドで削除できます。

```sh
sh run.sh purge
```

ブロック期間は検出された動作や設定によって異なり、最大 **365日**です。

## コマンド

```sh
sh run.sh                  # プロキシを起動
sh run.sh bans             # 現在のブロック一覧
sh run.sh reputation       # レピュテーションキャッシュ
sh run.sh purge            # 期限切れ記録を削除
sh run.sh check 8.8.8.8   # IPレピュテーションを確認
```

## ブロックレスポンス

ブロックされたクライアントにはHTTP `403` が返されます。

ブロック理由には以下のような値が使用されます。

```text
blacklist
rate
format
```

`expires_at` にはブロックの有効期限が含まれます。

例:

```json
{
  "reason": "rate",
  "expires_at": "2026-10-10T12:00:00Z"
}
```

## セキュリティモデル

RequestGuardは**軽量なリクエスト検査・ブロックレイヤー**として設計されています。

専用のWAF、ファイアウォール、DDoS保護サービスを完全に置き換えるものではありません。

```text
IPレピュテーション
       +
国別ポリシー
       +
レート分析
       +
リクエスト形式
       +
IP / MAC履歴
       ↓
RequestGuard
       ↓
許可 / ブロック
```

## 使用例

* セルフホストWebアプリケーション
* ローカルHTTPサービス
* Termuxサーバー
* 開発サーバー
* 小規模ホームサーバー
* 個人API
* OAuth対応ローカルアプリケーション
* 小規模セルフホストサービス

## 制限事項

* AbuseIPDBの可用性と精度に依存します。
* MACアドレスは確認可能なネットワークでのみ利用できます。
* 国の判定は外部IPレピュテーション検索に依存します。
* 専用ファイアウォールやDDoS保護サービスの代替ではありません。
* 多数の公開ポートを同時に監視すると、リソース使用量が増加する可能性があります。

---

## License

See the repository license file for licensing information.
