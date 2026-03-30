# VIBEE-Hacker Blackbox Tier 1 Remaining Plugins

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development

**Goal:** 남은 Tier 1 블랙박스 플러그인 6개를 구현하여 핵심 공격 벡터 커버리지를 완성한다.

**Tech Stack:** Python 3.10+, httpx, pytest, pytest-httpx

**Project Root:** `C:/Users/qwaqw/desktop/hacker`

**구현할 플러그인:**
1. `ssti.py` — Phase 3, Server-Side Template Injection (수학 연산 반영 탐지)
2. `xxe.py` — Phase 3, XML External Entity (Content-Type 변경 + 엔티티 주입)
3. `nosql_injection.py` — Phase 3, NoSQL Injection (MongoDB operator 주입)
4. `jwt_check.py` — Phase 3, JWT 토큰 분석 (alg:none, 약한 서명)
5. `file_upload.py` — Phase 3, 파일 업로드 취약점 (확장자 우회)
6. `idor_check.py` — Phase 3, BOLA/IDOR (ID 변조로 타 사용자 접근)

**공통 패턴:** 기존 플러그인과 동일 — `PluginBase` 상속, `async run()`, baseline 비교, `shlex.quote` curl, `MAX_PARAMS`, 1MB 응답 제한, `(TransportError, InvalidURL, DecodingError)` catch.

---

### Task 1: ssti.py — Server-Side Template Injection

수학 연산 페이로드 `{{7*7}}` 주입 후 응답에 `49` 반영 확인.
다중 템플릿 엔진: Jinja2 `{{}}`, Mako `${}`, ERB `<%= %>`, Freemarker `${}`

### Task 2: xxe.py — XML External Entity

POST 요청에 `Content-Type: application/xml` + XML 엔티티 정의 주입.
응답에 `/etc/passwd` 시그니처 또는 에러 메시지 탐지.

### Task 3: nosql_injection.py — NoSQL Injection

JSON body에 MongoDB operator (`{"$gt":""}`, `{"$ne":""}`) 주입.
인증 우회 시나리오: 로그인 엔드포인트에 `{"username":{"$ne":""},"password":{"$ne":""}}` 전송.

### Task 4: jwt_check.py — JWT 토큰 분석

응답/쿠키에서 JWT 토큰 탐지 → `alg:none` 변조 시도, 만료 미검증 확인, payload 내 PII 탐지.

### Task 5: file_upload.py — 파일 업로드 취약점

파일 업로드 폼 탐지 → 이중 확장자(`.php.jpg`), MIME 타입 변조로 업로드 시도.
destructive_level = 1 (데이터 변경 가능)

### Task 6: idor_check.py — BOLA/IDOR

숫자 ID 패턴 탐지 → ID 변조(+1, -1) 후 응답 비교. 동일 데이터 반환 시 취약.
인증 정보 필요하므로 `target.url`에 세션 쿠키가 있어야 유의미.
