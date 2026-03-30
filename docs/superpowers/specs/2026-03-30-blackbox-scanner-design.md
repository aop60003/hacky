# VIBEE-Hacker: Blackbox Scanner Design Spec

## Overview

외부에서 대상 웹 애플리케이션/API/서버에 접근하여 보안 취약점을 탐지하는 블랙박스 스캐너 설계 문서.
소스코드 없이 네트워크 요청과 응답만으로 점검을 수행한다.

총 **82개 플러그인**, 3단계(Phase) 구성.
IPv4/IPv6 듀얼스택 지원.
**Scope**: 웹 애플리케이션, REST/GraphQL API, 서버 인프라. IoT 프로토콜(MQTT, CoAP, Modbus)은 현재 미지원 (향후 확장 예정).

---

## Scan Phases

블랙박스 스캔은 3단계(Phase)로 진행되며, 순서가 보장되어야 한다.

### Phase 정의

- **Phase 1 (Recon)**: 대상 시스템의 공격 표면 파악을 위한 정보 수집. 능동적 탐색(포트 스캔, 서브도메인 브루트포스 등) 포함.
- **Phase 2 (Passive)**: 최소한의 요청으로 설정/구성 미흡을 확인. 악의적 페이로드 주입 없이 응답 분석 중심. 조작된 헤더(Origin, Host 등)를 포함한 정상 요청은 Passive로 간주.
- **Phase 3 (Active)**: 페이로드를 전송하여 취약점 존재 여부를 실증적으로 확인.

### 심각도 체계

기본 심각도(base)에 컨텍스트 조정(context modifier)을 적용:
- 기본 심각도: 각 플러그인에 명시된 기본값
- 컨텍스트 상향: 상태 변경 API의 CSRF → high, OAuth 흐름의 Open Redirect → high 등
- 각 Result 객체에 `base_severity`와 `context_severity`를 분리하여 기록

---

### Phase 1: 정보 수집 (Reconnaissance) — 12개 플러그인

목적: 대상 시스템의 공격 표면(attack surface) 파악

| # | 플러그인 | 점검 내용 | 출력 | Tier |
|---|----------|-----------|------|------|
| 1 | `port_scan.py` | TCP 포트 스캔 (상위 1000개 기본), 서비스 배너 수집. `--udp` 옵션으로 UDP 서비스(DNS/53, SNMP/161, NTP/123, TFTP/69, SSDP/1900) 탐지. `--protocol all`로 TCP+UDP 동시 스캔. IPv4/IPv6 듀얼스택 지원 | 열린 포트 + 서비스명 + 버전 + 프로토콜 | 기존 |
| 2 | `tech_fingerprint.py` | HTTP 응답 헤더, HTML 메타태그, 쿠키 패턴에서 기술 스택 추정 | 프레임워크, 서버, 언어 목록 | 기존 |
| 3 | `cve_lookup.py` | 탐지된 서비스 버전을 NVD/CVE DB와 매칭 | 알려진 CVE 목록 + CVSS 점수 | 기존 |
| 4 | `subdomain_enum.py` | 서브도메인 열거: 사전 브루트포스(Active) + Certificate Transparency 로그 조회(Passive) + DNS 와일드카드 필터링. 방식별 태깅 | 서브도메인 목록 (방식 태그 포함) | Tier 3 |
| 5 | `dns_zone_transfer.py` | 네임서버에 AXFR 요청 시도, 전체 DNS 레코드 유출 여부 확인 | DNS 레코드 전체 (유출 시) | Tier 2 |
| 6 | `waf_detection.py` | 공격 페이로드 전송 후 차단 응답 패턴 분석, WAF 제품 식별 (Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva 등). 결과를 Phase 3에 전달하여 우회 전략 수립에 활용 | WAF 존재 여부 + 제품명 | Tier 2 |
| 7 | `api_discovery.py` | Swagger/OpenAPI/GraphQL 엔드포인트 자동 탐색 (`/swagger.json`, `/openapi.json`, `/graphql`, `/api-docs` 등). `sitemap.xml`에서 API 경로 추출 | API 엔드포인트 목록 + 스키마 | Tier 2 |
| 8 | `robots_sitemap_parser.py` | `robots.txt` Disallow 경로를 민감 경로로 수집 (우선 스캔 대상), `sitemap.xml` 전체 URL 파싱, Allow/Disallow 체계적 분류. Phase 2/3에 전달 | 민감 경로 목록 + 전체 URL 맵 | Tier 2 |
| 9 | `whois_asn.py` | WHOIS 조회, ASN 정보 수집, IP 대역 확인, 도메인 등록자/만료일 정보 | IP 범위, 소유자 정보, ASN | Tier 3 |
| 10 | `snmp_check.py` | SNMP 커뮤니티 스트링 노출 점검 (public/private 등 기본값 시도), SNMP 버전 확인 | 커뮤니티 스트링, 시스템 정보 | Tier 2 |
| 11 | `cloud_service_misconfig.py` | 클라우드 서비스별 미스컨피그: S3 PutObject/DeleteObject 과잉 권한, Azure Blob 익명 접근, GCS allUsers, Firebase Realtime DB 무인증(`.json`), Cognito 공개 SignUp, Lambda Function URL 무인증, API Gateway 리소스 정책/스로틀링 부재 | critical | Tier 2 |
| 12 | `container_orch_check.py` | 컨테이너 오케스트레이션 엔드포인트 노출: kubelet API(10250), etcd(2379), Docker API(`/v1.24/containers/json`), Kubernetes Dashboard 무인증, cAdvisor 노출 | critical | Tier 2 |

소계: 12개 (기존 3 + Tier 2: 7 + Tier 3: 2)

**Note**: Phase 2 플러그인은 #13부터 시작하여 번호 중복 없음.

---

### Phase 2: 수동 점검 (Passive) — 25개 플러그인

목적: 최소한의 요청으로 설정/구성 미흡 확인. 페이로드 주입 없음.

**Note**: Phase 1이 #12까지 확장되어 Phase 2 플러그인 번호는 #13부터 시작해야 하나, 기존 문서 참조 호환을 위해 현재 번호 체계를 유지. 구현 시 연속 번호로 재할당.

#### 보안 헤더/설정

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 11 | `header_check.py` | 보안 헤더 누락 (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, Referrer-Policy, Permissions-Policy) | medium | 기존 |
| 12 | `ssl_check.py` | 인증서 만료/자체서명, 약한 암호 스위트, TLS 1.0/1.1 사용, 인증서 체인 문제, HSTS Preload List 포함 여부, `includeSubDomains`/`preload` 디렉티브, `max-age` 충분성 | high~critical | 기존 (확장) |
| 13 | `cors_check.py` | CORS 설정 점검: `Origin` 헤더 변경 응답 분석, 와일드카드(`*`) + Credentials 조합, null origin 허용, 프리픽스 매칭 우회, `Access-Control-Max-Age` 과도 설정 | high | Tier 1 |
| 14 | `csp_analysis.py` | CSP 심층 분석: `unsafe-inline`/`unsafe-eval`, 과도한 소스 허용(`*`, `data:`, `blob:`), JSONP CDN 포함, `base-uri`/`frame-ancestors` 미설정, Report-Only 모드 경고 | medium~high | Tier 3 |
| 15 | `clickjacking.py` | X-Frame-Options + CSP `frame-ancestors` 종합 점검, 민감 페이지별 세분화 검증 | medium | Tier 3 |
| 16 | `http_methods.py` | OPTIONS 요청으로 허용 메서드 확인, TRACE(XST) 허용 여부, 불필요한 PUT/DELETE 허용 탐지 | medium | Tier 3 |

#### 정보 노출

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 17 | `debug_detection.py` | 디버그 모드 활성화 탐지 (Django debug, Laravel Ignition, ASP.NET Yellow Screen 등), 디버그 엔드포인트 (`/console`, `/__debug__/`, `/telescope`, `/_debugbar`) | high | Tier 2 |
| 18 | `server_info_leak.py` | `Server`, `X-Powered-By`, `X-AspNet-Version` 등 정보 노출 헤더, HTML 주석 내 버전/개발자 정보, `/server-info`, `/nginx_status` 등 상태 페이지 | low | Tier 3 |
| 19 | `unnecessary_services.py` | 프로덕션 불필요 서비스: Redis/Memcached/Elasticsearch 무인증 노출, `/metrics`, `/actuator`, `/health`, `/phpinfo()`, `/test` | medium~critical | Tier 2 |
| 20 | `security_txt_check.py` | `/.well-known/security.txt` 존재 및 RFC 9116 준수 (Contact, Expires, Encryption) | info | Tier 3 |

#### 데이터 보호

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 21 | `sensitive_data_exposure.py` | HTTP 응답 본문에서 민감 정보 정규식 탐지: 카드번호, 주민등록번호, API 키, 비밀번호 해시 등. 평문 전송 여부 확인 | high | Tier 2 |
| 22 | `mixed_content.py` | HTTPS 페이지에서 HTTP 리소스 로딩 탐지. Active(JS/CSS/iframe) vs Passive(이미지/비디오) 구분. CSS 내 `@import`, `url()` 포함 | medium (Active MC: high) | Tier 3 |
| 23 | `sri_check.py` | 외부 CDN `<script>`, `<link>` 태그에 SRI `integrity` 속성 존재 확인, `crossorigin` 설정, 해시 알고리즘 강도(SHA-256+) | medium | Tier 3 |
| 24 | `cookie_security.py` | 쿠키 정적 속성 분석 전담: SameSite 심층(SameSite=None+Secure 미설정), Path 범위, 만료 정책, Domain 와일드카드, `__Host-`/`__Secure-` 접두사 미사용, 세션 토큰 엔트로피. (세션 관리 로직은 `auth_check.py` 담당) | medium | Tier 3 |

#### DNS/인프라

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 25 | `dangling_dns.py` | CNAME 대상 부재 탐지. 서비스 패턴: S3, Azure, GitHub Pages, Heroku, Netlify, Vercel, Shopify, Fastly, Pantheon, Tumblr, WordPress.com, Cargo, Surge.sh, Fly.io. 서브도메인 테이크오버 가능성 | high | Tier 2 |
| 26 | `email_security.py` | SPF/DKIM/DMARC 레코드 존재 및 강도 검증: `+all`/`~all` 느슨한 정책, `p=none` 미적용 정책 탐지 | medium | Tier 3 |

#### 클라우드

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 27 | `cloud_storage_exposure.py` | HTML/JS 내 S3/GCS/Azure Blob URL 추출, 디렉터리 리스팅(ListBucket) 시도, 도메인 기반 버킷 이름 추측 | critical | Tier 2 |
| 28 | `cloud_creds_leak.py` | 응답 내 클라우드 자격 증명 정규식 탐지: AWS Access Key(`AKIA...`), GCP API Key(`AIza...`), GitHub Token(`ghp_`), Slack Token(`xoxb-`), Private Key 헤더 | critical | Tier 2 |
| 29 | `api_key_exposure.py` | URL 쿼리 파라미터, JS 소스코드, 에러 응답 내 API 키 평문 노출 (공급자별 패턴 매칭) | critical | Tier 2 |

#### API 전용 (Passive)

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 30 | `api_schema_exposure.py` | Swagger/OpenAPI 스펙이 인증 없이 프로덕션에 노출, 내부 전용 엔드포인트 포함 여부 확인 | medium | Tier 3 |
| 31 | `api_versioning_check.py` | 구버전 API(`/api/v1/`, `/api/v0/`) 활성 여부, 보안 패치 미적용 구버전 응답 비교 | medium | Tier 3 |
| 32 | `graphql_introspection.py` | GraphQL 인트로스펙션 쿼리(`__schema`) 활성화 여부, 필드 제안(suggestion) 기능으로 스키마 유추 가능 여부 | high | Tier 2 |
| 33 | `excessive_data_exposure.py` | API 응답이 필요 이상의 데이터 반환: `password`, `hash`, `internal_id`, `_id`, `__v` 등 민감/내부 키 패턴, 페이지네이션 없는 전체 데이터 | high | Tier 3 |
| 34 | `pii_leakage.py` | API 응답 내 PII 비마스킹 노출: 이메일, 전화번호, 주민등록번호(6-7자리), 카드번호 전체 자릿수 | high | Tier 3 |
#### 프론트엔드 보안

| # | 플러그인 | 점검 내용 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 35 | `js_lib_audit.py` | 프론트엔드 JS 라이브러리(jQuery, Angular 등) 버전 정밀 탐지, Retire.js DB 매칭으로 클라이언트사이드 취약점 식별 | medium | Tier 3 |

소계: 25개 (기존 2 + Tier 1: 1 + Tier 2: 8 + Tier 3: 14)

---

### Phase 3: 능동 점검 (Active) — 45개 플러그인

목적: 페이로드를 전송하여 취약점 존재 여부를 실증적으로 확인

#### 인젝션 계열

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 36 | `sqli.py` | 파라미터에 SQL 페이로드 주입, 에러 기반/시간 기반/UNION 기반 탐지 | critical | 기존 |
| 37 | `xss.py` | Reflected/Stored/DOM-based/Blind XSS. DOM-based: JS sink(`innerHTML`, `eval`, `document.write`) + source(`location.hash`, `document.cookie`) 분석. Blind XSS: OOB 콜백 서버 연동으로 관리패널/로그뷰어 트리거 탐지 | high (stored: critical) | 기존 (확장) |
| 38 | `cmdi.py` | OS 명령어 주입: `; sleep 5`, `| whoami` 등 시간/출력/OOB 기반 탐지. 다양한 구분자(`;`, `|`, `||`, `&&`, `` ` ``, `$()`) | critical | Tier 1 |
| 39 | `ssti.py` | Server-Side Template Injection: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>` 등 엔진별 페이로드, Phase 1 프레임워크 정보 연계 | critical | Tier 1 |
| 40 | `xxe.py` | XML External Entity: 외부 엔티티 정의 주입, OOB XXE, Content-Type을 `application/xml`로 변경하여 XML 파서 트리거 | critical | Tier 1 |
| 41 | `crlf_injection.py` | URL 파라미터/헤더에 `%0d%0a` 주입, 응답 헤더에 새 헤더 삽입 여부 확인 (HTTP Response Splitting) | high | Tier 2 |
| 42 | `graphql_injection.py` | GraphQL 변수/인자를 통한 SQL/NoSQL 주입, 에러 메시지 내 DB 쿼리 구조 노출 확인 | critical | Tier 2 |
| 43 | `nosql_injection.py` | MongoDB/CouchDB 연산자 주입: `{"$gt":""}`, `$ne`, `$regex`, `$where` JavaScript 실행. JSON body + 쿼리 파라미터 모두 점검 | critical | Tier 1 |
| 44 | `ldap_injection.py` | LDAP 필터 주입: `)(cn=*)`, `*)(uid=*))(|(uid=*` 등. 로그인 폼 및 검색 기능 대상 | high | Tier 2 |
| 45 | `xpath_injection.py` | XPath 쿼리 주입: `' or '1'='1`, `' or ''='` 등. XML 기반 데이터 저장소 대상 | high | Tier 3 |
| 46 | `prototype_pollution.py` | 서버사이드: Node.js `__proto__`, `constructor.prototype` 주입 (JSON body). 클라이언트사이드: URL fragment/query → `Object.prototype` 오염 → DOM XSS/Cookie 변조 탐지 (`--headless` 필수) | high | Tier 2 |

#### 접근 제어

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 47 | `idor_check.py` | BOLA/IDOR: 리소스 ID 변조(순차/UUID)로 타 사용자 데이터 접근, 응답 내 사용자 식별 필드 불일치 비교 | critical | Tier 1 |
| 48 | `bfla.py` | 일반 사용자 토큰으로 관리자 API(`/api/admin/*`, DELETE/PUT 메서드) 호출, 403/401 외 응답 시 취약 | critical | Tier 2 |
| 49 | `path_traversal.py` | `../../../etc/passwd` 등 주입, 인코딩 우회(`%2e%2e%2f`, `%c0%ae`), NULL 바이트(`%00`), 응답에서 파일 시그니처 매칭 | critical | Tier 1 |
| 50 | `forced_browsing.py` | 비인증 세션으로 보호 페이지 URL 직접 접근 시도, 크롤러 수집 URL 중 인증 필요 페이지 재접근 | high | Tier 2 |
| 51 | `dir_enum.py` | 경로 브루트포스: `/admin`, `/.env`, `/.git`, `/backup`, `/wp-admin`, `/phpmyadmin`, `/.DS_Store`, `/server-status` 등. robots.txt Disallow 경로 우선 스캔 | medium~critical | 기존 (Phase 3으로 이동) |
| 52 | `default_creds.py` | 관리 인터페이스(Tomcat Manager, phpMyAdmin, Jenkins, Grafana, Spring Boot Actuator 등) 기본 자격증명 시도. 공개된 기본값 목록 기반 | critical | 기존 (Phase 3으로 이동) |
| 53 | `file_upload.py` | 파일 업로드 취약점: 웹쉘 업로드, MIME 타입 우회(`image/png` 헤더 + PHP 코드), 확장자 필터링 우회(이중 확장자 `.php.jpg`, null 바이트), polyglot 파일, 업로드 경로 조작 | critical | Tier 1 |

#### 인증/세션

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 54 | `csrf.py` | 폼에 CSRF 토큰 유무 확인, 토큰 없이 상태 변경 요청 시도 | base: medium, 상태변경 API: high | 기존 |
| 55 | `auth_check.py` | 세션 관리 로직 전담: 세션 고정, 로그아웃 후 세션 재사용, 세션 타임아웃 미설정, 동시 세션 제한 부재, 2FA/MFA 우회(응답 변조, 2FA 단계 건너뛰기, OTP 브루트포스/rate limit, 백업 코드 열거, 2FA 등록 해제 API 무인증 접근). (쿠키 정적 속성은 `cookie_security.py` 담당) | high | 기존 (역할 분리) |
| 56 | `jwt_check.py` | `alg:none` 공격, HS256→RS256 혼동, 만료(`exp`) 미설정/미검증, `kid` 헤더 주입(경로순회/SQL), `jku` 헤더 스푸핑, JWK 헤더 인젝션(self-signed key), JWKS 엔드포인트 접근성, payload 내 PII | critical | Tier 1 |
| 57 | `oauth_check.py` | `redirect_uri` 검증 우회, `state` 파라미터 부재, Authorization Code 재사용, `client_secret` 미필수, PKCE 미지원 | high | Tier 2 |
| 58 | `broken_auth_flow.py` | Authorization 헤더 제거/빈 토큰/잘못된 토큰으로 API 접근, 200+데이터 반환 시 취약 | critical | Tier 2 |
| 59 | `rate_limit_check.py` | 로그인/비밀번호 재설정/OTP 엔드포인트에 50~100회 반복 요청, 429 응답/계정 잠금/CAPTCHA 발생 여부 확인 | high | Tier 2 |
| 60 | `user_enum.py` | 존재/비존재 사용자 요청 시 응답 코드, 메시지, 시간 차이 비교. 차별적 메시지/타이밍 공격 기반 열거 가능성 | medium | Tier 3 |
| 61 | `password_policy_check.py` | 회원가입/비밀번호 변경 시 약한 비밀번호(`123456`, `password`, 빈 문자열) 허용 여부 확인 | medium | Tier 3 |

#### SSRF/리다이렉트

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 62 | `ssrf.py` | SSRF 취약점 존재 여부 확인 전담: 내부 URL 주입, DNS 리바인딩(TTL 조작), URL 파서 혼동(`evil.com@127.0.0.1`), 프로토콜 스머글링(`gopher://`, `file://`), IPv6(`::1`, `::ffff:127.0.0.1`, `fe80::1%25eth0`, `[::1]`), 302 리다이렉트 체인, IP 표현 변형(decimal `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`), `localhost`/`localtest.me`. (클라우드 메타데이터는 `cloud_metadata.py` 담당) | critical | 기존 (역할 분리) |
| 63 | `open_redirect.py` | 리다이렉트 파라미터에 외부 URL 주입, 실제 리다이렉트 발생 확인 | base: medium, OAuth 흐름: high | 기존 |
| 64 | `cloud_metadata.py` | 발견된 SSRF를 통한 클라우드 메타데이터 심층 추출 전담: IMDSv1/v2 구분, IAM 역할 자격 증명, 사용자 데이터, VPC 정보. AWS/GCP/Azure 엔드포인트별 심층 분석 | critical | Tier 2 |

#### 프로토콜/캐시

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 65 | `http_smuggling.py` | HTTP/1.1: Content-Length + Transfer-Encoding 동시 포함 (CL.TE, TE.CL, TE.TE), Transfer-Encoding 난독화. HTTP/2: H2.CL, H2.TE Desync, H2C Smuggling, HTTP/2 CRLF, HTTP/2 Rapid Reset (CVE-2023-44487). 시간 기반 탐지 | critical | Tier 2 |
| 66 | `host_header_injection.py` | `Host: evil.com` / `X-Forwarded-Host` 주입, 응답 링크/리다이렉트 반영 여부, 비밀번호 재설정 링크 도메인 변경 확인 | high | Tier 2 |
| 67 | `cache_poisoning.py` | 비캐시키 헤더(`X-Forwarded-Host`, `X-Original-URL`) 주입, 캐시 가능 응답(`Cache-Control`, `Age`)에서 주입값 캐시 여부 | high | Tier 2 |
| 68 | `http_method_tampering.py` | `X-HTTP-Method-Override`, `X-Method-Override` 헤더로 메서드 변조, 읽기 전용 엔드포인트에 쓰기 메서드 오버라이드 시도 | medium | Tier 3 |

#### API 전용 (Active)

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 69 | `mass_assignment.py` | PUT/PATCH/POST body에 비인가 필드(`role`, `is_admin`, `price`) 추가 전송, 응답에서 반영 여부 확인 | high | Tier 2 |
| 70 | `graphql_depth_limit.py` | 재귀 관계 필드를 10~20단계 중첩 쿼리 전송, 깊이 제한 에러 없이 처리 시 취약 | high | Tier 2 |
| 71 | `graphql_batch_attack.py` | 단일 HTTP 요청에 100+ GraphQL 쿼리 배열 전송, 배치 크기 제한/Rate Limit 우회 가능 여부 | high | Tier 2 |
| 72 | `verbose_error.py` | 의도적으로 잘못된 입력/타입 미스매치/존재하지 않는 엔드포인트로 에러 유발, 응답 내 스택 트레이스/DB 쿼리/내부 경로 노출 탐지 | medium | Tier 2 |

#### 기타

| # | 플러그인 | 점검 방법 | 심각도 | Tier |
|---|----------|-----------|--------|------|
| 73 | `websocket_check.py` | WS 엔드포인트 탐색, Origin 검증 부재, 인증 없는 연결, 메시지 입력 검증(XSS/SQLi), `ws://` 평문 사용, CSWSH | high | Tier 2 |
| 74 | `waf_bypass.py` | 탐지된 WAF 규칙 우회: 인코딩 변형(더블 URL/유니코드), chunked 분할, HPP, 대소문자/주석 삽입, Content-Type 변경 | high | Tier 2 |
| 75 | `deserialization_check.py` | 직렬화 객체 엔드포인트 탐지: Java(`rO0AB`/`aced0005`, `application/x-java-serialized-object`), PHP(`O:`, `a:`), Python(`\x80\x04\x95`), .NET BinaryFormatter(`AAEAAAD/////` Base64, `\x00\x01\x00\x00\x00`), ASP.NET ViewState(`__VIEWSTATE` MAC 미서명), .NET DataContractSerializer/XmlSerializer. 에러 기반 탐지(ClassNotFoundException 등). RCE 직결 | critical | Tier 2 |
| 76 | `race_condition.py` | 동일 요청 N회 동시 전송 후 리소스 상태 비교: 쿠폰 이중 사용, 잔액 이중 인출, 좋아요 중복 등 TOCTOU 취약점 | high | Tier 2 |
| 77 | `business_logic.py` | 가격 파라미터 음수/0 입력, 수량 한도 우회, 단계 건너뛰기(step skipping), 쿠폰 코드 재사용. 커스텀 룰 정의 지원 (`business_rules.yaml`) | high | Tier 2 |
| 78 | `content_type_confusion.py` | Content-Type 기반 공격: JSON→XML 자동 변환(XXE 유도), multipart boundary 조작, text/plain으로 CORS preflight 우회, Content-Type 헤더 제거/변경 시 서버 동작 변화 분석 | high | Tier 2 |
| 79 | `subdomain_takeover_poc.py` | `dangling_dns.py`(Phase 2)에서 탐지된 Dangling CNAME에 대해 실제 테이크오버 가능 여부 실증: 서비스별(S3, GitHub Pages, Heroku 등) 클레임 가능 조건 확인, 오탐 감소 | high | Tier 2 |
| 80 | `llm_injection.py` | AI/LLM 연동 엔드포인트 탐지(`/chat`, `/completion`, `/ask`, `/summarize` 등 경로 패턴 + 비결정적 자연어 응답 구조 분석) 후 Prompt Injection 시도: 시스템 프롬프트 추출, 도구 호출 유도, 간접 주입(저장 데이터 경유), 출력 내 민감정보 유출 | critical | Tier 2 |

소계: 45개 (기존 8 + Tier 1: 8 + Tier 2: 25 + Tier 3: 4)

---

## Crawler

능동 점검에 앞서 대상의 엔드포인트를 자동 수집하는 크롤러.

### 동작 방식

1. 시작 URL에서 HTML 파싱하여 링크(`<a>`, `<form>`, `<script>` src 등) 추출
2. 같은 도메인 내에서 재귀적으로 탐색
3. 각 페이지에서 폼 필드, 쿼리 파라미터, API 엔드포인트 수집
4. JavaScript 내 API 호출 패턴도 정규식으로 추출 (fetch, axios, XMLHttpRequest)
5. Headless Browser(Playwright) 기반 SPA 렌더링 후 동적 링크/API 호출 수집 (`--headless` 옵션으로 활성화)
6. WebSocket/SSE 엔드포인트 자동 수집 (JS 소스 내 `new WebSocket()`, `EventSource()` 패턴 탐지)

### 설정

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `max_depth` | 3 | 최대 크롤링 깊이 |
| `max_pages` | 500 | 최대 수집 페이지 수 (대규모 앱은 `--max-pages 5000` 권장) |
| `respect_robots` | **false** | robots.txt 존중 여부. 보안 테스트에서는 Disallow 경로가 오히려 우선 스캔 대상 |
| `scope` | same-domain | 크롤링 범위 (same-domain, same-origin, custom regex) |
| `headless` | false | Playwright 기반 SPA 렌더링 활성화. Playwright 컨텍스트에 `auth_cookie` 자동 주입. localStorage/sessionStorage 기반 토큰 지원(`--auth-storage`). SPA 토큰 리프레시 감지: XHR/fetch 인터셉터로 새 토큰 캡처 후 HTTP 클라이언트와 동기화 |
| `auth_cookie` | none | 인증된 크롤링을 위한 세션 쿠키 |
| `auth_header` | none | 인증된 크롤링을 위한 Authorization 헤더 |
| `login_url` | none | 자동 로그인 URL (login_form과 함께 사용) |
| `login_form` | none | 자동 로그인 폼 필드 (JSON: `{"username":"admin","password":"pass"}`) |
| `auth_config` | none | 다중 권한 크롤링 설정 파일 (YAML). 역할별 크롤링으로 IDOR/BFLA 비교 대상 확보 |

다중 권한 크롤링 설정 예시 (`auth-config.yaml`):
```yaml
roles:
  - name: unauthenticated
  - name: user
    cookie: "session=user_token"
  - name: admin
    header: "Authorization: Bearer admin_token"
```
Crawler가 각 역할별로 크롤링 → EndpointRegistry에 `accessible_roles` 필드로 기록 → IDOR/BFLA가 역할 간 접근 차이를 자동 비교.
특정 역할 인증 실패 시: 해당 역할만 skip + warning, 나머지 역할로 계속 진행.

### 출력

```python
@dataclass
class CrawlResult:
    urls: list[str]                    # 발견된 URL 목록
    forms: list[FormInfo]              # 폼 정보 (action, method, fields)
    parameters: dict[str, list[str]]   # URL별 쿼리 파라미터
    api_endpoints: list[ApiEndpoint]   # 구조화된 API 엔드포인트 (아래 참조)
    websocket_endpoints: list[str]     # WebSocket 엔드포인트
    sse_endpoints: list[str]           # Server-Sent Events 엔드포인트
    auth_required_urls: list[str]      # 인증 세션에서만 발견된 URL
    auth_context: dict[str, str]       # URL별 발견 시 인증 상태 (authenticated/unauthenticated)
```

## Rate Control (속도 제어)

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `--delay` | 100ms | 요청 간 딜레이 |
| `--concurrency` | 10 | 동시 요청 수 |
| `--timeout` | 10s | 개별 요청 타임아웃 |
| `--max-retries` | 2 | 요청 실패 시 재시도 횟수 |
| `--proxy` | none | HTTP/SOCKS5 프록시 (예: `http://127.0.0.1:8080`) |
| `--proxy-auth` | none | 프록시 인증 (예: `user:pass`) |
| `--ssl-no-verify` | false | 프록시 사용 시 TLS 검증 비활성화 |
| `--profile` | default | 스캔 프로파일: `stealth`(저속/UA랜덤/셔플), `default`, `aggressive`(고속/전체), `ci`(핵심만/JSON) |

- 대상 서버 부하 방지를 위해 기본값은 보수적으로 설정
- HTTP 429 (Rate Limit) 감지 시 지수 백오프 자동 적용
- 사용자가 `--aggressive` 플래그로 제한 완화 가능
- 시간 기반 탐지 플러그인(`sqli.py`, `cmdi.py` 등)은 `--timeout` 값에 페이로드 지연 시간(기본 5초)을 자동 가산
- 시간 기반 탐지 시 동시성을 자동으로 1로 제한하여 baseline 응답 시간 왜곡 방지
- **시간 기반 판정 알고리즘**: (1) baseline 응답 시간 3회 측정 → 평균(avg) + 표준편차(stddev) 계산, (2) 임계값 = avg + max(3*stddev, 페이로드 지연 시간*0.8), (3) 3회 시도 중 2회 이상 임계값 초과 시 취약 판정, (4) 네트워크 지터 보정: stddev > avg*0.5 시 baseline 불안정으로 시간 기반 탐지 skip + warning
- `race_condition.py`는 Rate Control의 **delay/concurrency만 오버라이드**하며, 프록시/Scope Enforcement/인증 헤더 주입은 동일 적용 (`--race-threads`, 기본 20)

## CLI Interface

```bash
# 기본 블랙박스 스캔 (전체 Phase)
vibee-hacker scan --target https://example.com --mode blackbox

# Phase 지정
vibee-hacker scan --target https://example.com --phase recon
vibee-hacker scan --target https://example.com --phase passive
vibee-hacker scan --target https://example.com --phase active

# 특정 플러그인만 실행
vibee-hacker scan --target https://example.com --plugin sqli,xss,cmdi

# 카테고리별 실행
vibee-hacker scan --target https://example.com --category injection
vibee-hacker scan --target https://example.com --category api
vibee-hacker scan --target https://example.com --category infra

# 포트 스캔 범위/프로토콜 지정
vibee-hacker scan --target 192.168.1.1 --ports 1-65535
vibee-hacker scan --target 192.168.1.1 --ports 1-65535 --udp

# Tier별 실행 (점진적 스캔)
vibee-hacker scan --target https://example.com --tier 1      # 핵심만
vibee-hacker scan --target https://example.com --tier 1,2    # 핵심+중요
vibee-hacker scan --target https://example.com --tier all     # 전체

# 속도 조정
vibee-hacker scan --target https://example.com --delay 500 --concurrency 5

# 인증 정보 전달
vibee-hacker scan --target https://example.com --cookie "session=abc123"
vibee-hacker scan --target https://example.com --header "Authorization: Bearer token"
vibee-hacker scan --target https://example.com --auth-config auth.yaml

# 스코프/제외
vibee-hacker scan --target https://example.com --exclude-url "/logout,/delete"
vibee-hacker scan --target https://example.com --exclude-param "csrf_token"  # 주입 대상에서만 제외, 존재 여부 점검에는 영향 없음
vibee-hacker scan --target https://example.com --include-only "/api/*"

# 리포트 출력
vibee-hacker scan --target https://example.com --output report.html --format html
vibee-hacker scan --target https://example.com --output report.json --format json
vibee-hacker scan --target https://example.com --output report.pdf --format pdf
vibee-hacker scan --target https://example.com --output report.sarif --format sarif
vibee-hacker scan --target https://example.com --output report.xml --format zap-xml
vibee-hacker scan --target https://example.com --output report.json --format gitlab-dast

# 세션 저장/재개
vibee-hacker scan --target https://example.com --save-session scan-001
vibee-hacker scan --resume scan-001

# 이전 결과 대비 diff / 오탐 필터링
vibee-hacker scan --target https://example.com --baseline previous-report.json
vibee-hacker scan --target https://example.com --false-positive fp-list.yaml

# 프록시/프로파일
vibee-hacker scan --target https://example.com --proxy http://127.0.0.1:8080
vibee-hacker scan --target https://example.com --profile stealth
vibee-hacker scan --target https://example.com --profile ci --fail-on critical,high

# CI/CD 통합
vibee-hacker scan --target https://example.com --fail-on critical  # critical 발견 시 exit 1
vibee-hacker scan --target https://example.com --quiet --json-summary  # 파이프라인용

# OOB 콜백 서버
vibee-hacker scan --target https://example.com --oob-server auto  # 자동 터널
vibee-hacker scan --target https://example.com --oob-server https://your-callback.com
```

## Result Severity Scale

| Level | 의미 | 예시 |
|-------|------|------|
| critical | 즉시 악용 가능, 시스템 장악 위험 | SQLi, RCE, CMDi, XXE, 기본 자격증명, Deserialization |
| high | 심각한 데이터 유출/조작 가능 | XSS (stored), 세션 하이재킹, 약한 TLS, CORS 오류 |
| medium | 제한적 영향 또는 추가 조건 필요 | CSRF, 보안 헤더 누락, Open Redirect |
| low | 정보 노출 수준 | 서버 버전 노출, 불필요한 HTTP 메서드 |
| info | 참고 정보 | 기술 스택 탐지, 열린 포트 목록 |

컨텍스트 기반 조정: 각 Result에 `base_severity` + `context_severity` 분리 기록.

## Development Tiers (개발 우선순위)

| Tier | 플러그인 수 | 설명 |
|------|------------|------|
| 기존 | 10개 | 원본 설계 포함 항목 (확장/이동 포함) |
| Tier 1 | 9개 | 필수 — 블랙박스 스캐너 기본 기능 완성에 필수 |
| Tier 2 | 37개 | 중요 — 실질적 위험이 높은 점검 항목 |
| Tier 3 | 23개 | 권장 — 커버리지 완성도 향상 |
| **합계** | **80개** | Phase 1: 10 + Phase 2: 25 + Phase 3: 45 |

## Phase Dependencies

```
Phase 1 (Recon) ─────┐
                      ├──→ Phase 2 (Passive) ─────→ Phase 3 (Active)
Crawler ─────────────┘
```

- Crawler는 `robots_sitemap_parser.py`(#8) 완료 후 Disallow 경로를 우선 큐에 반영하여 크롤링 시작
- Phase 1의 나머지 플러그인과 Crawler는 병렬 실행 가능
- Phase 1(`api_discovery.py`) + Crawler의 API 결과는 중앙 **EndpointRegistry**에 병합 (URL 정규화 + 중복 제거 + 출처 태깅)
- Phase 2는 Phase 1 완료 후 시작 (기술 스택 정보 활용)
- Phase 3는 Phase 2 + Crawler 완료 후 시작 (EndpointRegistry + 설정 정보 활용)
- WAF Detection(Phase 1) 결과는 Phase 3 플러그인에 전달되어 페이로드 전략 조정
- `ssrf.py` 결과는 `cloud_metadata.py`에 전달. SSRF 미발견 시 `cloud_metadata.py`는 skip
- `dangling_dns.py`(Phase 2) 결과는 `subdomain_takeover_poc.py`(Phase 3)에 전달

### Phase 3 내부 실행 순서 (Sub-ordering)

Phase 3 플러그인은 다음 서브페이즈 순서로 실행:
1. **Pre-scan**: `waf_bypass.py` — WAF 우회 페이로드 생성, 후속 플러그인에 전달
2. **Enumeration**: `dir_enum.py`, `default_creds.py`, `forced_browsing.py` — 추가 엔드포인트/접근 경로 발견
3. **Injection**: `sqli.py`, `xss.py`, `cmdi.py`, `ssti.py`, `xxe.py`, `graphql_injection.py` 등 인젝션 계열 — WAF 우회 결과 활용
3.5. **API Abuse**: `graphql_depth_limit.py`, `graphql_batch_attack.py`, `mass_assignment.py`, `content_type_confusion.py` — API 전용 능동 점검
4. **Auth/Access**: `idor_check.py`, `bfla.py`, `jwt_check.py` 등 인증/접근 제어 계열
5. **Protocol**: `http_smuggling.py`, `cache_poisoning.py` 등 프로토콜 계열
6. **Post-scan**: `race_condition.py`, `business_logic.py` — 다른 결과에 의존하는 점검
7. **Verification**: `subdomain_takeover_poc.py`, `cloud_metadata.py` — Phase 2 결과 실증

## Authentication Management

인증된 스캔 시 세션 유지 메커니즘:
- 스캔 중 401/403 응답 감지 시 `login_url`/`login_form`으로 자동 재인증
- 세션 갱신 후 실패한 요청 자동 재시도
- `auth_cookie`/`auth_header` 지정 시 모든 요청에 자동 포함
- 세션 만료 탐지: 연속 3회 이상 401/403 시 재인증 트리거
- 재인증 실패 시 스캔 일시정지 + 사용자 알림

## Scan Session Management

- `--save-session`: 스캔 진행 상태를 JSON으로 저장 (완료된 플러그인, 중간 결과, 크롤러 상태)
- `--resume`: 저장된 세션에서 중단 지점부터 재개
- 세션 파일 포함 사항: 타겟, 옵션, 진행률, 부분 결과, Phase 간 전달 데이터(inter-phase context: WAF 탐지, 기술 스택, SSRF 발견, dangling DNS, EndpointRegistry 등)
- Resume 시 이전 Phase 결과를 세션에서 복원하여 재실행 불필요
- **Resume 시 인증 사전 검증**: 첫 동작으로 토큰 유효성 확인 (GET / 또는 지정 health endpoint). 만료 시 자동 재인증 시도, 불가 시 사용자 알림 후 스캔 시작 차단
- 세션 파일 무결성 검증 (SHA-256 체크섬)
- **직렬화 프로토콜**: JSON (Python dataclass → dict 변환). `set[str]` → JSON array, `datetime` → ISO 8601 문자열, 중첩 dataclass 재귀 직렬화. 세션 파일 헤더에 스펙 버전 포함 (`"spec_version": "1.0"`), 버전 불일치 시 마이그레이션 또는 경고

## False Positive Management

- `--false-positive fp-list.yaml`: 이전에 확인된 오탐 목록을 필터링
- `--baseline previous-report.json`: 이전 스캔 대비 새로 발견된 항목만 표시 (diff 모드)
- 웹 대시보드에서 결과별 오탐 마킹 → 자동으로 fp-list에 추가

## OOB Callback Infrastructure

Blind 계열 탐지(Blind XSS, OOB XXE, Blind SSRF, Blind CMDi, Blind SSTI)에 필수.

- **내장 모드**: `--oob-server auto` — 자동으로 ngrok/Cloudflare Tunnel을 통해 콜백 서버 노출
- **외부 모드**: `--oob-server https://your-callback.com` — 사용자가 운영하는 외부 콜백 서버 지정
- **지원 프로토콜**: HTTP, DNS, SMTP
- **콜백 상관(correlation)**: 플러그인별 고유 토큰 발급, 콜백 수신 시 토큰으로 원본 요청 자동 매칭
- **연동 플러그인**: `xss.py`, `xxe.py`, `ssrf.py`, `cmdi.py`, `ssti.py`
- OOB 서버 미설정 시 Blind 탐지 비활성화 + 경고 출력

### OOB Callback Lifecycle
- 스캔 완료 후 `--oob-wait` (기본 30분) 동안 콜백 서버 유지
- `--oob-persistent` 모드: 백그라운드 데몬으로 지속 운영, 콜백 수신 시 기존 리포트에 append
- 세션 파일에 OOB 토큰 맵 저장 → resume 시 이전 토큰 콜백도 매칭 가능
- `vibee-hacker oob-status --session scan-001` 명령으로 대기 중인 콜백 확인

## Result Object Schema

```python
@dataclass
class Result:
    plugin_name: str          # 어떤 플러그인이 발견했는지
    base_severity: str        # critical / high / medium / low / info
    context_severity: str     # 컨텍스트 조정 후 심각도
    title: str                # "SQL Injection in /api/users"
    description: str          # 상세 설명
    evidence: str             # 매칭된 패턴/값 (증거)
    recommendation: str       # 수정 권고
    cwe_id: str | None        # CWE 번호
    cvss_score: float | None  # CVSS 점수
    request_raw: str          # 전체 HTTP 요청 원문
    response_raw: str         # 전체 HTTP 응답 원문 (10KB 초과 시 truncate)
    curl_command: str         # 재현용 cURL 명령어
    timestamp: datetime       # 탐지 시각
    endpoint: str             # 대상 엔드포인트
    param_name: str | None    # 취약 파라미터명
    validated: bool = False           # 자동 재검증 통과 여부
    validation_count: int = 0         # 재현 성공 횟수 / 시도 횟수
    confidence: str = "tentative"     # confirmed / tentative / unverified
    plugin_status: str = "completed"  # completed / partial / failed
```

Phase 3 완료 후 선택적 `--verify` 서브페이즈: critical/high 결과를 자동 재전송으로 검증.

## EndpointRegistry Schema

Phase 간 핵심 데이터 허브. Crawler + api_discovery + robots_sitemap_parser 결과를 통합.

```python
@dataclass
class ParamInfo:
    name: str
    location: str        # query / body / path / header / cookie
    type: str | None     # string / int / file / json 등

@dataclass
class ApiEndpoint:
    url: str
    method: str                    # GET, POST, PUT, DELETE, PATCH
    params: list[ParamInfo]
    content_type: str | None       # request content-type
    auth_required: bool
    source: str                    # js_extract / openapi / crawler / robots

@dataclass
class EndpointEntry:
    url_normalized: str            # scheme + host + path (query 제외)
    methods: set[str]
    params: list[ParamInfo]
    sources: list[str]             # ["crawler", "api_discovery", "robots_sitemap"]
    auth_context: str              # authenticated / unauthenticated / both
    accessible_roles: set[str]     # 접근 가능한 역할 목록 (다중 권한 크롤링 시)
    content_types: set[str]
    response_status: int | None    # 마지막 관찰된 HTTP 상태 코드
    response_content_type: str | None  # 응답 Content-Type
    response_size: int | None      # 응답 바이트 크기
    technologies: set[str]         # 해당 엔드포인트에서 탐지된 기술 (Phase 1 연계)

class EndpointRegistry:
    def register(entry: EndpointEntry) -> None    # 중복 시 merge (아래 규칙)
    def query(phase: str = None, plugin: str = None, auth: str = None) -> list[EndpointEntry]

# URL 정규화 규칙:
#   - scheme: 소문자 통일
#   - host: 소문자 통일, 포트 80/443 제거
#   - path: 트레일링 슬래시 통일, 퍼센트 인코딩 정규화, path parameter 패턴화 (/users/123 → /users/{id})
#   - query/fragment: 제거 (params는 별도 ParamInfo로 관리)
#
# Merge 전략:
#   - 동일 url_normalized: methods/sources/content_types/accessible_roles는 union
#   - ParamInfo: 동일 name+location → type이 다르면 "mixed"로 마킹
#   - response 메타데이터: 최신 관찰값으로 덮어쓰기
#
# Path Parameter 패턴화 휴리스틱:
#   - 순수 숫자 → {id}
#   - UUID 패턴 (8-4-4-4-12 hex) → {uuid}
#   - 그 외 가변 세그먼트: 동일 prefix 경로에서 해당 위치만 다른 URL 2개 이상 발견 시 패턴화
#   - 패턴화 미확실 시 원본 유지 (보수적)
```

## CI/CD Integration

- `--fail-on <severity>`: 지정 심각도 이상 발견 시 exit code 1 반환 (예: `--fail-on critical,high`)
- `--quiet`: 요약만 stdout, 상세는 파일 출력
- `--json-summary`: 파이프라인 파싱용 단일 JSON 요약
- 지원 리포트 형식: SARIF (GitHub), GitLab DAST JSON, OWASP ZAP XML
- 예시 파이프라인 설정은 `docs/ci-examples/`에 제공 (GitHub Actions, GitLab CI, Jenkins)

## Scan Profiles

| Profile | delay | concurrency | plugins | UA | 순서 |
|---------|-------|-------------|---------|-----|------|
| `stealth` | 1-5초 랜덤 | 2 | Tier 1만 | 랜덤화 | 셔플 |
| `default` | 100ms | 10 | Tier 1+2 | 고정 | 순차 |
| `aggressive` | 0ms | 50 | 전체 | 고정 | 순차 |
| `ci` | 50ms | 5 | Tier 1만 | 고정 | 순차 |

## Plugin Execution Policy

- 각 플러그인은 독립 코루틴으로 격리 실행
- 플러그인 예외 시: 해당 플러그인만 FAILED 처리, 부분 결과 보존, 나머지 계속 진행
- 연속 5개 플러그인 실패 시 대상 서버 다운 의심 → 스캔 일시정지 + 헬스체크 (GET /)
- 헬스체크 성공 시 재개, 실패 시 사용자 알림 후 대기
- 각 Result에 `plugin_status` (completed / partial / failed) 기록
- 최종 리포트에 실행 실패 플러그인 목록 및 사유 포함
- 각 서브페이즈에 전체 타임아웃 설정 (기본: phase_timeout / sub_phase_count)
- 서브페이즈 타임아웃 시: 진행 중 플러그인 partial 처리, 다음 서브페이즈 진행
- 시간 기반 탐지는 전용 실행 슬롯(concurrency=1), 비시간 기반은 별도 풀에서 병렬 (2-pool 모델)

## InterPhaseContext Schema

플러그인 간 데이터 전달의 명시적 계약.

```python
@dataclass
class InterPhaseContext:
    waf_info: WafResult | None           # waf_detection → Phase 3
    waf_bypass_payloads: dict | None     # waf_bypass → injection plugins
    tech_stack: list[str]                # tech_fingerprint → ssti, deserialization 등
    ssrf_endpoints: list[str]            # ssrf → cloud_metadata
    dangling_cnames: list[str]           # dangling_dns → subdomain_takeover_poc
    discovered_api_schema: dict | None   # api_discovery → graphql_*, api_* plugins
    crawl_result: CrawlResult | None     # crawler → Phase 3 전체
```

각 플러그인은 메타데이터로 의존성과 테스트 기준을 선언:
```python
class PluginBase:
    requires: list[str] = []          # 예: ["waf_info", "tech_stack"]
    provides: list[str] = []          # 예: ["ssrf_endpoints"]
    detection_criteria: str = ""      # 탐지 판정 조건 (예: "응답에 SQL 에러 패턴 매칭 시 취약")
    expected_evidence: str = ""       # 예상 증거 패턴 (예: "You have an error in your SQL syntax")
    destructive_level: int = 0        # 0: 안전, 1: 데이터 변경 가능, 2: 계정 영향 가능
```

### 플러그인 등록/디스커버리
- `plugins/blackbox/` 및 `plugins/whitebox/` 디렉터리 자동 스캔
- `PluginBase`를 상속한 클래스를 자동 발견 및 등록
- 커뮤니티 플러그인: `~/.vibee-hacker/plugins/` 또는 `--plugin-dir` 옵션으로 외부 디렉터리 지정
- `pip install vibee-hacker-plugin-xxx` 형태의 entry_points 기반 등록도 지원 (`vibee_hacker.plugins` 그룹)

### 테스트 계약
- 각 플러그인은 `tests/fixtures/{plugin_name}/` 에 취약/정상 응답 페어(fixture) 포함 필수
- 최소 1개 탐지 테스트(true positive) + 1개 비탐지 테스트(true negative)
- 참조 테스트 타겟: OWASP Juice Shop, DVWA, WebGoat 기반 통합 테스트
- CI에서 `pytest tests/plugins/` 로 전체 플러그인 회귀 테스트 실행

## Safety & Destructive Action Policy

파괴적 동작을 유발할 수 있는 플러그인 분류 및 안전장치:

### 파괴적 플러그인 분류 (Destructive Plugins)
- **Level 1 (데이터 변경 가능)**: `file_upload.py`, `business_logic.py`, `mass_assignment.py`, `race_condition.py`
- **Level 2 (계정 영향 가능)**: `default_creds.py`, `rate_limit_check.py`, `password_policy_check.py`

### 안전장치
- `--safe-mode` (기본 활성화): Level 1 플러그인 비활성화. 명시적 `--allow-destructive`로 해제
- `--dry-run`: 모든 Phase 3 플러그인이 페이로드를 전송하되 상태 변경 요청(POST/PUT/DELETE)은 건너뜀
- `file_upload.py`: 업로드 성공 시 자동 cleanup 시도 (DELETE 요청). 실패 시 리포트에 수동 삭제 필요 경고
- `rate_limit_check.py`: 계정 잠금 감지(연속 N회 `403 Locked`) 시 즉시 중단. `--test-account` 옵션으로 테스트 전용 계정 지정 권장
- `business_logic.py`: 읽기 전용 검증 우선 (음수 값 입력 시 서버 거부 확인만), 실제 트랜잭션 완료는 `--allow-destructive` 필요

## Scope Enforcement

- 첫 실행 시 `--i-am-authorized` 플래그 또는 `--scope-file targets.txt` 필수
- `subdomain_enum` 결과는 scope 범위 내 IP/도메인만 후속 스캔에 전달
- 스코프 외 요청 시도 시 자동 차단 + 경고 로깅
- `port_scan` 대상도 scope-file 기준으로 필터링
- 미지정 시 `--target` 도메인/IP만 스코프로 자동 설정

## Secret Management

- `auth-config.yaml`: 환경변수 참조 지원 (`${ADMIN_TOKEN}`)
- CLI: `--cookie-file`, `--auth-env VARNAME` 옵션 추가 (shell history 노출 방지)
- 세션 파일 내 인증 정보: AES-256 암호화 또는 OS keychain 위임
- `--redact-secrets` 기본 활성화: 세션/리포트에서 토큰 자동 마스킹

## OOB Callback Security

- 각 콜백 URL에 HMAC-SHA256 서명 토큰 포함 (예: `/callback/{plugin_token}/{hmac}`)
- 서명 불일치 콜백은 무시 + 로깅 (Result Injection 방지)
- `--oob-server auto` 시 Bearer 토큰 인증 강제
- 콜백 수신 데이터에 대한 입력 검증
- `--oob-server auto` 시 ngrok/Cloudflare Tunnel 모두 실패 → OOB 의존 플러그인 skip + warning, 비-Blind 탐지만 실행

## Report Redaction Policy

- 기본 활성화: `response_raw`/`curl_command` 내 Authorization, Cookie, Set-Cookie 헤더 값 마스킹
- `--no-redact`: 펜테스터 전용 모드 (명시적 opt-in)
- PII 패턴(카드번호, 주민번호 등)도 리포트 출력 시 부분 마스킹
- 리포트 파일 접근 권한 자동 설정 (chmod 600)
