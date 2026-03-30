# VIBEE-Hacker: Blackbox Scanner Gap Analysis

3개 전문 영역(OWASP Top 10, API Security, Infrastructure Security)에서 독립적으로 검증한 결과를 통합 정리한 문서.

---

## 검증 요약

| 검증 영역 | 누락 플러그인 수 | Critical | High |
|-----------|-----------------|----------|------|
| OWASP Top 10 대비 | 16개 | 3 | 5 |
| API 보안 (REST/GraphQL) | 27개 | 7 | 10 |
| 인프라/네트워크 | 31개 | 6 | 10 |

중복 제거 후 **추가 필요 플러그인: 총 42개**

---

## 통합 결과: 추가 필요 플러그인 목록

### Phase 1 — 정보 수집 (Recon) 추가 항목

| 플러그인 | 점검 내용 | 심각도 | 출처 |
|----------|-----------|--------|------|
| `subdomain_enum.py` | 서브도메인 열거 (사전 브루트포스, CT 로그 조회) | info | Infra |
| `dns_zone_transfer.py` | DNS Zone Transfer(AXFR) 시도로 전체 DNS 레코드 유출 확인 | high | Infra |
| `waf_detection.py` | WAF/IDS 존재 탐지 및 제품 식별 | info | Infra |
| `api_discovery.py` | Swagger/OpenAPI/GraphQL 엔드포인트 자동 탐색 | info | API |

### Phase 2 — 수동 점검 (Passive) 추가 항목

| 플러그인 | 점검 내용 | 심각도 | 출처 |
|----------|-----------|--------|------|
| `cors_check.py` | CORS 설정 오류 (와일드카드 Origin, Credentials 조합 등) | high | OWASP+API+Infra |
| `csp_analysis.py` | CSP 심층 분석 (unsafe-inline/eval, 과도한 소스 허용) | medium~high | Infra |
| `cookie_security.py` | 쿠키 보안 종합 (SameSite, Path, Domain, 만료, 접두사) | medium | Infra |
| `mixed_content.py` | HTTPS 페이지의 HTTP 리소스 로딩 탐지 | medium~high | OWASP+Infra |
| `sri_check.py` | 외부 CDN 리소스의 SRI(Subresource Integrity) 해시 부재 | medium | OWASP+Infra |
| `sensitive_data_exposure.py` | 응답 내 민감 정보(카드번호, 주민번호, API키 등) 패턴 탐지 | high | OWASP |
| `debug_detection.py` | 디버그 모드 활성화, 디버그 엔드포인트 노출 | high | Infra |
| `server_info_leak.py` | 불필요한 서버 정보 헤더, HTML 주석 내 버전 정보 | low | Infra |
| `unnecessary_services.py` | 프로덕션 환경 불필요 서비스/엔드포인트 (Actuator, phpinfo 등) | medium~critical | Infra |
| `dangling_dns.py` | 서브도메인 테이크오버 가능한 Dangling CNAME 탐지 | high | Infra |
| `email_security.py` | SPF, DKIM, DMARC 레코드 설정 강도 검증 | medium | Infra |
| `cloud_storage_exposure.py` | 공개 접근 가능한 S3/GCS/Azure Blob 버킷 탐지 | critical | Infra |
| `cloud_creds_leak.py` | 응답 내 클라우드 자격 증명/API 키 정규식 탐지 | critical | Infra |
| `api_key_exposure.py` | URL/JS/에러 응답 내 API 키 평문 노출 | critical | API |
| `api_schema_exposure.py` | Swagger/OpenAPI 스펙이 인증 없이 프로덕션에 노출 | medium | API |
| `api_versioning_check.py` | 구버전 API 엔드포인트 활성 여부 | medium | API |
| `graphql_introspection.py` | GraphQL 인트로스펙션 쿼리 활성화 여부 | high | API |
| `excessive_data_exposure.py` | API 응답이 필요 이상의 데이터 반환 (DB 내부 필드 등) | high | API |
| `pii_leakage.py` | API 응답 내 개인정보(PII) 비마스킹 노출 | high | API |
| `verbose_error.py` | 에러 응답 내 스택 트레이스, DB 쿼리, 내부 경로 노출 | medium | API |
| `clickjacking.py` | X-Frame-Options + CSP frame-ancestors 종합 점검 | medium | Infra |
| `security_txt_check.py` | /.well-known/security.txt 존재 및 RFC 9116 준수 | info | Infra |
| `js_lib_audit.py` | 프론트엔드 JS 라이브러리 버전 취약점 (Retire.js DB 매칭) | medium | OWASP |
| `http_methods.py` | 불필요한 HTTP 메서드(TRACE, PUT, DELETE) 허용 여부 | medium | Infra |

### Phase 3 — 능동 점검 (Active) 추가 항목

| 플러그인 | 점검 내용 | 심각도 | 출처 |
|----------|-----------|--------|------|
| `cmdi.py` | OS 명령어 주입 (시간/출력/OOB 기반 탐지) | critical | OWASP+Infra |
| `path_traversal.py` | 경로 순회 / LFI (인코딩 우회 포함) | critical | OWASP+Infra |
| `xxe.py` | XML External Entity 주입 | critical | OWASP+Infra |
| `ssti.py` | Server-Side Template Injection (엔진별 페이로드) | critical | OWASP |
| `http_smuggling.py` | HTTP Request Smuggling (CL.TE, TE.CL 변형) | critical | Infra |
| `idor_check.py` | BOLA/IDOR — 리소스 ID 변조로 타 사용자 데이터 접근 | critical | OWASP+API |
| `bfla.py` | 일반 사용자 권한으로 관리자 API 기능 접근 시도 | critical | API |
| `jwt_check.py` | JWT alg:none, 서명 우회, 만료 미검증, kid 주입 | critical | OWASP+API |
| `cors_check.py`(Active) | Origin 반영 + Credentials 조합 심층 테스트 | high | 통합 |
| `host_header_injection.py` | Host/X-Forwarded-Host 헤더 주입 (비밀번호 재설정 포이즈닝) | high | Infra |
| `cache_poisoning.py` | 비캐시키 헤더를 통한 웹 캐시 포이즈닝 | high | Infra |
| `crlf_injection.py` | CRLF 주입을 통한 HTTP Response Splitting | high | Infra |
| `websocket_check.py` | WebSocket Origin 검증, 인증, 입력 검증, CSWSH | high | Infra |
| `waf_bypass.py` | WAF 규칙 우회 (인코딩/HPP/분할 기법) | high | Infra |
| `mass_assignment.py` | API 요청에 비인가 필드 추가 시 서버 처리 여부 | high | API |
| `oauth_check.py` | OAuth redirect_uri 검증, state 파라미터, PKCE 미지원 | high | API |
| `rate_limit_check.py` | 인증 엔드포인트 Rate Limiting / 계정 잠금 부재 | high | OWASP+API+Infra |
| `graphql_depth_limit.py` | GraphQL 쿼리 깊이 제한 부재 (DoS 가능) | high | API |
| `graphql_batch_attack.py` | GraphQL 배칭으로 Rate Limit 우회 | high | API |
| `graphql_injection.py` | GraphQL 변수/인자를 통한 SQL/NoSQL 주입 | critical | API |
| `user_enum.py` | 로그인/비밀번호 찾기 응답 차이로 사용자 열거 | medium | API |
| `broken_auth_flow.py` | 인증 토큰 없이/빈 토큰으로 API 접근 | critical | API |
| `forced_browsing.py` | 비인증 세션으로 보호 페이지 직접 접근 시도 | high | OWASP |
| `deserialization_check.py` | 역직렬화 취약점 탐지 (Java/PHP/Python 직렬화 객체) | high | OWASP |
| `cloud_metadata.py` | SSRF를 통한 클라우드 메타데이터 엔드포인트 심층 접근 | critical | Infra |

---

## 우선순위 분류

### Tier 1 — 필수 (1차 개발 범위)

기존 설계에서 빠진 critical 수준 취약점. 블랙박스 스캐너로서 이것 없이는 기본 기능 미달.

| 플러그인 | 이유 |
|----------|------|
| `cmdi.py` | SQLi와 동급의 RCE 위험, 현재 완전 부재 |
| `path_traversal.py` | 파일 시스템 접근, 기본 점검 항목 |
| `xxe.py` | XML 기반 RCE/SSRF, OWASP Top 10 포함 |
| `ssti.py` | 템플릿 엔진 RCE, 프레임워크 보편적 사용 |
| `idor_check.py` | OWASP API Top 10 1위, 가장 빈번한 취약점 |
| `jwt_check.py` | 현대 웹/API의 핵심 인증 메커니즘 |
| `cors_check.py` | SPA+API 아키텍처의 가장 흔한 설정 오류 |

### Tier 2 — 중요 (2차 개발 범위)

실질적 위험이 높은 high 수준 취약점.

| 플러그인 | 이유 |
|----------|------|
| `http_smuggling.py` | 프록시/CDN 계층 공격, 탐지 어려움 |
| `host_header_injection.py` | 비밀번호 재설정 포이즈닝 |
| `cache_poisoning.py` | 전체 사용자 대상 공격 |
| `crlf_injection.py` | 헤더 주입 → XSS/캐시 포이즈닝 연계 |
| `graphql_introspection.py` | GraphQL 지원 명시, 기본 점검 부재 |
| `graphql_depth_limit.py` | GraphQL DoS 방지 |
| `rate_limit_check.py` | 브루트포스 방어 확인 |
| `mass_assignment.py` | API 권한 상승 |
| `cloud_storage_exposure.py` | 클라우드 환경 대량 데이터 유출 |
| `cloud_creds_leak.py` | 자격 증명 노출 |
| `websocket_check.py` | 실시간 통신 보안 |
| `sensitive_data_exposure.py` | 민감 정보 유출 |
| `debug_detection.py` | 프로덕션 디버그 모드 |
| `dangling_dns.py` | 서브도메인 테이크오버 |
| `oauth_check.py` | OAuth 구현 결함 |
| `broken_auth_flow.py` | API 인증 우회 |
| `bfla.py` | 기능 수준 권한 우회 |

### Tier 3 — 권장 (3차 개발 범위)

medium~low 수준이나 커버리지 완성도에 기여.

나머지 모든 플러그인 (cookie_security, mixed_content, sri_check, csp_analysis, email_security, subdomain_enum, js_lib_audit, http_methods, api_versioning_check, user_enum, verbose_error, pii_leakage, excessive_data_exposure, 등)

---

## 원본 설계 대비 변경 사항 요약

### 기존 13개 플러그인 → 확장 후 55개 플러그인

```
Phase 1: 3개 → 7개  (+4: subdomain_enum, dns_zone_transfer, waf_detection, api_discovery)
Phase 2: 4개 → 28개 (+24: 수동 점검 대폭 확장)
Phase 3: 6개 → 31개 (+25: 능동 점검 대폭 확장)
```

### 새로 추가된 점검 카테고리

1. **인젝션 확장**: Command Injection, SSTI, XXE, CRLF, Header Injection
2. **접근 제어**: IDOR/BOLA, BFLA, Forced Browsing, Path Traversal
3. **API 전용**: GraphQL 전체, JWT, OAuth, Mass Assignment, BOLA
4. **인프라/프로토콜**: HTTP Smuggling, Cache Poisoning, WebSocket, DNS 보안
5. **클라우드**: 스토리지 노출, 자격 증명 유출, 메타데이터 접근
6. **데이터 보호**: PII 유출, 과도한 데이터 노출, 민감 정보 탐지
