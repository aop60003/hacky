# VIBEE-Hacker Blackbox Tier 2 Batch 2

**Goal:** Tier 2 플러그인 8개 추가 구현 (총 28개 달성).

**Project Root:** `C:/Users/qwaqw/desktop/hacker`

## 구현할 플러그인

### Phase 1
1. `api_discovery.py` — Swagger/OpenAPI/GraphQL 엔드포인트 자동 탐색

### Phase 2
2. `unnecessary_services.py` — 프로덕션 불필요 서비스/엔드포인트 탐지
3. `graphql_introspection.py` — GraphQL 인트로스펙션 쿼리 활성화 여부

### Phase 3
4. `host_header_injection.py` — Host/X-Forwarded-Host 헤더 주입
5. `verbose_error.py` — 에러 응답 내 스택 트레이스/내부 경로 노출
6. `mass_assignment.py` — PUT/POST body에 비인가 필드 추가
7. `prototype_pollution.py` — __proto__/constructor.prototype 주입
8. `rate_limit_check.py` — 인증 엔드포인트 Rate Limiting 부재 확인
