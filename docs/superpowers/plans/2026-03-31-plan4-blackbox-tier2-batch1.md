# VIBEE-Hacker Blackbox Tier 2 Batch 1

**Goal:** 영향도 높은 Tier 2 블랙박스 플러그인 8개 구현.

**Project Root:** `C:/Users/qwaqw/desktop/hacker`

## 구현할 플러그인

### Phase 1 (Recon)
1. `waf_detection.py` — WAF 탐지 + 제품 식별. Phase 3에 결과 전달.
2. `robots_sitemap_parser.py` — robots.txt/sitemap.xml 파싱, 민감 경로 수집.

### Phase 2 (Passive)
3. `debug_detection.py` — 디버그 모드/디버그 엔드포인트 탐지.
4. `sensitive_data_exposure.py` — 응답 내 카드번호/주민번호/API키 정규식 탐지.
5. `cloud_creds_leak.py` — AWS/GCP/GitHub 토큰 정규식 탐지.

### Phase 3 (Active)
6. `open_redirect.py` — 리다이렉트 파라미터에 외부 URL 주입 (기존 스펙).
7. `crlf_injection.py` — HTTP Response Splitting 탐지.
8. `broken_auth_flow.py` — 인증 토큰 제거/변조 시 데이터 접근 가능 여부.
