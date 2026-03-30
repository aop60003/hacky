# VIBEE-Hacker: Whitebox Scanner Design Spec

## Overview

소스코드를 직접 분석하여 보안 취약점을 탐지하는 화이트박스(정적 분석) 스캐너 설계 문서.
패턴 매칭 + 데이터 흐름 분석(Taint Analysis) + 의존성 감사 + IaC 보안을 포함.

지원 언어:
- **Tier 1 (taint analysis 포함)**: Python, JavaScript/TypeScript
- **Tier 2 (패턴 매칭)**: PHP, Java, Go
- **Tier 3 (향후 확장)**: Ruby, C#/.NET, Kotlin, Scala, Rust

총 플러그인: **55개**, 5단계(Phase) 구성.

---

## Scan Phases

### Phase 1: 프로젝트 인식 (Discovery) — 4개 플러그인

목적: 분석 대상 프로젝트의 구조와 기술 스택 파악

| # | 플러그인 | 점검 내용 | 출력 |
|---|----------|-----------|------|
| 1 | `lang_detector.py` | 파일 확장자 + 내용 기반 언어/프레임워크 감지 | 언어별 파일 목록, 프레임워크 식별 |
| 2 | `project_mapper.py` | 엔트리포인트, 라우트 정의, 설정 파일 위치 파악. import/require 그래프 구축 (cross-file taint 추적용). **Monorepo 지원**: `package.json` workspaces, `pnpm-workspace.yaml`, `lerna.json`, `nx.json` 감지, workspace 패키지 간 심볼릭 링크 해석. 패키지 경계를 넘는 taint는 confidence 0.1 감소 | 프로젝트 구조 맵 + 모듈 의존성 그래프 |
| 3 | `dep_collector.py` | manifest: `requirements.txt`, `package.json`, `pom.xml`, `composer.json`, `go.mod`, `Gemfile`, `*.csproj`. **lock 파일 우선**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Pipfile.lock`, `poetry.lock`, `Gemfile.lock`, `go.sum`. lock 파일이 존재하면 manifest보다 우선하여 정확한 버전 매칭 | 의존성 목록 + 정확한 버전 |
| 4 | `env_file_detector.py` | `.env` 파일 탐지: `git ls-files`로 실제 추적 중인 파일 확인 (`.gitignore`에 등록되어 있어도 `git add -f`로 추가된 경우 탐지). 비-git 프로젝트는 파일 시스템 직접 스캔. 추적 중인 .env 파일 내용 분석하여 시크릿 추출 | 커밋된 env 파일 목록 + 시크릿 |

Phase 1 결과는 후속 Phase에서 어떤 언어별 플러그인을 활성화할지 결정한다.
`project_mapper.py`의 모듈 의존성 그래프는 Phase 3 cross-file taint 추적에 필수.

---

### Phase 2: 패턴 매칭 (Pattern Matching) — 30개 플러그인

목적: 정규식 및 AST 기반으로 알려진 위험 패턴을 빠르게 탐지

#### 언어 공통 (7개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 5 | `hardcoded_secrets.py` | API 키, 비밀번호, 토큰, private key 하드코딩 (정규식 + **Shannon entropy 분석**: 20자 이상, entropy 4.5+ 고엔트로피 문자열 탐지). `.env` 파일 내용도 분석. 커스텀 API 키, base64 인코딩된 시크릿도 포착 | critical |
| 6 | `dangerous_defaults.py` | `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `SECRET_KEY` 기본값, CORS `allow_all` | high |
| 7 | `insecure_crypto.py` | MD5/SHA1 비밀번호 해싱, ECB 모드, 하드코딩된 IV/salt, 약한 난수 생성기(`random` vs `secrets`/`crypto`) | high |
| 8 | `insecure_xml.py` | 모든 언어의 XML 파서에서 외부 엔티티 비활성화 미설정: Python `lxml.etree`, `xml.etree`, Java `DocumentBuilderFactory`/`SAXParserFactory`/`XMLInputFactory`, PHP `simplexml_load_string()` | critical |
| 9 | `insecure_jwt.py` | JWT 검증 미흡: `algorithm='none'` 허용, 서명 미검증(`verify=False`), 만료 미확인, 비대칭키 혼동, 하드코딩된 시크릿 | critical |
| 10 | `log_injection.py` | 사용자 입력이 로그에 직접 기록: `logger.info(f"User: {user_input}")`, `console.log(req.body)` 등 CRLF 인젝션 가능 패턴 | medium |
| 11 | `todo_fixme_security.py` | `TODO: fix security`, `FIXME: vulnerable`, `HACK:` 등 보안 관련 임시 코드 표시 | info |

#### Python 전용 (7개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 12 | `py_dangerous_funcs.py` | `eval()`, `exec()`, `pickle.loads()`, `shelve.open()`, `marshal.loads()`, `dill.loads()`, `yaml.load()` (unsafe), `subprocess.shell=True`, `os.system()`, `__import__()` | critical |
| 13 | `py_sql_pattern.py` | f-string/format/% 사용 SQL 쿼리 조합 (ORM 미사용 raw query) | critical |
| 14 | `py_template_pattern.py` | Jinja2 `|safe` 필터, `autoescape=False`, `Markup()` 직접 사용, `Environment.from_string()`, Mako 템플릿 동적 렌더링, Tornado 템플릿 | high |
| 15 | `py_django_check.py` | Django: `DEBUG`, `SECRET_KEY`, CSRF 미들웨어 비활성화, `@csrf_exempt` 남용, `safe` 템플릿 필터, `HttpResponseRedirect(user_input)`, mass assignment (`exclude`/`fields` 미설정 ModelForm) | high |
| 16 | `py_flask_check.py` | Flask: `debug=True`, 하드코딩된 `secret_key`, `render_template_string()`, 세션 쿠키 설정, `redirect(user_input)` | high |
| 17 | `py_fastapi_check.py` | FastAPI: `response_model` 미설정(과도한 데이터 노출), `Depends()` 체인 내 인증 누락, CORS 와일드카드, `Body(embed=False)` 미검증 | high |
| 18 | `py_ssrf_pattern.py` | `requests.get(user_input)`, `urllib.request.urlopen()`, `httpx.get()`, `aiohttp.ClientSession.get()` 에 사용자 입력 직접 전달 | critical |

#### JavaScript/TypeScript 전용 (7개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 19 | `js_dangerous_funcs.py` | `eval()`, `Function()`, `innerHTML`, `outerHTML`, `document.write()`, `setTimeout(string)`, `new Function(string)` | critical |
| 20 | `js_sql_pattern.py` | 템플릿 리터럴/문자열 연결로 SQL 쿼리 조합 | critical |
| 21 | `js_xss_pattern.py` | `dangerouslySetInnerHTML` (React), `v-html` (Vue), `[innerHTML]` (Angular), `bypassSecurityTrust*`, `pug`/`ejs`/`handlebars` 동적 템플릿 컴파일 | high |
| 22 | `js_node_check.py` | `child_process.exec()` 사용자 입력, `fs.readFile()` 경로 미검증, CORS `origin: '*'`, `helmet` 미사용, prototype pollution (`Object.assign({}, userInput)`, `lodash.merge()`, `_.defaultsDeep()`) | high |
| 23 | `js_express_check.py` | Express: `trust proxy` 미설정, 세션 쿠키 `secure: false`, `bodyParser` 크기 제한 없음, 에러 핸들러 미등록, `res.redirect(user_input)` | medium |
| 24 | `js_nestjs_check.py` | NestJS: Guard 미적용 컨트롤러, DTO ValidationPipe 미적용, `@Public()` 데코레이터 남용, CORS 설정 미흡 | high |
| 25 | `js_redos.py` | 사용자 입력에 적용되는 취약한 정규식 탐지 (catastrophic backtracking 유발 패턴). `new RegExp(userInput)` 동적 생성도 탐지 | high |

#### PHP 전용 (3개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 26 | `php_dangerous_funcs.py` | `eval()`, `exec()`, `system()`, `passthru()`, `shell_exec()`, `preg_replace('/e')`, `unserialize()` (`__wakeup()`/`__destruct()` 매직 메서드 체인 분석 포함), `include($var)`, `file_get_contents($url)`, `curl_exec()`, `header("Location: $url")` | critical |
| 27 | `php_sql_pattern.py` | 문자열 연결/변수 삽입 SQL 쿼리, prepared statement 미사용 | critical |
| 28 | `php_config_check.py` | `display_errors = On`, `allow_url_include = On`, `register_globals`, `simplexml_load_string()` 외부 엔티티 미비활성화 | high |

#### Java 전용 (4개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 29 | `java_dangerous_funcs.py` | `Runtime.exec()`, `ProcessBuilder`, `ObjectInputStream.readObject()`, `XStream`, `SnakeYAML`, `Jackson` (polymorphic typing `@JsonTypeInfo` + `DefaultTyping`), `Kryo`, `ScriptEngine.eval()`, `URL.openConnection()`, `HttpClient.send()`, `RestTemplate.getForObject()` | critical |
| 30 | `java_sql_pattern.py` | `Statement.execute()` + 문자열 연결, `PreparedStatement` 미사용 | critical |
| 31 | `java_spring_check.py` | Spring Boot 3 / Spring Security 6: `SecurityFilterChain` 빈 기반 설정, Lambda DSL (`http.csrf(csrf -> csrf.disable())`), `@CrossOrigin("*")`, actuator 노출, `redirect:` prefix에 사용자 입력 | high |
| 32 | `java_xxe_check.py` | `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`에서 `FEATURE_SECURE_PROCESSING` 미설정, `setExpandEntityReferences(false)` 미호출 | critical |

#### Go 전용 (2개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 33 | `go_dangerous_funcs.py` | `os/exec.Command()` 사용자 입력, `text/template` vs `html/template` 혼용, `http.ListenAndServe()` TLS 미사용, `sql.Query()` 문자열 연결, `json.Unmarshal` → 미검증 구조체 | critical |
| 34 | `go_config_check.py` | CORS 설정, `net/http` 타임아웃 미설정, `crypto/rand` 대신 `math/rand` 사용 | high |

#### 언어 공통 추가 (2개)

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 35 | `nosql_injection.py` | MongoDB operator injection (`{"$gt":""}`, `$ne`, `$regex`, `$where` 절), Mongoose `find()/findOne()` + 사용자 입력 직접 전달, DynamoDB 조건식 인젝션 | critical |
| 36 | `race_condition.py` | TOCTOU 패턴: `os.path.exists()` → `open()`, `fs.existsSync()` → `fs.writeFileSync()`, 임시 파일 안전하지 않은 생성(`mktemp` 미사용, `tempfile.NamedTemporaryFile(delete=False)` 후 미정리) | medium |

---

### Phase 3: 데이터 흐름 분석 (Taint Analysis) — 5개 플러그인

목적: 사용자 입력(Source)이 위험 함수(Sink)까지 도달하는 경로를 추적. Sanitizer가 경로에 없으면 취약점으로 보고.

```
Source (사용자 입력)  ──→  전파 경로  ──→  Sink (위험 함수)
                              ↑
                         Sanitizer (정화 함수) 가 경로에 있으면 안전
```

#### `py_taint_analyzer.py` (#37) — Python Taint Analysis

**Sources:**
- Flask: `request.args`, `request.form`, `request.json`, `request.data`, `request.files`, `request.cookies`, `request.headers`
- Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.META`, `request.COOKIES`
- FastAPI: `Request`, `Query()`, `Path()`, `Body()`, `Form()`, `Header()`, `Cookie()`, `Depends()` 반환값
- 공통: `sys.argv`, `input()`, `os.environ`, `open().read()`, `json.load()`

**Sinks:**
- SQL: `cursor.execute()`, `engine.execute()`, raw query
- 명령어: `os.system()`, `subprocess.run()`, `subprocess.Popen()`, `subprocess.call()`, `subprocess.check_output()`, `subprocess.check_call()`
- 코드 실행: `eval()`, `exec()`, `pickle.loads()`, `yaml.unsafe_load()`
- 파일: `open(path, 'w')`, `shutil.copy()` → 경로 순회
- 출력: `render_template_string()`, `Markup()` → XSS
- 역직렬화: `pickle.loads()`, `shelve.open()`, `marshal.loads()`, `dill.loads()`
- SSRF: `requests.get()`, `urllib.request.urlopen()`, `httpx.get()`, `aiohttp.ClientSession.get()`
- 리다이렉트: `redirect()`, `HttpResponseRedirect()`
- 로그: `logger.info()`, `logger.error()`, `print()` (CRLF 인젝션)
- LDAP: `ldap.search_s()`, `ldap3` 모듈 쿼리
- 이메일: `smtplib.SMTP.sendmail()` 헤더 인젝션
- NoSQL: `pymongo.collection.find({"$where": input})`, `motor` 쿼리

**Sanitizers:**
- XSS: `bleach.clean()`, `markupsafe.escape()`, `html.escape()`
- SQL: ORM 파라미터 바인딩 (SQLAlchemy `text(:param)`, Django ORM queryset)
- 명령어: `shlex.quote()`, `shlex.split()`
- 경로: `os.path.realpath()` + `os.path.commonpath()` 검증 (주의: `startswith()` 단독은 불충분)
- SSRF: URL allowlist 검증 함수 (사용자 정의)
- 타입 변환 (숫자/식별자 컨텍스트): `int()`, `float()`, `uuid.UUID()` — SQL 인젝션에서 숫자 변환 후 사용은 안전

**심각도:** Source → Sink 유형에 따라 자동 결정

#### `js_taint_analyzer.py` (#38) — JavaScript/TypeScript Taint Analysis

**Sources:**
- Express: `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`, `req.files` (multer), `req.ip`, `req.hostname`
- NestJS: `@Body()`, `@Query()`, `@Param()`, `@Headers()` 데코레이터 파라미터
- Next.js 13+: `cookies()`, `headers()`, Server Actions `FormData`, Route Handlers `NextRequest`, `useSearchParams()`, `searchParams`, dynamic route `params`, `generateMetadata` 인자
- 브라우저: `location.search`, `location.hash`, `document.cookie`, `window.name`
- 공통: `process.argv`, `process.env`, `fs.readFileSync()`
- WebSocket: `ws.on('message')` 핸들러 데이터
- gRPC: service handler 파라미터

**Sinks:**
- DOM: `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `Function()`
- SQL: 템플릿 리터럴 쿼리, `db.query(string)`, `knex.raw()`
- 명령어: `child_process.exec()`, `child_process.spawn()`, `child_process.execSync()`
- 파일: `fs.readFile(path)`, `fs.writeFile(path)`, `fs.unlink(path)`
- 리다이렉트: `res.redirect(url)`, `window.location = url`
- SSRF: `fetch(url)`, `axios(url)`, `http.request(url)`, `got(url)`
- Prototype: `Object.assign({}, input)`, `lodash.merge()`, `_.defaultsDeep()`
- 로그: `console.log()`, `winston.info()`, `pino.info()`
- 코드 실행: `vm.runInContext()`, `vm.runInNewContext()`, `vm.runInThisContext()`
- NoSQL: MongoDB `$where`, `$regex` operator, Mongoose `find()`/`findOne()` + 사용자 입력
- 메시지: `postMessage()` (cross-origin, 수신 측 origin 미검증 포함)

**Sanitizers:**
- XSS: `DOMPurify.sanitize()`, `escape()`, `encodeURIComponent()`, `he.encode()`
- SQL: 파라미터 바인딩 (`db.query('SELECT ?', [param])`, `knex.where({})`)
- 명령어: `child_process.execFile()` (shell 미경유)
- 경로: `path.resolve()` + `path.relative()` 검증
- 타입 변환: `parseInt()`, `Number()`, `parseFloat()` — 숫자 컨텍스트 SQL 인젝션 방지

**심각도:** Source → Sink 유형에 따라 자동 결정

#### `php_taint_analyzer.py` (#39) — PHP Taint Analysis (Tier 2 확장)

Phase 2 패턴 매칭으로 시작, 향후 full taint analysis 추가 예정.
초기 지원: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` → 주요 sink 추적.

#### `java_taint_analyzer.py` (#40) — Java Taint Analysis (Tier 2 확장)

Phase 2 패턴 매칭으로 시작, 향후 full taint analysis 추가 예정.
초기 지원: `HttpServletRequest.getParameter()`, `@RequestParam`, `@PathVariable` → 주요 sink 추적.

#### `go_taint_analyzer.py` (#41) — Go Taint Analysis (Tier 2 확장)

Phase 2 패턴 매칭으로 시작, 기본적인 단일 파일 taint 추적 포함.
초기 Sources: `r.URL.Query()`, `r.FormValue()`, `r.Body`, `r.Header.Get()`, `mux.Vars(r)`, `gin.Context.Query()/Param()/PostForm()`.
초기 Sinks: `db.Query()`, `db.Exec()`, `exec.Command()`, `template.HTML()`, `http.Redirect()`, `fmt.Fprintf(w, userInput)`.

### Taint Analysis 구현 방식

```
1. 언어별 AST 파싱
   - Python: ast 모듈 (단일 파일) + project_mapper의 모듈 의존성 그래프 (cross-file)
   - JavaScript/TypeScript: tree-sitter-javascript / tree-sitter-typescript
   - PHP: tree-sitter-php (향후)
   - Java: tree-sitter-java (향후)

2. Cross-file / Inter-procedural 분석
   - Phase 1의 모듈 의존성 그래프를 활용하여 import/require 체인 추적
   - export된 함수의 파라미터를 잠재적 source로 간주 (modular analysis)
   - 클래스 상속 관계에서의 메서드 오버라이드 추적
   - 콜백/프로미스/async-await 체인: 콜백 인자를 tainted 전파
   - max_call_depth로 분석 깊이 제한 (무한 루프 방지)

3. AST에서 Source 노드 식별
   - 함수 호출, 속성 접근, 데코레이터 패턴 매칭

4. 데이터 전파 추적 (Taint Propagation Rules)
   - 변수 할당: x = source → x도 tainted
   - 함수 인자: func(tainted) → 반환값도 tainted (기본)
   - 문자열 연결: "prefix" + tainted → 결과도 tainted
   - 컨테이너: list.append(tainted) → list도 tainted
   - 딕셔너리/객체 속성: obj.attr = tainted → obj도 tainted, tainted_dict['key'] → tainted
   - 슬라이싱: tainted[0:5] → tainted
   - 언패킹: a, b = tainted_tuple → a, b 모두 tainted
   - Spread: {...tainted} → 결과 tainted
   - 조건부: x = tainted if cond else safe → x는 tainted (보수적)

5. Sink 도달 확인
   - tainted 변수가 Sink 함수의 인자로 사용되는지 확인

6. Sanitizer 유효성 검증
   - Source → Sink 경로 상에 Sanitizer 함수 호출이 있으면 안전 판정
   - Sanitizer는 해당 취약점 유형에 맞아야 함 (XSS sanitizer는 SQL sink에 무효)
   - **sanitizer 반환값 추적**: sanitizer(input)의 결과가 실제 후속 경로에서 사용되는지 확인
   - **재오염(re-tainting) 탐지**: sanitizer 후 다시 tainted 데이터와 결합하면 tainted
   - sanitizer 호출했지만 반환값을 사용하지 않는 경우 → 여전히 취약

7. 결과 보고
   - Source → Sink 전체 taint chain 포함
   - 각 단계의 파일명:라인번호 포함

8. Implicit Flow 정책
   - 현재 버전: explicit data flow만 추적 (implicit flow 의도적 배제)
   - 사유: implicit flow 추적 시 false positive 급증, 성능 저하
   - 향후: 선택적 implicit flow 모드 제공 (`--implicit-taint` 플래그)

9. Output Context 기반 Sanitizer 매핑
   | Sink Context | 유효 Sanitizer |
   |---|---|
   | HTML body | `html.escape()`, `bleach.clean()`, `DOMPurify` |
   | HTML attribute (quoted) | `html.escape()` + 따옴표 보장 |
   | HTML attribute (unquoted) | 화이트리스트 검증만 유효 |
   | JavaScript inline | `JSON.stringify()` + escape |
   | URL parameter | `encodeURIComponent()`, `urllib.parse.quote()` |
   | CSS value | 화이트리스트 검증만 유효 |
   | SQL | parameterized query만 유효 |
   - 컨텍스트 불일치 시 sanitizer 무효 처리 + warning 발행
```

### 분석 범위 제한

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `max_call_depth` | 5 | 함수 호출 추적 최대 깊이 |
| `max_file_size` | 1MB | 분석 대상 파일 최대 크기 |
| `exclude_patterns` | `node_modules/`, `venv/`, `.git/`, `dist/`, `build/`, `vendor/`, `.tox/`, `target/`, `.gradle/`, `__pycache__/`, `.next/`, `.nuxt/` | 분석 제외 경로 |
| `timeout_per_file` | 30s | 파일당 분석 타임아웃 |
| `timeout_total` | 600s | 전체 Phase 3 분석 총 시간 제한 |
| `timeout_per_chain` | 60s | 단일 taint chain 추적 시간 제한 |

---

### Phase 4: 의존성 분석 (Dependency Audit) — 5개 플러그인

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 42 | `dep_vuln_check.py` | 의존성 파일에서 패키지 버전 추출, NVD/OSV/GitHub Advisory DB 매칭. lock 파일 우선 사용 | varies (CVE별) |
| 43 | `dep_outdated.py` | 최신 버전 대비 오래된 패키지 식별, 보안 패치 포함 업데이트 우선 표시 | low~high |
| 44 | `dep_license_check.py` | 라이선스 호환성 확인 (GPL 혼용 등) | info |
| 45 | `dep_typosquat.py` | 알려진 타이포스쿼팅 패키지명 탐지 (`requests` vs `requets`, `lodash` vs `1odash` 등) | critical |
| 46 | `dep_supply_chain.py` | 최근 소유자 변경, 비정상적 다운로드 급증, 설치 스크립트(`postinstall`) 내 의심스러운 코드 패턴 탐지. **데이터 소스**: npm registry API, PyPI JSON API. 로컬 SQLite 캐시(24h TTL). `--offline` 시 캐시만 사용, 미존재 시 skip+warning | high |

---

### Phase 5: IaC / CI 보안 (Infrastructure as Code) — 7개 플러그인

| # | 플러그인 | 점검 내용 | 심각도 |
|---|----------|-----------|--------|
| 47 | `dockerfile_check.py` | `USER root`, `COPY . .`(시크릿 포함 위험), `latest` 태그, `--privileged`, 불필요한 포트 노출 | high |
| 48 | `k8s_manifest_check.py` | `privileged: true`, `hostNetwork`, `runAsRoot`, `securityContext` 미설정, `imagePullPolicy: Always` 미사용 | high |
| 49 | `terraform_check.py` | 공개 S3 버킷, 보안 그룹 `0.0.0.0/0` 인바운드, 암호화 미설정, IAM 과도 권한 | critical |
| 50 | `github_actions_check.py` | 타사 action 미고정 버전(`@main` 대신 `@sha256` 필요), 시크릿 노출, `pull_request_target` 위험, 스크립트 인젝션(`${{ github.event.issue.title }}`) | high |
| 51 | `gitlab_ci_check.py` | 시크릿 노출, 안전하지 않은 runner 설정, 보호되지 않은 변수 | high |
| 52 | `compose_check.py` | `docker-compose.yml`: 시크릿 평문, 불필요한 포트 매핑, `privileged` 모드, 볼륨 마운트 위험 | medium |
| 53 | `graphql_schema_check.py` | GraphQL 스키마 분석: introspection 활성화, depth/complexity 제한 미설정, `@auth` 디렉티브 누락, 과도한 필드 노출 | high |

---

## Result Model (화이트박스)

```python
@dataclass
class WhiteboxResult(Result):
    file_path: str                    # 취약 코드가 있는 파일
    line_number: int                  # 라인 번호
    column_start: int | None         # SARIF startColumn
    column_end: int | None           # SARIF endColumn
    end_line_number: int | None      # SARIF endLine (multi-line 취약점)
    code_snippet: str                 # 해당 코드 조각 (전후 3줄)
    taint_chain: list[str] | None    # Source → Sink 경로 (taint analysis인 경우)
    confidence: float                 # 0.0~1.0 신뢰도 점수
    cwe_id: str | None               # "CWE-89" 등
    remediation: str                  # 수정 방법 안내
    references: list[str]            # 참조 URL (OWASP, CWE 등)
    suppressible: bool               # nosec 등으로 억제 가능 여부
    rule_id: str                     # 플러그인 규칙 ID (예: "py_sql_pattern", "hardcoded_secrets") — SARIF ruleId 매핑
    # taint_chain 예:
    # [
    #   "app.py:12 — user_id = request.args.get('id')",
    #   "app.py:15 — query = f'SELECT * FROM users WHERE id = {user_id}'",
    #   "app.py:16 — cursor.execute(query)"
    # ]
```

## False Positive Suppression

- 인라인 주석: `# nosec`, `// nosec`, `/* nosec */`, `@SuppressWarnings("security")`
- 규칙별 억제: `# nosec:CWE-89` (특정 CWE만 억제)
- 설정 파일: `.whitebox-ignore.yml` — 파일/경로/규칙별 억제
- `--min-confidence 0.7`: 신뢰도 임계값 이하 결과 필터링

### Suppression 보안 정책
- 와일드카드 전체 억제 금지: `rule: "*"` 또는 `path: "**"` 단독 사용 차단
- 최대 억제 비율: 전체 탐지 대비 80% 초과 시 warning 발행
- `--audit-suppressions`: 이전 스캔 대비 suppression 변경 표시
- CI 모드: suppression 파일 변경 시 자동 리뷰 요청 권고 출력

```yaml
# .whitebox-ignore.yml 예시
suppressions:
  - rule: hardcoded_secrets
    path: tests/**           # 테스트 코드의 시크릿 허용
  - rule: py_sql_pattern
    file: migrations/*.py     # 마이그레이션 파일 제외
  - cwe: CWE-79
    line: "src/legacy.py:42"  # 특정 라인 억제
```

## CLI Interface

```bash
# 기본 화이트박스 스캔 (전체 Phase)
vibee-hacker scan --target ./my-project --mode whitebox

# Phase 지정
vibee-hacker scan --target ./my-project --phase discovery
vibee-hacker scan --target ./my-project --phase pattern
vibee-hacker scan --target ./my-project --phase taint
vibee-hacker scan --target ./my-project --phase dependency
vibee-hacker scan --target ./my-project --phase iac

# 특정 언어만
vibee-hacker scan --target ./my-project --mode whitebox --lang python
vibee-hacker scan --target ./my-project --mode whitebox --lang javascript

# 특정 플러그인만
vibee-hacker scan --target ./my-project --plugin hardcoded_secrets,py_sql_pattern

# 증분 스캔 (변경 파일만)
vibee-hacker scan --target ./my-project --mode whitebox --incremental
vibee-hacker scan --target ./my-project --mode whitebox --diff-base main

# 분석 깊이 조정
vibee-hacker scan --target ./my-project --mode whitebox --call-depth 10

# 신뢰도 필터링
vibee-hacker scan --target ./my-project --mode whitebox --min-confidence 0.7

# 리포트 출력
vibee-hacker scan --target ./my-project --mode whitebox --output report.json --format json
vibee-hacker scan --target ./my-project --mode whitebox --output report.sarif --format sarif

# CI/CD 통합
vibee-hacker scan --target ./my-project --mode whitebox --fail-on critical,high --quiet
```

## Phase Dependencies

```
Phase 1 (Discovery) ──→ Phase 2 (Pattern) ──→ Phase 3 (Taint)
                    └──→ Phase 4 (Dependency)
                    └──→ Phase 5 (IaC/CI)
```

- Phase 1 완료 후 Phase 2, 4, 5 병렬 실행 가능
- Phase 3는 Phase 2 완료 후 시작. Phase 2 결과 활용 정책:
  - Phase 2 결과 중 confidence < 0.5인 sink/source는 Phase 3에서 제외
  - Phase 3 자체적으로 AST 기반 sink/source 재검증 후 사용
  - Phase 2 결과는 "힌트"로만 활용, Phase 3의 최종 판정을 우선
- Phase 3는 Phase 1의 모듈 의존성 그래프 필수

## Incremental Scan

- `--incremental`: `git diff HEAD~1`로 변경 파일 추출
- `--diff-base <branch>`: 지정 브랜치 대비 변경 파일 추출
- 변경 파일 + 해당 파일을 import하는 파일(영향 범위)도 함께 분석
- Phase 4(의존성)은 항상 전체 실행 (lock 파일 변경은 전체 영향)

## Performance & Parallelism

- 파일 단위 병렬 처리: `--workers N` (기본: CPU 코어 수)
- AST 파싱 결과 캐시: `.vibee-cache/` 디렉토리에 파일 해시 기반 캐시
- Phase 2는 파일 단위 완전 병렬 (파일 간 의존성 없음)
- Phase 3은 모듈 의존성 그래프의 리프 노드부터 상향식(bottom-up) 분석. 순환 참조 시 SCC(Strongly Connected Components) 기반 처리: SCC 내 모듈은 하나의 분석 단위로 통합
- 메모리 제한: `--max-memory 4G` (기본: 시스템 RAM의 50%)

## Development Tiers

| Tier | 내용 |
|------|------|
| Tier 1 | Phase 1 + Phase 2 공통/Python/JS + Phase 3 Python/JS Taint + Phase 4 (24개) |
| Tier 2 | Phase 2 PHP/Java/Go + Phase 5 IaC + Phase 4 공급망 (16개) |
| Tier 3 | Ruby/C#/.NET/Kotlin/Scala/Rust 확장, PHP/Java full taint (12개) |

## Plugin Extensibility

- 커스텀 플러그인: `~/.vibee-hacker/plugins/whitebox/` 또는 `--plugin-dir` 옵션으로 외부 디렉터리 지정
- `pip install vibee-hacker-wb-plugin-xxx` 형태의 entry_points 기반 등록 (`vibee_hacker.whitebox_plugins` 그룹)
- 커스텀 룰 정의: `.vibee-rules.yml`에 패턴 매칭 규칙 추가 가능 (정규식 + 파일 패턴 + 심각도)
- 각 플러그인은 `tests/fixtures/{plugin_name}/` 에 취약/정상 코드 페어 포함 필수
