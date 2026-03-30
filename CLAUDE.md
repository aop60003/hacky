# VIBEE-Hacker — Claude Code Harness Design

## Project Overview

Python 기반 보안 취약점 점검 도구. 플러그인 아키텍처로 화이트박스(소스코드 분석)와 블랙박스(외부 스캐닝)를 모두 지원.
CLI + 웹 대시보드 인터페이스, HTML/JSON 리포트 생성.

## Harness Architecture: 3-Agent Pattern

이 프로젝트는 Anthropic의 하네스 디자인 원칙을 따른다.

### 1. Planner (계획자)

- 사용자 요청을 받아 **완전한 기능 사양**으로 확장
- 고수준 설계에 집중, 세밀한 구현 디테일은 Generator에게 위임
- 각 기능을 독립적인 **스프린트 단위**로 분할
- 스프린트 시작 전 **성공 기준(스프린트 계약)**을 먼저 정의

### 2. Generator (생성자)

- 한 번에 하나의 스프린트(기능)만 구현
- 스프린트 완료 후 반드시 Evaluator에게 핸드오프
- 자기 자신의 코드를 평가하지 않는다 (자체 평가의 한계)

### 3. Evaluator (평가자)

- Generator의 결과물을 **독립적으로** 검증
- 스프린트 계약 기준으로 pass/fail 판정
- 검증 방법: 테스트 실행, 실제 스캔 동작 확인, 코드 리뷰
- 실패 시 구체적인 피드백과 함께 Generator에게 반환

## Sprint Workflow

```
1. Planner: 스프린트 범위 정의 + 성공 기준 작성
2. Generator: 코드 구현 (하나의 기능/플러그인)
3. Evaluator: 성공 기준 기반 검증
   - Pass → 다음 스프린트로
   - Fail → 피드백과 함께 Generator로 반환
4. 반복
```

## Context Management

### 컨텍스트 리셋 전략

- 컨텍스트가 길어지면 **압축이 아닌 리셋**을 선호
- 리셋 시 반드시 **구조화된 핸드오프 아티팩트** 작성:
  - 현재까지 완료된 것
  - 다음에 해야 할 것
  - 알려진 이슈/결정사항
- 핸드오프 아티팩트는 `docs/handoff/` 에 저장

### 컨텍스트 불안감 방지

- 작업을 조기에 완료하려는 충동에 저항
- 스프린트 계약의 모든 기준이 충족될 때까지 완료로 표시하지 않음

## Evaluator Rubric (평가 기준)

### 코드 품질

- 플러그인 인터페이스(PluginBase)를 올바르게 구현하는가
- 에러 처리가 적절한가 (타임아웃, 네트워크 실패 등)
- 타입 힌트가 일관적인가

### 기능성

- 플러그인이 실제로 취약점을 탐지하는가 (테스트 케이스 통과)
- CLI에서 정상 동작하는가
- 리포트가 올바르게 생성되는가

### 보안

- 도구 자체에 보안 취약점이 없는가
- 사용자 입력이 적절히 검증되는가
- 스캔 대상 외의 시스템에 영향을 주지 않는가

## Development Rules

### 스프린트 계약 우선

코드를 작성하기 **전에** 항상 스프린트 계약을 정의한다:
- 이 스프린트에서 구현할 것
- 성공으로 간주되는 조건 (구체적, 검증 가능)
- 범위 밖인 것

### 플러그인 개발 규칙

- 모든 플러그인은 `PluginBase`를 상속
- 플러그인 하나 = 파일 하나
- `is_applicable()`로 적용 가능 여부 판단
- `run()`은 `list[Result]`를 반환
- 플러그인 간 의존성 금지 (독립 실행 보장)

### 테스트

- 각 플러그인에 대해 최소 1개의 탐지 테스트 + 1개의 비탐지 테스트
- 블랙박스 플러그인은 mock 서버로 테스트
- 화이트박스 플러그인은 취약한 샘플 코드로 테스트
- `pytest` 사용

### 반복적 단순화

- 모든 하네스 구성요소는 "모델이 독립적으로 수행할 수 없는 것"에 대한 가정
- 정기적으로 재평가: 더 이상 필요 없는 스캐폴딩은 제거
- 가장 간단한 솔루션을 찾고, 필요할 때만 복잡성 증가

## Tech Stack

- **Language**: Python 3.11+
- **CLI**: Click
- **Web**: FastAPI + Jinja2 templates
- **Async**: asyncio (플러그인 병렬 실행)
- **Testing**: pytest + pytest-asyncio
- **HTTP**: httpx (async 지원)
- **Reports**: HTML (Jinja2), JSON

## Project Structure

```
vibee-hacker/
├── vibee_hacker/
│   ├── core/
│   │   ├── engine.py
│   │   ├── plugin_base.py
│   │   ├── target.py
│   │   └── result.py
│   ├── plugins/
│   │   ├── blackbox/
│   │   └── whitebox/
│   ├── cli/
│   │   └── main.py
│   ├── web/
│   │   ├── app.py
│   │   ├── templates/
│   │   └── static/
│   └── reports/
│       ├── html_report.py
│       └── json_report.py
├── tests/
├── docs/
│   ├── handoff/
│   └── sprints/
├── pyproject.toml
├── CLAUDE.md
└── README.md
```
