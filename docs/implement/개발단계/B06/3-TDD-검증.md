# B06 3단계 TDD 검증 증거

브랜치: `codex/b06-stage3-completion` · 기준일: 2026-10-05

출발 계획은 [3단계 잔여 작업지시서](../../../plan/B06/3-잔여작업-지시서.md)다. 사용자가 `POST /api/v1/setup/settings` 제안을 승인해 최초 설정 보류 항목을 해소했다. 모든 설정값은 관리자 명시 입력이며 기존 GET/PATCH 수정 계약은 유지한다. 구현·검증을 담당한 Luna 결과는 루트가 직접 재검증·통합했다.

## 사용자 여정과 실제 보장

| 작업 | 보장 / 테스트 대상 | RED 증거 | GREEN 증거 / 현재 결과 |
| --- | --- | --- | --- |
| 최초 설정 API 계약 | 관리자 session/CSRF, 전체 입력, 201·ETag·Location, If-Match 불필요 | `go test ./api -run TestInitialSettingsContract -count=1`: route missing. `defa12d` | `go test ./api -count=1` 통과. `7637a5d` |
| 최초 설정 HTTP | 세션 없으면 401, strict 입력 거절 시 service 미호출, typed command와 DTO | `TestInitialSettingsRequiresSession`: 405, want 401. `b26e1ba` | `go test ./internal/adapter/http -count=1` 통과. `a65e043` |
| 최초 설정 service | 현재 계정/세션·권한·설치 단계·TLS URL·설정 없음 재확인, version 1·감사 원자성, 경쟁 한 번 생성, rollback | 새 command/Initialize 누락 compile RED. `a8a6007` | contract/service scoped·race 통과. `a65e043`; 감사 저장 호환성은 후속 수정 포함 |
| 초기 입력 화면 | 설정 없음 시 form 노출, 전체 POST, 이후 versioned PATCH, 실패 시 완료 노출 없음 | 실제 app.js 실행 시 form.hidden true, want false. `9da6155` | `tools/tests/stage3_ui.test.mjs` 실제 app.js 동작 테스트 통과. `85c8893` |
| 초기 저장 응답 손실/경쟁 | GET으로 저장된 값·version 확인 후 PATCH. 생성 재시도로 덮어쓰지 않음 | 응답 손실/409/본문 중단 뒤 completion hidden true, want false. `6d1ab62`, `950d7c4`, `8b4a5d1` | UI 동작 suite 통과. `0ebf379`, `daea6da` |
| 초기 HTTPS 실제 runtime | bootstrap → 관리자(자동 로그인 없음) → 로그인/me → 설정 생성/수정 → Root 없음 거절 → 재시작 보존 | SQLite Open bootstrap forbidden invalid_request. `7ccb6e5` | SQLite HTTPS journey 통과. `c357151` |
| bootstrap DER SAN | bootstrap 목적 키의 고정 cert-me identity만 예외. 일반 CA/다른 subject 거절 | signer SAN mismatch, 비고정 subject 예외 허용 RED. `a431f64`, `5f28751` | `go test ./internal/cryptoengine -run '^TestCertificateSignerFixedBootstrapSAN$' -count=1` 통과. `a058eb7` |
| 초기 TLS SQL 포인터 | 최초 change의 NULL previous version과 교체 change round-trip | 실제 SQLite row NULL→string Scan 오류. `fa804e2` | `TestTLSChangeScanNullablePreviousVersion` 통과. `c357151` |
| 설정 감사 저장/재시작 | UUID용 audit target_id에 정수 singleton PK를 쓰지 않음. 기존 설치 감사 분류와 호환 | TargetID=1 및 새 action으로 SQL 저장/재시작 실패. `33e3678`, `9332543` | nullable target·settings.update + operation=initialize로 SQLite restart 통과. `c357151` |
| 기존 인증/설정 HTTP | mode/origin, cookie, 429 비밀 제거, If-Match/ETag, Root 거절, 역순 URL 게시, CSP/프록시 경계 | 기존 기능 회귀 suite는 최초 실행 GREEN; RED를 만들어내지 않음 | HTTP/race 통과, package coverage 81.7%. `cd9a81a` |
| 외부 DB catalog/startup | 서버 실제 catalog와 reviewed schema 비교 및 FK 참조 열 순서. literal/숫자 cast/논리 우선순위/regex flags·범위 변경을 보존 | PG 정보 스키마 존재하지 않는 열 및 intrinsic NOT NULL, CHECK 재표현, MySQL/Maria default·charset 차이. `9f0d428`, `02d82b0` 및 후속 RED 커밋들 | 네 DB 실제 startup·설정 경쟁/rollback·재시작 검증 및 race 모두 PASS. SQL/checksum 변경 없음. `1785d49` |
| 설정 URL/Origin 계약 | 잘못된 DNS/모호한 숫자 주소가 저장 후 CSRF를 막지 않음. DNS/fetch 없음 | 실제 URLValidator가 잘못된 호스트를 허용한 RED. `bad9f96` | URLValidator 및 ingress 호환 테스트 통과. `eac089a`, `fdafbdd` |
| setup 완료 Empty 계약 | NoBody/{} 허용, unknown/invalid/oversize 본문은 service 미호출. chunked empty 및 closer 보존 | OpenAPI body required 및 Complete 호출 전에 body 미검증 RED. `22946bd`, `f7bd684` | API/HTTP/race 통과. `1a19a68`, `e58acd4` |

각 체크포인트는 이 브랜치의 실제 task sequence에 포함된다. squash 시 이 표의 실제 실패·통과 증거를 PR/merge 설명에 보존한다. 회귀 suite에 가상의 RED는 기록하지 않았다.

## 실행 환경과 검증 범위

- `python3 tools/check_artifacts.py`, `go test ./... -v`, `go vet ./...` 통과. OpenAPI는 52 paths·60 operations·65 schemas다.
- `go test -race ./internal/app/contract ./internal/app/service ./internal/adapter/http ./internal/runtime ./internal/cryptoengine ./internal/storage/sqlstore/operations` 통과.
- HTTP coverage 82.2%, contract package coverage 81.7%, service package 71.5%, runtime 60.5%. 새 Initialize command 검증은 100%, Initialize service는 82.4%다. 기존 service/runtime 전체 package가 80%라고 주장하지 않는다.
- Go 파일 gofmt 적용. goimports/gosec 실행 파일은 환경에 없어 미실행이며 도구 의존성을 추가하지 않았다.
- UI `.mjs` 테스트는 Node REPL의 `node:fs/promises`, `node:vm`, `node:assert/strict`로 실제 embedded app.js를 읽어 DOM/fetch fixture에서 실행했다. 로컬 Node CLI가 없어 `node tools/tests/stage3_ui.test.mjs` CLI 실행을 주장하지 않는다. 실제 browser E2E와 다르다. CUA browser inventory는 비어 있었고 iab 생성은 unavailable이었다.
- 외부 DB에는 저장소 CI의 pinned PostgreSQL/MySQL/MariaDB 이미지를 사용한다. 임시 컨테이너 포트는 loopback으로만 공개하며 별도 테스트 CA로 서버 인증서를 검증한다. TLS 검증을 해제하지 않는다. runtime 환경변수는 `CERTME_RUNTIME_TEST_<KIND>_{HOST,PORT,DATABASE,USERNAME,PASSWORD}`이며 dedicated empty DB만 사용한다. 연결 비밀/DSN은 출력하지 않는다.
- bare 전체 테스트에서 외부 DB environment가 없는 경우 skip된다. 이 기본 실행을 네 DB 통과로 표시하지 않는다.

루트는 별도 새 DB `certme_stage3_green7`에서 `go test ./internal/runtime -run '^TestRuntimeInitialHTTPSAdminFlow$' -count=1 -race -v`를 실행했다. SQLite 2.59초, PostgreSQL 7.36초, MySQL 22.95초, MariaDB 27.64초로 모두 PASS, package 종료 코드 0(61.582초)이었다. 각 DB에서 실제 HTTPS/admin/login/me, 최초 설정 전 오류, SQL 감사 실패 rollback, 동일 세션/CSRF의 동시 생성 201/409, 설정 GET/PATCH ETag, Root 없는 완료 거절, 종료 admission 및 재시작 보존을 확인했다. Luna도 별도 새 DB green8에서 같은 여정의 non-race 실행을 모두 PASS(49.476초)로 확인했고 루트가 원본 로그를 읽었다. schema-only 테스트 통과로 이를 대체하지 않았다.

진단에서 사용한 일부 opt-in catalog fixture는 전용 DB 환경변수가 없으면 skip한다. PostgreSQL NOT NULL/복합 FK 순서와 MariaDB 같은 이름 CHECK의 테이블 격리 검증은 별도 disposable fixture에서 실행했다. 전체 DB 지원의 모든 장애/복원/rotate 시나리오까지 통과했다는 의미는 아니다.

## 독립 검토와 후속 gate

Astra는 최초 설정·HTTP·bootstrap·nullable 저장·감사 변경 및 후속 URL/UI/canonical catalog의 실제 diff를 검토하고 material blocker를 발견하지 못했다. 최종 후속 검토에서 `go test ./internal/storage/migrate ./internal/adapter/http ./internal/cryptoformats -count=1`도 직접 통과를 확인했다. 리뷰어의 Node/외부 DB 미실행은 루트의 실제 실행 증거와 구분했다.

catalog 설계 확인에 사용한 공식 자료: [PostgreSQL key_column_usage](https://www.postgresql.org/docs/18/infoschema-key-column-usage.html), [pg_constraint의 not-null 구분](https://www.postgresql.org/docs/18/catalog-pg-constraint.html), [MySQL REGEXP/REGEXP_LIKE 관계](https://dev.mysql.com/doc/refman/8.4/en/regexp.html), [MariaDB NULL default 표현](https://mariadb.com/docs/server/reference/system-tables/information-schema/information-schema-tables/information-schema-columns-table). 실제 패치의 적합성은 문서만이 아니라 서버·부정 테스트로 검증했다.

Root 생성 화면/API는 4단계 범위다. 3단계 검증은 Root 없는 setup 완료의 거절을 확인하며 Root→Leaf 발급까지의 신규 설치 E2E 완료를 주장하지 않는다. 실제 브라우저 렌더링·수동 입력/저장 검증은 도구 부재로 별도 검증 공백이다.
