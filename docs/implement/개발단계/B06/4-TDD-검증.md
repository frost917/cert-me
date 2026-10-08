# B06 4단계 TDD 검증 기록

기준일: 2026-10-09 · 브랜치: `codex/b06-stage4-implementation` · 상태: 완료

기준 계획은 [4단계 오케스트레이션](../../../plan/B06/4-오케스트레이션.md)이다. 네 DB 실제 흐름과 race, 신규 서비스 실패 경로 및 최종 공통 검사를 완료했다.

## 독립 리뷰 후 회귀 검증

| 보장 | 실제 RED | 수정 후 확인 | 체크포인트 |
| --- | --- | --- | --- |
| 다른 입력의 멱등 키 재사용은 공개 `idempotency_conflict` 409 | `TestPKIIdempotencyConflictPublicCode`: 실제 `idempotency_key_reused` | HTTP 전체 테스트 통과 | `26dd3c9` → `1f8c6c0` |
| 갱신 트랜잭션에서 기존 결과를 발견해도 replay 표시 유지 | `TestRenewCommitReplaySignalsHTTPStatus`: 기존 인증서지만 `Replayed=false` | 동일 target 및 race 통과 | `642abc3` → `292f883` |
| pending 전달을 수동/긴급 재발급으로 종료하면 폐기·CRL 요구·secret 삭제 동시 반영 | 수동·긴급 재발급 회귀 모두 기존 폐기 `port: not found` | Reissue target 및 race 통과 | `0f42678` → `93cfd6a` |
| 미래 NotBefore라도 유출 키의 미만료 인증서는 폐기 | 소수 초 시각 유출 재발급 회귀에서 폐기 `port: not found` | Reissue target 및 race 통과 | `0f42678` → `93cfd6a` |
| 새 CA를 활성화한 직후 Intermediate 생성 가능 | `TestAuthorityServiceCreatesUsableRootAtFractionalClockTime`: Intermediate 생성 403 | 동일 target 포함 서비스 테스트 및 race 통과 | `abff040` → `f5972a9` |
| setup 완료 감사 target에 UUID가 아닌 문자열을 넣지 않음 | `TestComplete_AuditUsesInstallationTargetWithoutUUID`: 실제 target `installation` | 서비스 전체 및 실제 HTTPS setup 완료 통과 | `036ce8a` → `2b701a8` |
| 발급 결과가 관련 보호 리소스 조회 링크 제공 | `TestIssuanceResponseLinksToProtectedResources`: 두 링크 누락 | HTTP 전체 통과 | `9bfeffe` → `ab0998c` |
| 개인키 수령 전 갱신은 서명 없이 업무 충돌 409 | `TestRenewPendingDeliveryReturnsConflictWithoutSigning`: 실제 forbidden/invalid_request | 동일 target 및 서비스 전체 통과 | `b92ada3` → `8031244` |
| 전달 완료·custody 변경·감사가 한 transaction이며 전달과 재발급의 series 잠금 순서 일치 | SQL method 부재 compile RED; service 성공 후 pending 유지·mark 실패 무시·grant/delivery 우선 잠금 RED | 서비스 전체·SQLite guard·집중 race 통과 | `17dae27`, `55b44a2` → `99b5f89` |
| 읽기 스냅샷은 row lock을 얻지 않으며 쓰기는 기존 잠금 유지 | core helper 부재 compile RED; 외부 세 DB 동시 재발급 503 | core·SQL 전체 및 네 DB 재발급 race 통과 | `02fa60b` → `ced64ee` |

갱신 race 회귀는 첫 성공을 저장한 뒤 `commitRenew`를 직접 호출해 초기 조회 이후 다른 요청이 커밋한 분기를 결정적으로 검증한다. 실제 동시 HTTP 실행 전체의 증거와 구분한다.

## 실행한 공통 검사

- `python3 tools/check_artifacts.py`: PASS, 44 SQL checksum·생성 재현·문서 링크 검사. SQL migration은 변경하지 않았다.
- `go vet ./...`: 종료 코드 0.
- `go test -race ./internal/adapter/http ./internal/app/porttest ./internal/storage/sqlstore/operations -count=1`: 통과.
- `go test -race ./internal/app/service -run 'Reissue|ReplaySignalsHTTPStatus|CreatesUsableRoot' -count=1`: 통과.
- `go test ./internal/adapter/http -coverprofile=/tmp/cert-me-stage4-http.cover -count=1`: 통과, statement coverage **80.0%**.
- `go test ./internal/app/service -coverprofile=/tmp/cert-me-stage4-service.cover -count=1`: 초기 통과 결과는 **71.6%**. 이후 재발급 guard 보강 실행은 전체 **71.9%**, Reissue 함수 **80.4%**, prepareReissue **84.0%**, 재발급 파일 전체 **73.8%**다. 파일 전체 80%에는 미달하며 주로 저장소 오류·경합 예외 경로가 남는다. 최종 atomic/race 측정에서 서비스 패키지 전체는 **72.6%**, 신규 파일은 Reissue **80.2%**(388/484), 시리즈 **89.3%**(92/103), 공개 CA 조회 **85.3%**(93/109)다. 신규 구현 파일의 80% 목표를 충족했으며 전체 서비스 패키지의 기존 코드 coverage는 80% 미만이다.
- `go test -race ./internal/app/service ./internal/adapter/http ./internal/app/porttest ./internal/storage/sqlstore/operations -count=1`: 통과.
- Astra 변경 후 재검토: 기존 세 결함의 해결 확인, 추가 중대 결함 미발견. runtime·외부 DB 결과는 별도 gate다.

## 실제 네 DB 검증

최초 외부 실행은 동시 재발급 단계에서 PostgreSQL `issuance_series_read_failed`, MySQL/MariaDB `identity_account_read_failed`로 실패했다. MySQL/MariaDB의 최근 deadlock 기록을 확인했으나 PostgreSQL의 드라이버 SQLSTATE는 확인하지 못했다. 읽기 스냅샷의 잠금 절 분리 후 새 전용 DB로 재검증했다.

- `SSL_CERT_FILE=<전용 CA> go test ./internal/runtime -run '^TestRuntimePKIIssuanceFlow$' -count=1 -v`: 네 DB PASS, 총 56.29초. 외부 DB는 loopback 임시 Docker 인스턴스이며 서버 TLS 인증서를 검증했다.
- 별도의 새 DB에서 `SSL_CERT_FILE=<전용 CA> go test -race ./internal/runtime -run '^TestRuntimePKIIssuanceFlow$' -count=1 -v`: 네 DB PASS, 총 67.15초. 이 실행은 `57161b5`의 실제 DistributionService 전송 경계도 포함한다.

| DB | race 실행 | 검증 범위 |
| --- | --- | --- |
| SQLite | PASS · 2.88초 | 초기 HTTPS/admin/settings, Root/Intermediate, setup 완료, Leaf/renew, 동일 키 동시 reissue 201/200, series 수정/보관·조회, 실제 전송 중 재발급 409 및 완료 후 201 |
| PostgreSQL | PASS · 7.60초 | 동일 흐름, 실제 TLS SQL 연결 |
| MySQL | PASS · 28.98초 | 동일 흐름, 실제 TLS SQL 연결 |
| MariaDB | PASS · 27.69초 | 동일 흐름, 실제 TLS SQL 연결 |

기본 전체 테스트에서 환경 변수가 없어 skip되는 외부 DB case는 PASS로 계산하지 않는다. 위 표는 전용 환경 변수를 설정한 별도 실행 결과다. 원문 DSN·키·토큰은 기록하지 않는다. 실패 및 성공 로그는 `/tmp/cert-me-stage4-validation`에 보존한다.

## 검증 범위와 공백

주 여정의 첫 갱신 전 receipt는 domain/UOW fixture로 만들며 일반 `SaveLeafKeyGeneration`으로 custody를 바꾸지 않는다. 추가 여정은 실제 DistributionService와 암호 encoder, typed grant fixture, 채널로 제어하는 sink를 사용해 transferring 거절·series 불변·server_completed/custody·admission 및 같은 재발급 키의 성공 재시도를 검증한다. 공개 Link 생성/개인키 HTTP sink endpoint는 5단계 범위다.

`goimports`와 `gosec`는 현재 PATH에서 찾지 못했다. 검증 도구를 프로젝트 의존성으로 추가하지 않았다. 실제 브라우저 E2E와 전체 CA 관리 화면 완료를 이 기록으로 주장하지 않는다.

## 최종 추가 검증과 완료 판정

- `392faa1`의 실제 HTTP RED는 살아 있는 Leaf가 CA 파기·보관을 막을 때 403을 반환했다. `47012d4`는 인가 이후 종료 조건 실패를 409 `authority_closure_blocked`로 분류한다.
- `761f362`의 stopped-issuer RED 후 `e37a7e4`는 `issuer_stopped`만 업무 충돌로 분류한다. 일반 권한 거절 403과 domain 원인 오류는 유지한다.
- 최종 네 DB race 재실행은 SQLite **3.04초**, PostgreSQL **8.11초**, MySQL **30.05초**, MariaDB **34.58초**, 총 **75.78초**로 모두 PASS다. 최종 테스트 helper는 `5ecea23`에 기록했다. 공개 Root/Intermediate 인증서·체인과 서명/순서, ETag 304, Leaf ID 404, 이름 변경 시 DER 불변, 발급 중지 409 및 유효한 하위 인증서의 파기·보관 거절도 포함한다.
- 외부 DB 초기화의 30초 테스트 예산에 걸린 실패도 기록했다. 제품 timeout을 변경하지 않고 테스트 startup 예산만 120초로 조정했다. HTTP 요청 제한은 그대로 유지하며 새 DB에서 재실행했다.
- `go test ./... -v`, `go test -race ./... -v`, `go vet ./...`, artifact 검사 모두 통과했다. Astra 최종 재검토에서도 추가 중대 결함을 발견하지 못했다.
- service coverage 보강 중 stopped-issuer RED 체크포인트와 겹친 실행이 실패했으나 최종 동일 소스의 atomic/race 전체 실행은 통과했다. 실패를 PASS로 계산하지 않았다.

4단계 API·서비스 범위는 완료했다. 후속 HTTP 개인키 수령/폐기/CRL worker, 관리 UI와 실제 브라우저 검증은 별도 단계이며 이 보고서의 통과 범위에 포함하지 않는다.
