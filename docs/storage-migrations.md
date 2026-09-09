# DB 저장소와 마이그레이션 설계

[데이터 모델](./data-model.md)의 논리 제약을 네 DB에 구현하기 위한 계약이다. 초기 SQL 파일과 고정 버전은 [실행 아티팩트](./dependencies.md)에 연결했다. SQLite 초기 스키마는 실행 검증했으며 외부 DB·운영 실행기의 검증 완료를 뜻하지 않는다.

## 저장소 경계

서비스에는 CRUD 테이블 저장소 대신 `IssueCertificate`, `RenewLeaf`, `ConsumeDelivery`, `FailDelivery`, `ImportPKI`, `RevokeCertificate`, `ReserveCRL`, `PublishCRL`, `BeginPasswordReset`, `CompletePasswordReset`, `RotateSecrets` 같은 업무 단위 인터페이스를 노출한다. 서비스가 여러 저장소를 호출하며 트랜잭션을 누락하지 않도록 동일 UnitOfWork를 강제한다.

조회 모델은 인증서·수령·폐기·영향·발급 상태를 조합하지만 저장된 DER를 다시 쓰지 않는다. Go 오류는 not_found/conflict/version_conflict/retryable/unavailable로 정규화하고 SQL 오류 문자열·DSN을 API에 전달하지 않는다.

MVP는 낮은 처리량과 단일 인스턴스를 전제로 **변경 트랜잭션을 프로세스 내 한 writer 경로로 직렬화**한다. 읽기는 별도 풀을 사용할 수 있다. 암호화·서명·응답 포맷 변환은 가능하면 writer 밖에서 처리하고 커밋 직전에 version·기한·권한을 다시 검사한다. 이 단순화에도 DB 유일 제약·조건부 갱신·트랜잭션 테스트는 유지한다.

## 물리 타입과 인덱스

| 논리 값 | SQLite | PostgreSQL | MySQL / MariaDB |
| --- | --- | --- | --- |
| UUID·고정 hex | TEXT, 길이 검사 | VARCHAR(n), 길이 검사 | VARCHAR(n), ASCII binary collation |
| UTC 마이크로초·카운터 | INTEGER | BIGINT | BIGINT signed |
| 논리 bool | INTEGER 0/1 | BOOLEAN | BOOLEAN 및 0/1 입력 검증 |
| DER·암호문·SPKI | BLOB | BYTEA | LONGBLOB |
| JSON 스냅샷·설정 | TEXT | TEXT | LONGTEXT |
| 사용자 표시 문자열 | TEXT | TEXT | utf8mb4 TEXT |

UUID·지문·정규화 계정 이름은 DB별 비교 결과가 같도록 저장소에서 정규화한다. 로그인 이름은 MVP에서 ASCII 영문·숫자·`._-`, 3~64자로 제한하고 소문자로 유일성 검사한다. 표시 이름과 혼동하지 않는다. 사용자 문자열은 길이 제한을 서비스 계약으로 검증한다.

일련번호는 신규 발급 기준 최대 40 hex 자리다. import도 지원 가능한 양의 20옥텟 이하 일련번호로 검증한다. CRL 번호는 비음수 최대 20옥텟으로 제한한다. 길이를 넘는 입력은 자르거나 정수 overflow시키지 않고 unsupported_import로 거부한다.

SAN과 긴 문자열 전체에 무제한 인덱스를 만들지 않는다. SAN 검색에는 `normalized_value_hash` 고정 64자 필드를 추가해 `(type,normalized_value_hash)`로 후보를 찾고 원문을 다시 비교한다. 로그인·상태·작업키 등 인덱스 대상은 길이가 정해진 VARCHAR로 매핑한다. 작업 dedup_key 최대 128 ASCII자, request_id UUID, actor_key 최대 64 ASCII자다.

이진 필드와 JSON의 최대 크기는 API 입력 제한 및 파서 검증을 따른다. 각 JSON에는 schema_version을 두고 unknown version을 임의 해석하지 않는다. MySQL/MariaDB 테이블은 InnoDB로 생성한다. FK 대상과 참조 필드는 같은 타입·collation을 사용한다.

## 실행 잠금과 트랜잭션

| DB | 실행 전체 배타 잠금 | 업무 트랜잭션 |
| --- | --- | --- |
| SQLite | DB가 위치한 동일 로컬 볼륨의 고정 lock 파일에 OS 배타 잠금. PID 파일만으로 판정하지 않음 | 전용 writer 연결의 BEGIN IMMEDIATE; FK 활성화·busy timeout 설정 |
| PostgreSQL | 전용 writer 연결에서 DB별 고정 키의 session advisory lock 획득 | READ COMMITTED + 필요한 SELECT FOR UPDATE·UQ·version 조건 |
| MySQL / MariaDB | 전용 writer 연결에서 DB 이름을 포함한 고정 이름의 GET_LOCK(name,0), 반환 1 확인 | InnoDB READ COMMITTED + SELECT FOR UPDATE·UQ·version 조건 |

PostgreSQL session advisory lock은 세션 종료까지 유지되고 transaction rollback과 별개다. SQLite BEGIN IMMEDIATE는 먼저 쓰기 트랜잭션을 확보하며 기존 writer가 있으면 busy가 발생할 수 있다. [PostgreSQL 잠금 문서](https://www.postgresql.org/docs/current/explicit-locking.html), [SQLite 트랜잭션 문서](https://www.sqlite.org/lang_transaction.html).

MySQL/MariaDB 잠금 이름은 정규화한 DB 이름의 해시를 포함한 64자 이하 고정 문자열로 만든다. 잠금은 commit/rollback으로 해제되지 않고 명시적 해제 또는 세션 종료로 해제된다. [MySQL GET_LOCK](https://dev.mysql.com/doc/refman/8.4/en/locking-functions.html), [MariaDB GET_LOCK](https://mariadb.com/docs/server/reference/sql-functions/secondary-functions/miscellaneous-functions/get_lock).

잠금을 보유한 연결은 풀에 반환하지 않고 그 연결로 모든 변경 트랜잭션을 수행한다. 연결 교체·자동 재연결로 잠금 없이 작업을 이어가지 않는다. DB 연결을 잃으면 writer를 닫고 요청·작업을 중단한 뒤 프로세스를 종료한다. 새 실행은 새 잠금·저장 키·복구 검증을 통과해야 한다. 잠금 이름을 임의 설정해 같은 DB에 두 서비스를 실행하는 구성은 지원하지 않는다.

이 구조는 잠금 확인용 연결만 끊겼는데 다른 연결에서 계속 쓰는 문제를 피하기 위한 선택이다. 읽기 결과로 서명·키 전송을 승인하지 않고 writer에서 최종 소비·상태 변경을 커밋해야 한다. 이미 커밋하여 전송 중인 응답을 외부 프로세스가 취소할 수 있다고 보장하지는 않는다. 정상 유지보수 진입은 신규 요청 중지 → 기존 전송 종료 대기 → writer 종료 → 잠금 해제 순서다. 강제 중단은 transferring 복구 정책을 따른다.

SQLite DB·lock 파일은 동일 호스트의 안정적인 로컬 볼륨에 둔다. 네트워크 파일시스템·서로 다른 lock 파일로 같은 DB 접근은 지원하지 않는다. lock 파일은 잠금 해제 시 삭제하지 않아 inode 교체 경쟁을 피한다. 외부 DB도 프록시가 session 단위 잠금 연결을 보존해야 하며 transaction pooling을 사용하지 않는다.

잠금 순서는 writer → 계정/설치 → 요청 ID → authority(ID 정렬) → Leaf 계보(ID 정렬) → 공개키 → crl_states → 인증서 → delivery → token → job으로 고정한다. 필요한 대상은 사전 조회 후 이 순서로 잠그고 관계를 재검증한다. 데드락·busy는 외부 효과 전일 때만 최대 3회 제한 재시도하고 이후 503을 반환한다.

성공 요청 ID 조회는 If-Match 검사보다 먼저 수행한다. 계정 인증·권한 검사는 항상 먼저다. 커밋 결과가 불명확하면 새 ID로 다시 발급하지 않고 같은 요청 ID로 결과를 확인한다. 개인키 소비는 결과 조회 후에도 소비된 권한으로 전송을 재개하지 않는다.

## 마이그레이션 실행

`cert-me db migrate`는 오프라인 실행 잠금을 획득한 뒤 마이그레이션을 수행한다. 빈 DB에 대한 최초 스키마 생성만 최초 서버 시작에서 같은 실행 경로로 자동 수행한다. 기존 DB 버전이 다르면 서버는 HTTP를 열지 않고 필요한 migrate 명령을 안내한다. 구버전 바이너리가 신버전 DB를 열어 쓰는 것도 거부한다.

`schema_migrations`에는 version PK, name, checksum, state(applying/applied/failed), started_at, completed_at, last_step, error_code를 둔다. DB별 동일 논리 버전은 서로 다른 SQL 파일과 체크섬을 갖는다. 적용 완료 파일을 수정하지 않으며 새 마이그레이션을 추가한다. 서버는 버전뿐 아니라 체크섬·failed/applying 상태를 검사한다.

MVP 마이그레이션은 다음 논리 묶음으로 작성한다. `installation`과 상태 테이블의 순환 참조는 아래 FK 처리 절차를 따른다.

| 버전 | 생성 대상과 목적 |
| --- | --- |
| 001 identity | accounts, sessions, password_reset_tokens, auth_rate_limits, service_settings |
| 002 keys | key_materials, encryption_generations, private_key_secrets, encryption_verifier |
| 003 pki | authorities, ca_key_generations, certificates, ca_certificates, leaf_series, leaf_key_generations, leaf_certificates, certificate_sans |
| 004 delivery | key_deliveries, download_tokens, operation_requests |
| 005 revocation | import_batches, revocations, revocation_revisions, ca_takeovers, crl_states, crl_documents |
| 006 operations | ca_transitions, transition_impacts, deployment_confirmations, tls_versions, tls_changes, maintenance_runs, maintenance_crl_requirements, jobs |
| 007 installation_audit | installation, audit_events, audit_event_scopes, 미완성 FK·조회 인덱스·전체 무결성 검사 |

위 버전은 애플리케이션 릴리스 버전과 별개다. 모두 완료돼야 MVP 스키마로 서비스 가능하다. schema_migrations는 실행기가 먼저 생성한다. 빈 DB 스키마 생성만으로 관리자나 Root를 만들지 않는다. 저장 키 verifier·installation·기본 설정 데이터는 모든 스키마가 준비된 뒤 별도 원자적 초기화로 만든다.

### 순환 FK 처리

PostgreSQL/MySQL/MariaDB는 해당 묶음의 기본 테이블부터 생성한 뒤 FK를 추가한다. 아직 없는 다른 묶음의 대상은 007에서 추가한다. nullable 포인터는 DML의 최초 행 생성 시만 비워두며 실제 리소스 생성 트랜잭션 완료 시 모델의 불변식을 검사한다.

SQLite는 최초 CREATE TABLE에 FK 선언을 포함하고 모든 참조 테이블 생성 이후 foreign_key_check를 수행한다. 실제 행 입력은 전체 생성 뒤에 시작한다. 후속 스키마 변경에서 테이블 재구성이 필요하면 copy → 개수/값/참조 검증 → 교체를 수행하고 FK 검사를 통과한 경우만 완료한다. 연결별 foreign_keys 설정 변경은 트랜잭션 경계와 드라이버 동작을 테스트한다. FK를 끈 상태로 일반 서비스를 시작하지 않는다. [SQLite FK 문서](https://www.sqlite.org/foreignkeys.html)의 연결별 활성화·스키마 변경 제약을 따른다.

### 실패와 재개

MySQL/MariaDB의 DDL은 암묵적 commit을 일으킬 수 있으므로 migration 전체를 단일 rollback으로 되돌린다고 가정하지 않는다. [MySQL DDL commit 문서](https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html), [MariaDB implicit commit 문서](https://mariadb.com/docs/server/reference/sql-statements/transactions/sql-statements-that-cause-an-implicit-commit).

각 DDL 단계는 실행 전 기대 스키마, 실행 후 실제 테이블·컬럼·인덱스·FK를 검사한다. 단계 적용 후 last_step 기록 전에 죽어도 실제 스키마를 비교해 적용 완료를 인정할 수 있어야 한다. `IF NOT EXISTS`만으로 이름이 같고 정의가 다른 테이블을 성공 처리하지 않는다. 예상 정의와 다르면 중지한다.

자동 파괴적 down migration은 제공하지 않는다. 실패한 단계는 전용 재개 명령이 체크섬·실제 스키마·데이터 조건을 검사한 뒤 이어간다. 데이터 손실 없이 재개 불가능하면 실패 상태를 유지하고 수정 마이그레이션 또는 운영자 복구가 필요하다. 백업 실행·보관을 cert-me가 대신하지 않는다.

PostgreSQL/SQLite에서 가능한 DDL은 버전 단위 트랜잭션으로 묶지만 동일 중단·재개 검증을 수행한다. 적용 완료 후 인덱스·FK·필수 singleton·모델 제약 검사 및 버전 갱신을 마친 뒤 서비스 시작을 허용한다.

## DDL로만 보장할 수 없는 제약

DB에서는 PK/UQ/FK/NOT NULL과 가능한 CHECK를 사용한다. 다음은 업무 저장소를 통한 쓰기 및 계약 테스트로 보장한다.

- certificates의 CA/Leaf subtype 정확히 하나, issuer 키와 issuer 인증서 일치.
- leaf_series current 포인터·generation·공개키의 소속 일치.
- 일반 Leaf Root 직접 발급 금지 및 bootstrap 격리.
- import 공개키 중복 거부와 정상 갱신 공개키 재사용 허용.
- 수령 상태 전이와 secret 존재 여부, CA·내부 TLS의 수령 권한 생성 금지.
- CRL 번호 큰 정수 비교·generation 후퇴 방지, revocations와 certificates 사이 일련번호 충돌 검사.
- CA 인수 확인·유효성·키 존재 여부·발급 차단과 권한 검사.

복구용 직접 SQL 편집을 정상 운영 API로 취급하지 않는다. 정합성 검사에서 실패하면 일반 서비스는 열리지 않고 구체적인 대상 ID와 위반 규칙만 출력한다. 키·토큰 원문은 출력하지 않는다.

## 구현 완료 조건

네 DB에 각각 빈 DB 설치, 동일 버전 재실행, 이전 버전 업그레이드, 잘못된 체크섬·새 버전 거부, DDL 단계별 강제 중단·재개를 검증한다. MySQL과 MariaDB는 별도 CI job이다.

공통 저장소 테스트는 동시 첫 관리자 생성·개인키 수령·갱신·같은 요청 ID·중복 import·CRL 예약/게시·재설정/로그인 경쟁·rotate 원자성을 포함한다. 실행 잠금은 두 프로세스 경쟁, 소유 연결 강제 종료, 유지보수 진입 중 전송, 종료 후 재시작을 검증한다.

SQL 파일 경로는 `internal/storage/migrations/{sqlite,postgres,mysql,mariadb}/NNN_name.sql`로 통일한다. 000_metadata.sql은 실행기의 journal을 먼저 생성한다. DB별 단계 재개가 필요한 버전은 대응하는 Go 실행기를 구현해야 한다. 드라이버·마이그레이션 도구 선택 후 이 경로와 단계 메타데이터를 실제 구현으로 고정한다. 테스트 통과 전에는 네 DB 지원 완료로 표시하지 않는다.
