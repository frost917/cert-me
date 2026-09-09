# 구현 기준 버전과 검증 상태

2026-09-09 확인한 초기 구현 기준이다. Go 모듈의 실제 선택 버전·전이 의존성·무결성은 [go.mod](../go.mod)와 [go.sum](../go.sum), DB 이미지 digest와 HTMX 패키지 무결성은 [dependencies.lock.json](../dependencies.lock.json)에 고정한다. 업데이트는 명시적으로 파일을 바꾸고 검증한다. 이 목록은 보안 감사나 네 DB 제품 지원 완료를 뜻하지 않는다.

| 영역 | 선택 | 이유·제약 |
| --- | --- | --- |
| Go | 1.27.1 | 공식 배포 목록에서 확인한 stable patch. net/http·crypto/x509·html/template·AES-GCM은 표준 라이브러리 |
| SQLite | modernc.org/sqlite v1.58.0 / 내장 SQLite 3.53.4 | CGO 없는 단일 실행 파일. SQLite 버전은 드라이버와 함께 고정 |
| PostgreSQL | 18.x, 초기 테스트 이미지 18.6 | database/sql 어댑터 github.com/jackc/pgx/v5/stdlib v5.11.0 |
| MySQL | 8.4 LTS, 초기 테스트 이미지 8.4.11 | github.com/go-sql-driver/mysql v1.10.1. 8.4.12 릴리스 노트는 있으나 공식 이미지 태그 확인 실패로 8.4.11을 테스트 기준으로 고정 |
| MariaDB | 11.8 LTS, 초기 테스트 이미지 11.8.9 | 동일 mysql 드라이버, 독립 스키마 테스트 |
| 비밀번호 해시 | golang.org/x/crypto v0.57.0 / argon2 | Argon2id. 운영 파라미터 튜닝은 인증 구현 단계 |
| 암호화 PKCS#8 | github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 | 버전 태그 대신 정확한 commit 고정. 서비스는 PBES2/PBKDF2-HMAC-SHA256/AES-CBC만 허용하도록 별도 ASN.1 정책 검사 필요 |
| PKCS#12 | software.sslmate.com/src/go-pkcs12 v0.7.3 | Modern2023 encoder 명시 사용. 약한 legacy encoder로 자동 fallback하지 않음 |
| OpenAPI | 3.0.3 / kin-openapi v0.149.0 | 참조·스키마·operation 구조 검증에 사용. 런타임 자동 라우터로 결정한 것은 아님 |
| 화면 | HTMX 2.0.10 + html/template | 패키지 무결성 고정. 화면 구현 시 로컬 자산으로 embed; 런타임 CDN 의존 없음 |
| 마이그레이션 | database/sql + 프로젝트 전용 실행기 | DB별 단계 재개·실행 전체 잠금 계약을 직접 구현. goose/sqlc/ORM은 도입하지 않음 |

공식 확인 출처: [Go 배포 목록](https://go.dev/dl/?mode=json), [PostgreSQL 지원 정책](https://www.postgresql.org/support/versioning/), [MySQL 8.4.12 릴리스](https://dev.mysql.com/doc/relnotes/mysql/8.4/en/news-8-4-12.html), [MariaDB LTS 정책](https://mariadb.org/about/). 모듈 버전은 Go module proxy에서 조회하고 다운로드 시 Go checksum database로 검증했다. [PKCS#8 프로젝트](https://github.com/youmark/pkcs8), [PKCS#12 API](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12), [HTMX 고정 패키지 메타데이터](https://registry.npmjs.org/htmx.org/2.0.10).

## 생성된 실행 아티팩트

- [OpenAPI JSON](../api/openapi.json): 51개 경로, 59개 작업. 관리 API뿐 아니라 토큰 다운로드·고정 CA/CRL·복구 화면 포함. 사용자 입력 객체의 알 수 없는 필드는 거부한다. 버전형 공개 스냅샷만 확장 필드를 허용한다.
- [마이그레이션 manifest](../internal/storage/migrations/manifest.json): 4개 dialect × 8개 파일, 38개 테이블(메타데이터 포함). 000은 journal 생성, 001~007은 업무 스키마다. SQLite는 CREATE에 FK 포함, 나머지는 007에서 FK 추가.
- [스키마 테스트](../internal/storage/migrations/schema_test.go): 전용 빈 DB에 SQL 전체 실행, 중복·FK·상태 제약·rollback 검사. [PKI 제약 테스트](../internal/storage/migrations/pki_constraints_test.go)는 공개키 재사용 갱신·일련번호·수령·인증서 없는 폐기 항목을 검사한다.
- [암호화 형식 테스트](../internal/cryptoformats/compatibility_test.go): P-256의 PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC PKCS#8과 Modern2023 PKCS#12 왕복·잘못된 암호 거부. 전체 지원 알고리즘과 OpenSSL 독립 fixture 검증은 아직 아니다.
- [CI](../.github/workflows/contracts.yml): SQLite/OpenAPI와 PostgreSQL·MySQL·MariaDB의 개별 초기 스키마 테스트. 컨테이너는 확인한 공식 manifest digest에 고정했다.

현재 로컬에서 OpenAPI 검증, SQLite 3.53.4 스키마·제약, 암호화 형식 검사가 통과했다. 외부 DB 세 개는 서버·Docker가 없어 로컬 실행하지 못했으며 DSN 미설정으로 skip된다. CI 파일 작성과 CI 실제 통과는 다르다. 초기 스키마 실행 테스트는 운영 마이그레이션 실행기의 crash recovery·체크섬 journal 동작이나 업무 서비스의 동시성 검증을 대신하지 않는다.

## 재현 방법

```sh
python3 tools/check_artifacts.py
go test ./... -v
go vet ./...
```

외부 DB는 테스트 전용 **빈 DB**의 DSN을 CERTME_TEST_POSTGRES_DSN, CERTME_TEST_MYSQL_DSN, CERTME_TEST_MARIADB_DSN에 각각 주입한다. 해당 테스트는 테이블과 합성 데이터를 생성한다. 운영 DB에는 실행하지 않는다. 미설정 대상은 skip하며 지원 완료로 간주하지 않는다.

초기 스키마·OpenAPI 원본 생성기는 tools/generate_migrations.py와 tools/generate_openapi.py다. 아티팩트 검사기는 임시 디렉터리에서 재생성해 저장된 파일과 비교하며 작업 파일을 수정하지 않는다. 첫 릴리스 이후 기존 SQL을 재생성해 배포하지 않고 신규 버전으로만 변경한다.

## 남은 구현 범위

실제 HTTP 핸들러, 인증·발급 서비스, 보안 입력 파서, CLI, 오프라인 마이그레이션 실행기, 실행 잠금·중단 복구는 아직 없다. 다음 구현은 journal·배타 잠금·마이그레이션 실행기부터 시작하고, 초기 HTTPS·설정·세션을 연결한다. SQL이 파싱된다는 이유로 one-time 전달·rotate·폐기 게시 계약이 구현됐다고 표시하지 않는다.
