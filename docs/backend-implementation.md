# 백엔드 구현 설계

## 설계 상태와 사용 방법

이 문서는 [요구사항 수집](./backend-design-inputs.md)에서 남긴 객체·서비스·저장 경계 선택을 확정한다. 개발 에이전트는 추가 기획 승인 없이 아래 순서로 구현할 수 있다. 제품 정책은 [운영](./architecture.md)·[수명](./certificate-lifecycle.md)·[import](./pki-import.md), 외부 필드는 [OpenAPI](../api/openapi.json), 저장 필드는 [데이터 모델](./data-model.md)을 따른다. 기존 SQL은 초기 저장 표현이며 서비스 객체와 일대일 대응시키지 않는다.

결정: Go 단일 프로세스의 모듈화된 백엔드, 명시적 생성자 주입, 구체 서비스 구조체, 소비자 측 port 인터페이스, 서비스가 여는 하나의 UnitOfWork, 명시적 DTO 변환을 사용한다. ORM·DI 프레임워크·범용 CRUD 서비스·이벤트 버스·런타임 코드 생성은 도입하지 않는다. 모든 기능을 갖춘 거대 CertificateManager도 만들지 않는다.

설계 문서의 Go 선언은 구현할 공개 계약이다. 필드가 표로 정의된 command/result 타입을 포함하여 해당 패키지에 실제 코드를 작성한다. 아직 선언·서비스 구현 파일이 존재한다는 뜻은 아니다.

## 1. 디렉터리와 의존 규칙

```text
cmd/cert-me/main.go             # 인자 파싱, runtime 실행, 종료 코드
internal/runtime/              # New, Start, Shutdown, 객체 조립·수명
internal/config/               # env/file 로드, 검증된 설정
internal/domain/               # 순수 객체·정책·값 타입
  identity.go                  # Account, SessionState, ResetPolicy
  authority.go                 # Authority, IssuerContext, AuthorityPolicy
  certificate.go               # Certificate, CertificateProfile, Subject, SAN
  series.go                    # LeafSeries, LeafKeyGeneration, PlanRenewal
  delivery.go                  # Delivery, DownloadGrant, 전이 규칙
  revocation.go                # Revocation, CRLState, 폐기 변경 규칙
  transition.go                # Transition, 영향·배포 확인
  tls.go                       # TLSVersion, TLSChange
  values.go                    # 구별된 ID·시각·지문·일련번호·기간
  errors.go                    # 정책 오류
internal/app/contract/         # command, result, 조회 DTO, RequestMeta
internal/app/port/             # UnitOfWork·repository·암호화·TLS·시각 인터페이스
internal/app/                  # 구체 서비스와 트랜잭션 내부 공통 작업
internal/secret/               # 로그/JSON 출력이 차단된 단기 비밀 입력
internal/adapter/http/         # JSON·HTML·다운로드, 인증/CSRF 미들웨어, 오류 매핑
internal/adapter/local/        # 권한 제한 Unix 소켓, CLI 온라인 요청
internal/adapter/crypto/       # x509·서명·키 암호화·import 파서·묶음
internal/adapter/tls/          # 새 TLS 연결용 설정 교체
internal/storage/             # SQL 어댑터, 네 dialect, writer·읽기 연결
internal/storage/migrations/  # 기존 SQL·manifest 유지
internal/worker/              # 영속 작업 스케줄·실행·종료
```

의존 방향은 `domain ← contract ← port ← app ← adapter/runtime`이다. port는 domain·contract·secret을 참조할 수 있고 app은 port를 사용한다. secret은 표준 라이브러리만 참조한다. storage·crypto·tls는 port를 구현하고 app을 import하지 않는다. domain은 HTTP·SQL·파일·환경변수·전역 시계를 참조하지 않는다. 기존 internal/cryptoformats 테스트는 어댑터 구현 시 이동하되 검증 범위를 유지한다.

MVP에서 domain/app은 각각 단일 Go 패키지로 시작한다. 파일로 책임을 구분하고 실제 순환 의존·변경 단위가 생길 때 패키지를 나눈다. 서비스마다 인터페이스와 구현체 쌍을 만들지 않는다. 핸들러가 테스트 대역을 필요로 하는 경우 그 핸들러가 사용하는 좁은 인터페이스만 선언한다.

## 2. 값 타입·객체·공통 입력

AuthorityID, CAKeyGenerationID, CertificateID, SeriesID, LeafKeyGenerationID, KeyMaterialID, DeliveryID, GrantID, RevocationID, AccountID, SessionID, TransitionID, TLSVersionID, JobID는 서로 다른 named string 타입이다. 생성은 UUID, 파싱 시 형식 검사한다. Version은 비음수 int64, Fingerprint는 SHA-256, SerialNumber/CRLNumber는 검증된 hex와 큰 정수 비교 기능을 갖는다. []byte와 slice는 생성자·조회 accessor에서 복사하여 불변 객체의 외부 변경을 막는다.

| 객체 | 생성/메서드 | 규칙·반환값 |
| --- | --- | --- |
| Certificate | ParseCertificate를 통과한 CertificateFacts로 NewCertificate, IsValidAt(now) | 원본 DER 불변. 암호학적 파싱은 어댑터, 원본 기간/식별자는 객체 |
| Authority | CanIssue(IssuerContext, now), StopIssuance(), CanDestroyKey(ClosureFacts, now) | 인증서·키·인수·상위 영향 검사, 중지와 CRL 서명 허용 분리 |
| LeafSeries | PlanRenewal(RenewalFacts, now), ChangePolicy(policy) | RenewalPlan에 reuse/rotate, 다음 횟수·대상 issuer·기간. 입력 객체를 미리 변경하지 않음 |
| Delivery | CanConsume(now), Consume(now), Complete(now), Fail(code, now), Expire(now) | 전이마다 새 상태/오류 반환. 완료는 서버 전송 관측값 |
| DownloadGrant | Validate(purpose, certificateID, deliveryID, now), Consume(now), Invalidate(now) | 토큰·권한·대상 결합. 원문 토큰 미보유 |
| Account | CanLogin(), BeginReset(), CompleteReset(hash) | 상태·epoch 변경 반환. 세션 전체 삭제는 같은 트랜잭션의 서비스 책임 |
| Revocation | Merge(incoming), StampChangeGeneration(generation), Correct(reason,time,justification,now) | 동일 기록 무변경, 충돌 자동 덮어쓰기 금지, 해제 없음. stamp는 현재 값보다 큰 양수만 허용. 정정은 `revokedAt <= now + 5분`만 허용하고 now 미설정을 거부 |
| CRLState | CanPublish(number,generation), MarkPublished(...) | 번호·반영 세대 후퇴 금지 |
| Transition | SetTarget(...), ConfirmDeployment(...), Complete(ClosureFacts) | 긴급 영향과 개별 폐기 분리, 수동 확인 보존 |

객체는 자기 필드만으로 알 수 없는 사실을 DB에서 직접 찾지 않는다. Facts에는 검증 대상의 ID/version도 포함하고 서비스가 commit 안에서 최신 사실을 다시 구성한다. 모든 만료 판정은 `now >= expires_at`을 만료로 처리한다.

```go
// internal/app/contract
// 모든 command에는 외부 입력 필드만 있다. Actor/system 여부를 JSON으로 받지 않는다.
type RequestMeta struct {
    Principal Principal
    RequestID string
    ClientIP  netip.Addr
}
type MutationMeta struct {
    RequestMeta
    ExpectedVersion *domain.Version // 필수 여부는 메서드 표에서 결정
    IdempotencyKey  string          // 재시도 대상 메서드에서 UUID 필수
}
```

Principal은 kind·계정/세션 식별자·auth_epoch·내부 작업 종류를 숨긴 필드로 갖고 JSON으로 역직렬화하지 않는다. 일반 요청용 Principal은 IdentityService가 세션 검증 후 생성한다. 익명·토큰 접근에는 별도 경로를 사용한다. local/worker/runtime의 내부 Principal 생성은 조립 단계에서 주입한 전용 factory로 제한한다. system은 만능 권한이 아니라 허용된 작업 종류를 가진다.

관리 서비스의 모든 변경은 현재 계정 상태·epoch·세션 존재·만료·Action/Scope를 트랜잭션 안에서 다시 확인한다. 권한 검사 입력의 Scope는 DB 관계에서 구성하며 사용자 제공 Root ID를 신뢰하지 않는다. CA 전환은 원본/대상 모두 검사한다. MVP Authorization은 전체 관리자만 허용한다.

## 3. 서비스와 공개 메서드

모든 표의 메서드는 기본적으로 `(ctx context.Context, meta contract.MutationMeta, cmd XxxCommand) (XxxResult, error)`다. 읽기는 RequestMeta, 내부 작업은 검증된 system/local Principal을 사용한다. 인자 없는 명령도 명시적 빈 command를 사용한다. Context에 업무 인자·트랜잭션·암호를 숨기지 않는다.

command의 외부 필드는 아래 OpenAPI schema를 그대로 typed struct로 옮기며 domain 값으로 검증·변환한다. DTO에 SQL row를 embed하지 않는다. 결과는 해당 응답 schema의 data 객체다. version은 If-Match로, IdempotencyKey는 헤더로 전달하며 JSON 필드로 중복 정의하지 않는다.

| 구체 서비스 | 메서드: Command schema → Result schema | 전제/특수 처리 |
| --- | --- | --- |
| SetupService | Status: Empty → Setup; CreateAdmin: Credentials → Account; Complete: Empty → Setup | 최초 생성은 익명, Complete는 Settings version 필수. 설치 상태를 내부에서 확인 |
| IdentityService | Login: Credentials → Login; Logout: Empty → 없음; Authenticate(sessionToken) → Principal/Session; BeginReset(accountID) → ResetLink; CompleteReset: PasswordReset → 없음; IssueCSRF → CSRF | BeginReset은 local 전용. Login/CompleteReset은 세션 인증 대신 pre-auth 검증 경로 |
| SettingsService | Get → Settings; Update: SettingsPatch → Settings | Update에 version 필수, 이전 링크/계보 설정 불변 |
| AuthorityService | Create: AuthorityCreate → Authority; Rename: NamePatch → Authority; SetIssuanceState: IssuanceState → Authority; DestroyKey: KeyDestruction → Authority; Archive: Empty → Authority | Create는 idempotency, 나머지는 Authority version 필수 |
| IssuanceService | Issue: LeafCreate → Issuance; Renew: Renew → Issuance; Reissue: Reissue → Issuance; UpdateSeries: LeafPatch → LeafSeries; ArchiveSeries: Empty → LeafSeries | 발급 3종 idempotency, 기존 계보 명령은 Series version 필수 |
| DistributionService | CreateLink: DownloadLinkRequest → DownloadLink; Deliver: DownloadCommand + DownloadSink → TransferSummary; ReportFailure: Justification → DeliveryFailure | ReportFailure는 Delivery version 필수. Deliver는 토큰만으로 제한된 인증 |
| RevocationService | Revoke: Revoke → Revocation; Compromise: Justification → Compromise; Correct: RevocationCorrection → Revocation | Correct는 Revocation version. Revoke 동일 값은 무변경 결과 |
| ImportService | Preview: ImportUpload → ImportPreview; Commit: ImportUpload → ImportResult; AttachSigningKey: SigningKeyUpload → Authority; ConfirmTakeover: TakeoverInput → Takeover | Commit은 idempotency, CA 변경 2종은 Authority version 필수 |
| TransitionService | Create: TransitionCreate → Transition; SetTarget: TransitionPatch → Transition; ConfirmDeployment: DeploymentInput → Deployment; Complete: Empty → Transition | 기존 전환 명령은 Transition version. 긴급 Create는 차단·영향·부모 폐기 함께 반영 |
| CRLService | RequestPublication(authorityID) → JobAccepted; Publish(jobID, CAKeyGenerationID) → PublicationResult | Request는 관리자, Publish는 worker/maintenance 전용 |
| TLSService | Status: Empty → TLSStatus; UploadCandidate: TLSUpload → TLSVersion; IssueCandidate: TLSIssue → TLSVersion; Reload: Empty → TLSVersion; Activate: TLSActivation → TLSStatus; Bootstrap/Reconcile → 내부 결과 | IssueCandidate는 idempotency. Activate는 TLS 상태 version, 나머지 내부 명령은 runtime/local 전용 |
| QueryService | List/Get Authority, Series, Certificate, Revocation, Transition, Import, Job, Audit; GetCRLStatus; ReadPublicCA | 필터/커서/결과는 OpenAPI. 검색·상세마다 권한 재확인 |
| MaintenanceService | Rotate(oldKey,newKey) → MaintenanceResult; FinalizeRestore(options) → MaintenanceResult; RecoverTransfers() → RecoverySummary; PruneAudit(cutoff) → count | runtime이 오프라인 허가 또는 제한된 복구 실행 경로로 호출 |

command 타입 이름은 `<Service접두사><Method>Command`로 통일한다(예: IssuanceRenewCommand). URL path의 대상 ID는 command에 typed 필드로 별도 포함한다. Authority 계열은 AuthorityID, Series 계열은 SeriesID, 폐기/링크 생성은 CertificateID, 키 유출은 KeyMaterialID, 수령 실패는 DeliveryID, 정정은 RevocationID, 전환 변경은 TransitionID다. JSON decoder는 이 필드를 받지 않고 핸들러가 검증된 path에서 채운다. Get/List는 QueryService의 typed query struct를 사용한다. 업로드 command는 파일 바이트와 키별 secret.Input을 소유하고 작업 후 해제한다.

ResetLink는 URL(secret.Input), ExpiresAt, TokenID, AccountID이고 MaintenanceResult는 RunID, Kind, Phase, Completed, BlockingCAIDs다. PublicationResult는 CAKeyGenerationID, DocumentID, Number, CoveredGeneration, Published, FollowupRequired다. RecoverySummary는 Checked/Changed/Failed 카운터와 비밀 없는 FailedIDs다. 이들은 내부 결과이며 새 공개 HTTP API를 만들지 않는다.

CreateLink는 매 호출 새 토큰을 발급하므로 idempotency 원문 재생을 지원하지 않는다. 결과 유실 시 다시 링크 생성하며 기존 수령 기한은 유지한다. SetupService/IdentityService의 비밀번호 해시·토큰 생성은 저장 전에 수행하고 commit에서 상태를 재검사한다.

조회 목록의 필터 struct는 domain ID·UTC 시간·허용 enum·Limit/Cursor만 포함한다. 자유 SQL 정렬·조건 문자열은 받지 않는다. 감사 export는 QueryService가 같은 권한 필터를 적용한 iterator를 반환하고 HTTP/CLI 어댑터가 JSON/CSV로 표현한다.

## 4. 트랜잭션 인터페이스: 하나로 통일

서비스가 UnitOfWork.Write를 호출하고 callback 안에서 얻은 TxStores만 쓰기에 사용한다. repository 메서드는 트랜잭션을 열거나 커밋하지 않는다. app 내부 공통 함수가 동일 TxStores를 받아 여러 서비스에서 재사용한다. 완성된 서비스가 다른 서비스의 public 변경 메서드를 호출하지 않는다.

```go
// internal/app/port
// 아래 repository 인터페이스의 메서드 범위는 이어지는 표로 정의한다.
type UnitOfWork interface {
    Write(context.Context, func(TxStores) error) error
}
type RuntimeGate interface {
    // FailClosed is idempotent and must not wait for the caller.
    FailClosed(code string)
}
type TxStores interface {
    Accounts() AccountRepository
    Installation() InstallationRepository
    PKI() PKIRepository
    Delivery() DeliveryRepository
    Revocations() RevocationRepository
    CRLs() CRLRepository
    Transitions() TransitionRepository
    TLS() TLSRepository
    Requests() RequestRepository
    Secrets() SecretRepository
    Jobs() JobRepository
    Audit() AuditRepository
}
```

ReadStore는 별도 읽기 스냅샷용 인터페이스로 둔다. 사전 준비용 읽기 결과는 commit 권한이 아니다. 필요한 인터페이스는 app/port에 선언하고 storage가 구현한다. 모든 repository 메서드는 context를 첫 인자로 받는다.

| 저장소 | 필수 메서드와 입력/출력 |
| --- | --- |
| AccountRepository | GetAccountForUpdate(id) → Account; FindSessionByHash(hash) → SessionState; GetSessionForUpdate(sessionID) → SessionState; InsertAccount; SaveAccount(account,expectedVersion); Insert/DeleteSession; DeleteAllSessions(accountID); Get/Insert/InvalidateResetTokens; SaveRateLimit |
| InstallationRepository | GetForUpdate → Installation; Save(expectedVersion); Get/SaveSettings(expectedVersion) |
| PKIRepository | GetIssuerForUpdate(authorityID) → Authority; GetSeriesForUpdate(seriesID) → SeriesSnapshot; GetCertificate(id); FindCertificateByDER; FindKeyBySPKI; SerialExists(issuer,serial); InsertKeyMaterial/Authority/CAKeyGeneration/LeafKeyGeneration/Certificate/Series; SaveLeafKeyGeneration(generation); SaveSeries/Authority(expectedVersion); ListCertificatesUsingKey; ListAffectedDescendants |
| DeliveryRepository | GetDeliveryForUpdate; GetGrantForUpdate(tokenHash); InsertDelivery/Grant; SaveDelivery(expectedVersion); SaveGrant; InvalidatePrivateGrants(deliveryID); InvalidatePublicGrants(certificateID); ListExpired/Transferring |
| RevocationRepository | FindForUpdate(issuer,serial); Insert; Save(expectedVersion); AppendRevision; ListByIssuer |
| CRLRepository | GetStateForUpdate(caKeyID); SaveState(expectedVersion); InsertDocument; GetDocument |
| TransitionRepository | GetForUpdate; Insert/Save(expectedVersion); AddImpact; LinkReplacement; AddDeploymentConfirmation; ListImpacts |
| TLSRepository | GetActiveForUpdate; InsertVersion; GetVersion; SaveChange(expectedVersion); SetActive(expectedVersion,versionID) |
| RequestRepository | Find(actorKey,operation,key); InsertResult(inputHash,publicResult) | 
| SecretRepository | GetEncrypted(keyID,purpose); InsertEncrypted; Delete(keyID,purpose); ListEncrypted; ReplaceEncrypted; Get/SaveVerifier |
| JobRepository | UpsertDemand(key,payload); ClaimDue(now,leaseUntil); Save(expectedVersion); GetForUpdate; ListRecoveryRequired |
| AuditRepository | Append(publicEvent,scopes); DeleteBefore(cutoff,limit) |

초기 SQL의 operation_requests processing/failed 값은 허용되어 있지만 MVP 서비스는 성공 결과를 업무 커밋에 함께 InsertResult한다. 사전 준비 중에는 영속 processing 행을 만들지 않는다. 같은 key의 동시 요청이 둘 다 준비될 수 있어도 commit 안에서 먼저 결과를 확인하고 한 쪽만 반영한다. 패자는 새 키/서명 결과를 버리고 기존 공개 결과를 반환한다. 일반 단일 실패는 결과 행이 없으므로 같은 key로 재시도할 수 있다.

Write callback 내부 순서는 인증/권한 확인 → 요청 결과 재확인 → version/현재 정책 확인 → 도메인 전이 → 저장 → 작업 요구·감사 기록이다. 서비스별 검증이 저장 중 실행되므로 저장소는 정책 객체 대신 row를 검증 없이 덮어쓰는 우회 메서드를 제공하지 않는다. callback 오류면 모든 변경을 rollback한다. callback panic도 rollback 후 runtime 오류 처리로 전달한다.

오류 응답과 저장할 변경이 함께 필요한 경우는 명시적으로 구분한다. 잘못된 비밀번호의 실패 카운터, 요청에서 발견한 수령 만료의 키 삭제·폐기·CRL 작업은 정상적인 업무 변경이다. 서비스가 callback 밖 로컬 변수에 거부 결과를 담고 callback은 nil로 끝내 해당 변경을 커밋한 뒤 거부 오류를 반환한다. DB 저장 실패는 callback 오류로 rollback한다. 이 경로에서도 payload는 보내지 않으며, 거부 자체를 성공 발급 요청 결과로 저장하지 않는다.

성공 결과는 callback의 로컬 변수에 준비하되 Write가 nil을 반환하기 전 외부로 반환하지 않는다. CommitUnknown 오류에는 결과를 내보내지 않는다. UnitOfWork는 callback을 자동 재실행하지 않는다. 서비스가 외부 효과 전의 명확한 rollback·DB 경합일 때만 최대 3회 전체 준비를 재시도한다. 새 요청 ID로 바꾸지 않는다.

## 5. 서비스 조립과 의존성

각 서비스는 `NewXService(deps XDeps) (*XService, error)`로 생성한다. 필수 의존성이 nil이면 시작 시 실패한다. 핸들러에 Db/SecretRepository를 직접 전달하지 않는다. 공통 의존성은 UoW, ReadStore, Authorizer, Clock, IDGenerator이며 서비스별로 필요한 것만 XDeps에 둔다.

| 서비스 | 추가 의존성 |
| --- | --- |
| Setup/Identity | PasswordHasher, TokenCodec |
| Settings | URLValidator, 현재 TLS 공개 스냅샷 조회 |
| Authority/Issuance | KeyEngine, CertificateSigner, SerialGenerator, ProfileValidator |
| Distribution | TokenCodec, DeliveryEncoder, PublicCertificateEncoder, OperationalLogger, RuntimeGate |
| Revocation/Transition | 추가 외부 I/O 없음; app 내부 revocationChanges 공통 함수 |
| Import | PKIParser, ChainValidator, KeyEngine |
| CRL | CRLSigner |
| TLS | KeyEngine, CertificateSigner, ChainValidator, TLSInstaller, 허용된 파일 소스 |
| Query | ReadStore, Authorizer |
| Maintenance | KeyEngine, RuntimeGate; CRL 후속 작업은 JobStore로 기록 |

app 내부 `applyRevocations(ctx, tx, changes, meta)`는 폐기 병합·generation 증가·CRL 작업·감사 추가를 함께 수행한다. Distribution의 실패/만료, Transition의 부모 CA 폐기, Import의 CRL 병합, RevocationService가 이 함수를 사용한다. 자체 트랜잭션을 열지 않는다. 여러 항목은 issuer별 generation을 한 번 증가시키고 같은 generation을 부여할 수 있다.

generation은 issuer의 CRLState를 잠그고 batch당 한 번 계산하며 `Revocation.StampChangeGeneration(generation)`으로 각 레코드에 부여한다. 저장소에 별도 generation 인자를 두어 객체와 다른 값을 저장하지 않는다. 신규 레코드도 같은 batch generation을 받는다. `Merge`가 `changed=false`를 반환한 레코드는 stamp와 저장 대상에서 제외하며, batch 전체가 무변경이면 issuer generation과 CRL 작업 요구도 증가시키지 않는다.

version은 DB 저장 횟수가 아니라 낙관적 잠금 토큰이다. 도메인 전이는 저장 필드를 바꿀 때마다 version을 올리므로 Merge/Correct 뒤 stamp하면 한 요청에서 두 번 증가할 수 있다. app은 DB에서 읽은 최초 version을 expectedVersion으로 보존하고 최종 객체를 한 번 Save한다. 저장소는 `WHERE version=expectedVersion`으로 검사하고 객체의 최종 version을 그대로 저장하며 `finalVersion=expectedVersion+1`을 강제하지 않는다. 레코드·CRLState·정정 이력·CRL 작업 요구·감사는 동일 트랜잭션에 커밋한다. 생성자에 Facts를 다시 조립하는 방식을 업무 전이의 대체 수단으로 사용하지 않는다.

인증서 서명 공통 함수는 `prepareCertificate(plan, keyRef)`로 두고 Authority/Issuance/TLS가 사용한다. 내부 TLS 발급이 일반 Leaf 발급 서비스를 호출해 delivery를 만든 뒤 삭제하는 방식은 금지한다. 계획의 custody가 처음부터 internal이며 response에 download grant가 없다.

## 6. 비밀 입력·키·서명 계약

secret.Input은 단기 []byte의 소유권을 갖는다. `Close()`는 소유 버퍼를 지우고 참조를 끊으며 여러 번 호출해도 안전하다. String/LogValue는 항상 redacted, MarshalJSON은 오류를 반환한다. 평문을 필요로 하는 어댑터에만 `Use(func([]byte) error)`로 동기 접근을 제공한다. callback이 참조를 보존하지 않는 것은 어댑터 계약이며 메모리 안전 삭제의 절대 보장을 주장하지 않는다.

secret.Input은 실행 중인 Use callback 수를 추적한다. Close는 즉시 closed로 표시해 새 Use를 거부하되 callback이 남아 있으면 기다리지 않고 반환하고, 마지막 callback이 종료될 때 버퍼를 지운다. callback 종료 처리는 panic에도 defer로 수행한다. callback 내부 Close와 중첩 Use가 데드락을 만들지 않으며, 다른 goroutine의 Close가 사용 중인 버퍼를 동시에 덮어쓰지 않는다. callback이 없으면 Close가 즉시 버퍼를 지운다. callback은 바이트를 읽기 전용으로 사용하고 참조를 외부에 보존하지 않는다. Use/Close 경합은 race detector 테스트로 검증한다.

HTTP/CLI는 비밀을 별도 command 필드의 secret.Input으로 변환하고 작업 반환 시 Close한다. command 전체를 로깅하지 않는다. encrypted secret에는 OwnerKeyID·Purpose·FormatVersion·EncryptionGenerationID·Nonce·Ciphertext가 있으며 AAD를 검증해 다른 레코드로 옮긴 암호문을 거부한다.

```go
// internal/app/port: 공개키는 domain.PublicKey, 암호문은 domain.EncryptedSecret.
type KeyEngine interface {
    Generate(context.Context, KeySpec) (GeneratedKey, error)
    ImportCA(context.Context, ValidatedCAKeyInput, KeySpec) (GeneratedKey, error)
    ImportTLS(context.Context, ValidatedTLSKeyInput, KeySpec) (GeneratedKey, error)
    Reencrypt(context.Context, domain.EncryptedSecret, RotationKeys) (domain.EncryptedSecret, error)
}
type CertificateSigner interface {
    Sign(context.Context, CertificateSigningRequest, domain.EncryptedSecret) (domain.Certificate, error)
}
type CRLSigner interface {
    SignCRL(context.Context, CRLSnapshot, domain.EncryptedSecret) (SignedCRL, error)
}
```

KeySpec은 발급 전에 정한 KeyMaterialID·Algorithm·Purpose를 포함한다. GeneratedKey에는 PublicKey와 EncryptedSecret만 있으며 평문 키가 app에 반환되지 않는다. Root 자체 서명도 생성한 CA 암호문으로 Sign을 호출한다. 서명 어댑터는 해당 secret 목적이 ca_signing/bootstrap_ca인지 검사하고 callback 수명 안에서만 복호화한다. TLSInstaller는 internal_tls 목적만 받는다.

DeliveryEncoder는 leaf_delivery 암호문만 허용하며 검증된 delivery·인증서와 동일 공개키인지 확인한다. 일반 CA/내부 TLS 키를 입력으로 주면 포맷 변환 전에 거부한다. PKIParser는 지원 형식·암호화 조합만 받아들이며 라이브러리의 더 넓은 지원 목록을 그대로 노출하지 않는다. 임의 OID나 scrypt로 자동 fallback하지 않는다.

Login/CSRF/DownloadLink/ResetLink처럼 원문을 반드시 전달하는 결과는 해당 필드만 secret.Input으로 보유한다. HTTP·CLI mapper는 Use callback 안에서 응답을 작성하고 반환 후 닫는다. 일반 json.Marshal(result)로 비밀 결과를 직렬화하지 않는다. 전송 실패 뒤 서버가 원문을 재조회하는 경로도 만들지 않는다.

TokenCodec은 32바이트 암호학적 난수를 base64url(패딩 없음)로 발급하고 SHA-256 해시만 저장한다. 결과 원문은 로그인/링크 생성 응답의 전용 비밀 값으로만 전달한다. PKCS#12 암호는 수령 헤더에서 secret.Input으로 변환하며 캐시·DB·job·감사에 저장하지 않는다. 입력 크기는 기존 API 제한을 적용하고 CPU가 큰 키 생성·변환은 프로세스 전체 semaphore 2개로 제한한다. 대기 5초 초과 시 소비/발급 커밋 전에 unavailable로 반환한다.

## 7. 다운로드의 정확한 실행 API

```go
// Deliver는 payload를 반환하지 않고 소비 성공 후에만 sink를 호출한다.
func (s *DistributionService) Deliver(
    ctx context.Context,
    meta contract.RequestMeta,
    cmd contract.DownloadCommand,
    sink port.DownloadSink,
) (contract.TransferSummary, error)

type DownloadSink interface {
    Send(context.Context, FileDescriptor, io.Reader) (TransferOutcome, error)
}
```

DownloadCommand는 RawToken(secret.Input), Format, PEMPart, PKCS12Password(secret.Input)이다. RequestMeta의 Principal은 익명이며 실제 인증은 grant 해시·목적·기한으로 수행한다. Range/조건부 요청/HEAD는 HTTP 어댑터에서 정책대로 거부하고 Deliver를 호출하지 않는다.

FileDescriptor는 ContentType, 안전하게 생성한 Filename, Size만 가진다. TransferOutcome은 BytesWritten, FinishedAt, Completed를 가진다. DownloadSink는 응답 헤더 작성·전체 쓰기·가능한 flush 결과 관측을 수행한다. 헤더의 no-store/no-referrer는 고정 정책으로 설정한다. sink는 Reader를 보관·다른 goroutine으로 전달하지 않으며 Send 반환 전에 사용을 종료한다.

Deliver 실행 순서:

1. grant와 공개 자료·delivery·암호문을 읽고 초기 정책을 확인한다.
2. encoder가 메모리 payload를 완성한다. 준비 오류는 소비하지 않는다.
3. UoW에서 grant/delivery·기한·원래 key generation을 다시 확인한다. private는 transferring·임시 암호문 삭제·전체 private grant 무효화·시작 감사, public은 해당 grant 소비·시작 감사를 커밋한다.
4. Write 성공 뒤에만 payload Reader를 sink.Send에 전달한다. 여러 동시 요청 중 commit 패자에게는 sink 호출이 없다.
5. Send가 반환하거나 panic하면 payload를 정리한다. 서버 runtime 수명에서 분리한 최대 5초 후처리 context로 결과를 기록한다. private 실패는 같은 commit에서 폐기·CRL 작업을 기록한다. public 실패는 감사만 기록한다.
6. private 후처리 실패/미확정은 RuntimeGate.FailClosed를 호출해 신규 요청·worker를 즉시 닫고 최대 30초 정리 후 비정상 종료한다. transferring을 다음 시작의 복구 대상으로 남기며 프로세스가 살아 있는 채 일반 서비스를 재개하지 않는다. public 후처리 실패는 키 폐기를 만들지 않고 정제된 오류를 운영 로그에 남긴다. 이미 보낸 HTTP 본문 뒤에 JSON 오류를 덧붙이지 않는다. 핸들러는 responseStarted를 추적한다.

TransferSummary는 비밀 없는 tokenID/deliveryID·서버 관측 결과다. 클라이언트가 재호출할 수 있는 CompleteTransfer API는 만들지 않는다. 관리자 저장 실패 신고만 기존 ReportFailure 경로로 받는다. 성공 전송 후 갱신을 허용하려면 server_completed 기록이 먼저 완료돼야 한다.

## 8. 대표 변경 작업의 커밋 규칙

| 작업 | 트랜잭션 밖 준비 | 단일 Write 안에서 수행 |
| --- | --- | --- |
| 최초 관리자 | 비밀번호 정책 검사·해시 | installation 미설정 재확인, 계정 생성·설정 단계 변경·감사 |
| 로그인 | 저장된 비밀번호 해시로 비교·새 세션 난수 준비 | 계정/자격 증명 version 재확인, active·epoch 확인, 세션 저장·감사 |
| 재설정 시작 | 새 토큰 난수 | 계정 reset_pending·epoch 증가·모든 세션 삭제·링크 교체·감사 |
| 재설정 완료 | 새 비밀번호 해시 | 계정·토큰·기한 재확인, 해시·epoch·active 변경·모든 링크/세션 무효화·감사 |
| Leaf 발급/갱신 | snapshot→계획→필요시 키 생성→서명 | 인증·기존 결과 우선 확인, 기대 version·issuer/키/수령/폐기 검사, serial 검사, 계보·인증서·암호문·delivery·요청 결과·감사 |
| CA 생성 | parent snapshot, 새 키·CA 서명 | parent 권한·상태·기간 재확인, CA/키/인증서·CRL 상태·요청 결과·감사 |
| import | 파싱·해제·체인 검증·키 암호화 | 현재 중복/충돌·권한·미리보기 지문 재확인, 자료·폐기·인수·결과·작업·감사 |
| 긴급 전환 | 권한 범위 조회, 입력 검증 | source 하위 발급 중지·영향 목록·전환 생성·Intermediate라면 부모 폐기·작업·감사 |
| 일반 폐기 | 입력 정규화 | 현재 상태 확인, 공통 폐기 변경 함수 |
| CRL 생성 | 준비 없음 | 번호 예약·폐기 snapshot·generation 캡처 |
| CRL 게시 | 예약 snapshot과 CA 암호문으로 서명 | signer 여전히 사용 가능 확인, 번호/세대 비교·게시본 저장·후속 작업·감사 |

CRL snapshot 예약은 번호와 목록을 같은 순간의 상태로 캡처한다. 실패한 예약 번호는 되돌리지 않는다. 게시 이전에 새 폐기가 추가되면 새 작업 요구를 남기고 기존 작업 완료로 지우지 않는다. CA 신규 발급 stopped 상태만으로 CRL 서명을 금지하지 않는다.

기대 version 검사보다 기존 성공 요청 결과 재생이 먼저다. 다만 현재 인증/권한이 없는 요청은 기존 결과도 받지 못한다. 설정 snapshot이 준비 후 바뀌었으면 신규 작업은 재계산하고, 이미 성공한 요청의 재생은 당시 결과를 유지한다. SAN·서명 정책의 중대한 사실이 바뀐 준비 결과는 버리고 다시 준비한다.

serial은 서명 전 생성하고 commit에서 certificates·revocations 양쪽과 충돌 검사한다. 충돌은 같은 요청 ID로 새 serial을 만들어 제한 재준비할 수 있다. 이미 서명된 DER의 serial 필드를 수정하지 않는다. 응답은 commit 전 노출하지 않는다.

## 9. TLS·복구·백그라운드 작업

TLSService는 후보 준비와 활성화를 분리한다. 준비한 후보를 TLSInstaller.Prepare에 넣어 실제 적용 가능한 메모리 설정을 먼저 만든다. Activate는 프로세스 내 TLS 변경 mutex 아래 version 재검사 → DB committed 기록/활성 포인터 변경 → Installer.Apply → DB applied 기록 순서다. Apply 실패는 DB/메모리 모두 원복한다. applied 기록 실패를 포함한 불명확한 변경은 일반 서비스 재개를 막고 Reconcile로 판단한다.

Reconcile은 prepared 후보는 활성화하지 않고, committed 상태는 저장된 후보를 다시 검증해 적용한 뒤 applied로 완결한다. 후보가 사용할 수 없으면 이전 정상 버전을 검증해 rollback한다. 둘 다 불가능하면 maintenance 상태다. 기존 외부 파일의 현재 내용은 복구 중 자동 불러오지 않는다. DB의 검증된 snapshot만 사용한다. 정상 적용 후 참조가 없어진 bootstrap 비밀 키를 삭제한다.

worker는 기본 1개 실행 루프로 시작하고 키 생성 semaphore와 별개다. due job을 claim할 때 5분 lease·version을 기록한다. 장기 작업은 1분마다 version 확인 후 lease를 연장한다. 전체 프로세스 종료 후 lease 만료 작업은 다시 실행할 수 있다. CRL은 CA 키별 dedup_key로 요구 generation을 병합한다. 완료 시 처리한 generation보다 새 요구가 있으면 pending으로 남긴다.

수령 만료 스캔은 매분, 감사 정리는 하루 한 번, CRL은 저장된 next_publish_at에 따른다. 처리 batch는 100개이며 각 수령 실패 변경은 독립 트랜잭션으로 처리한다. 요청 자체의 만료 검증은 배치 실행을 기다리지 않는다. 초기 재시작 복구에서 transferring을 failed로 바꾸는 동안 다운로드/갱신 요청을 열지 않는다.

MaintenanceService.Rotate는 RuntimeGate가 보장한 오프라인 상태에서만 실행한다. 외부 Secret 파일을 변경하지 않고 UoW 하나로 암호문·verifier·키 세대를 바꾼다. FinalizeRestore는 세션/토큰 무효화·대기 키 삭제/폐기와 필요한 CRL 작업을 먼저 커밋하고 영속 복구 단계로 추적한다. 보관 전용 키 없는 CA는 게시 필수 대상에 포함하지 않는다.

## 10. 오류·취소·리소스 해제

AppError는 Code, Kind(validation/auth/forbidden/conflict/unavailable/commit_unknown), PublicFields를 갖고 내부 cause는 응답/로그에 원문 출력하지 않는다. HTTP 상태 매핑은 adapter/http, CLI 종료 코드 매핑은 cmd가 소유한다. conflict는 자동 재시도 허가를 뜻하지 않으며 버전 불일치와 저장소 경합을 구분한다.

각 메서드는 소유한 secret/payload에 즉시 defer Close를 설정한다. 요청 취소가 commit 전에 발생하면 외부 결과 없이 rollback/정리한다. commit 뒤 취소는 업무가 이미 실행됐을 수 있으므로 일반 발급은 기존 요청 결과로 확인하고, 개인키 수령은 실패/복구 규칙으로 처리한다. Runtime.Shutdown은 신규 요청·worker를 닫고 진행 중 전송의 후처리까지 최대 30초 허용한 뒤 저장소/키 어댑터를 닫는다.

## 11. 테스트와 구현 순서

메모리 저장소는 서비스 테스트용으로만 사용한다. UoW 대역은 copy-on-write로 callback 실패 시 전체 rollback을 구현하며 트랜잭션 없이 각 메서드를 즉시 반영하는 단순 map mock을 사용하지 않는다. 시계·난수·서명·sink는 결정적 대역으로 교체한다. 실제 SQL 어댑터는 별도의 네 DB 계약 테스트를 통과해야 한다.

| 첫 구현 단계 | 추가할 파일/작업 | 통과해야 할 검증 |
| --- | --- | --- |
| B01 도메인 | domain 값 타입·LeafSeries·Delivery·Account·폐기/CRL 정책 | 주기 3의 0→1→2→새 키0, 기간 초과 거부, terminal 수령 복원 금지, reset 만료 후 로그인 차단 |
| B02 앱 계약 | contract DTO·port·UoW 대역·오류·secret | 잘못된 ID/소속 거부, 비밀 JSON/로그 차단, 트랜잭션 rollback |
| B03 대표 서비스 | IssuanceService·DistributionService·Revocation 공통 함수 | 중복 요청 한 번 반영, commit 패자 sink 0회, 인코딩 실패 무소비, 전송 실패 폐기·job·감사 동일 커밋 |
| B04 나머지 서비스 | Identity/Setup/Authority/Import/Transition/CRL/TLS/Query/Maintenance | 아래 U01~U16 시나리오를 서비스 대역에서 검증 |
| B05 어댑터 연결 | SQL·crypto·TLS·runtime·설정·migration | 실제 암호 형식과 네 DB 원자성·잠금·복구 검증 |
| B06 진입점·통합 | HTTP/HTML·local CLI·worker·Docker | OpenAPI 입출력 일치, 초기 HTTPS부터 발급·수령·폐기 전체 흐름 |

B01~B04는 백엔드 규칙과 협력 관계를 구현하는 단계다. 마이그레이션 실행기를 먼저 완성할 필요가 없다. B05에서 기존 SQL/실행기 문서를 서비스 저장 계약에 맞춰 연결한다. B06 전에 공개 배포용 서버가 완성됐다고 표시하지 않는다.

추가 필수 서비스 시나리오:

- U01~U04: 첫 계정 생성 경쟁 한 번 성공, 로그인 준비 중 reset 시 세션 생성 거부, 재설정 완료 토큰 한 번 소비, 설정 변경이 기존 수령 기한을 연장하지 않음.
- U05~U06: CA private download 불가, issuer stopped/유출/만료 시 발급 거부, 일반 갱신에 Leaf 개인키 조회 0회, CA 이동만으로 횟수 초기화 없음.
- U07~U08: 링크 교체 후 기존 링크 거부, private terminal 수령 복원 없음, public 실패는 폐기 0건, 소비 commit 실패·미확정 시 Send 호출 0회.
- U09~U10: 유출 공개키의 유효 인증서 모두 폐기, 동일 DER 반환/다른 DER 같은 SPKI import 거부, preview 이후 충돌 재검사, 인증서 없는 폐기 이력 보존.
- U11~U12: 긴급 신고 후 새 발급 차단, 긴급 Leaf 항상 새 키, 상위 영향이 자동 개별 폐기로 표시되지 않음, CRL 완료 순서 역전·생성 중 새 폐기에도 게시 후퇴 없음.
- U13: TLS 후보 검증 실패는 활성 버전 불변, Apply 실패 원복, committed 중단 재시작 복구, 일반 Leaf delivery 생성 0건.
- U14~U16: 복수 scope 감사 접근 검증, 감사 정리 후 PKI 이력 보존, lease 재실행 멱등성, rotate 실패 시 전체 기존 암호문 유지, restore 대기 키 삭제와 게시 필요 범위 준수.

이 문서의 선택을 다시 기획 질문으로 돌리지 않는다. 함수 내부 알고리즘·파일 분할·네 DB SQL 차이·구체 테스트 fixture는 개발자가 결정한다. 사용자에게 돌아가야 하는 변경은 개인키 재수령 허용, 인증/권한 완화, 새로운 외부 배포 자동화처럼 이미 확정한 제품 동작을 바꾸는 경우다.


## 12. 보안 검토 후 구현 확정 사항

- RuntimeGate에 `FailClosed(code string)`을 추가한다. 멱등·비차단 호출로 먼저 신규 요청과 worker admission을 원자적으로 닫고 runtime 종료를 요청한다. 핸들러가 자신의 종료를 기다리는 데드락을 만들지 않는다. 자동 재개하지 않으며 진행 중 요청 취소/응답 닫기·후처리·최대 30초 종료를 runtime이 소유한다. 전송 Send의 최대 60초 deadline도 종료 시 남은 30초 이하로 줄인다. DB 연결을 바꿔 후처리하는 우회는 없다.
- private 소비 commit 미확정 또는 소비 후 Send panic에서 후처리를 끝내지 못한 경우도 FailClosed 대상이다. 확정 rollback으로 소비가 없었던 경우는 payload만 지우고 반환한다. 후처리가 확정 성공하면 추가 폐기하지 않는다. 재시작 복구 commit이 실패하면 다운로드/발급 요청을 열지 않는다. 이전 프로세스가 잠금을 완전히 반납하기 전 다른 프로세스가 시작하지 않는 기존 규칙을 유지한다.
- 인코딩/전송/비밀번호 KDF와 import의 자원 상한은 [HTTP 계약](./api-contract.md), [운영 정책](./architecture.md), [import](./pki-import.md)를 따른다. 해시·복호화 admission은 비싼 계산 전에 검사하고 임의 중첩 작업이 semaphore를 두 번 획득하지 않게 한다. PasswordHasher는 지원 프로필 외 DB 파라미터를 실행하지 않는다.
- ImportService는 typed ImportMetadata 입력과 별도의 PublicImportManifest/TakeoverEvidence 저장 타입을 사용한다. manifest는 파서가 만든 공개 Facts에서 생성하고 repository에 input command를 전달하지 않는다. OpenAPI ImportManifest/TakeoverEvidence의 필드만 매핑한다.

- B03 필수 테스트에 Send 성공/실패 × 후처리 rollback/commit_unknown, FailClosed admission 차단, 재시작 시 저장된 completed 유지/잔류 transferring 폐기를 추가한다. timeout 후 background 계산을 방치하지 않는 자원 해제도 확인한다. B05는 KDF 상한 사전 거부와 실제 상한 입력 비용, B06은 프록시 로그·IP 체인·CSRF origin·CSP/HTMX·재설정 URL 제거를 검증한다.

## 13. B02 계약 검토 확정 사항

설계 변경은 기획 담당자가 문서를 직접 수정하고 해당 개발 브랜치에 커밋·푸시한 뒤 PR에 커밋과 적용 범위를 알린다. 개발팀은 같은 문서를 별도로 재작성하지 않고 확정된 계약의 코드·테스트를 구현한다. 판단 요청은 한 번에 모아 제시하고, 확정 전에는 해당 부분의 임시 구현·매핑 테스트를 확대하지 않으며 독립적인 작업을 진행한다. 기획 리뷰는 재현 조건과 기대 동작을 전달하고 제품 코드 수정은 개발팀이 맡는다. 명칭·파일 분할 같은 제품 동작을 바꾸지 않는 구현 선택은 개발팀이 결정한다. 새 결정이 기존 요청을 대체하면 PR에서 대체 관계를 명시한다.

PR #2의 설계 질문에 대한 결정이다. §4의 축약 목록은 메서드의 상한이 아니다. 서비스가 TxStores만으로 필요한 사실을 읽고 결과를 저장할 수 있어야 하며, 대역 내부 map에 직접 fixture를 넣어야만 가능한 정상 업무 흐름은 계약 완성으로 인정하지 않는다.

1. 전환 상태는 OpenAPI·SQL의 `in_progress → externally_completed → closed`를 도메인에도 사용한다. 후속 CA 선택 여부는 nullable TargetAuthorityID로 표현한다. SetTarget은 in_progress 안에서 수행한다. Complete는 기존 영향 처리·수동 외부 배포 확인 조건을 검사해 externally_completed로 옮긴다. closed는 원본 CA의 게시 종료 조건까지 충족한 상태이며 Complete만으로 추정하지 않는다. CRL 종료와 연결하는 별도 도메인 전이가 필요하다. 기존 reported/target_set/completed의 단순 전단사 매핑은 사용하지 않는다. 서비스 연결은 B04에서 구현하되 B02 계약에서 상태 의미를 통일한다.
2. 배포 확인은 `certificate_installed`로 통일한다. 지정한 인증서와 대응하는 키를 대상에 설치했다는 관리자의 수동 확인이다. 같은 키를 재사용한 정상 갱신에도 기록할 수 있으며 항상 새 키를 만들었다는 뜻은 아니다. 긴급 전환의 새 키 필수 조건은 발급 정책에서 별도로 검사한다. 도메인의 cert_key_replaced 명칭도 이 의미에 맞춘다.
3. GetIssuerForUpdate는 저장된 Authority를 반환한다. app이 요청 기간·intent·인수 확인으로 IssuerContext를 구성하고 트랜잭션 안에서 CanIssue를 다시 검사한다.
4. PKIParser는 인증서 PEM/DER 묶음, CRL PEM/DER, CA 개인키, 내부 TLS 개인키를 구분하는 typed 입력/출력 메서드를 제공한다. 인증서/CRL 출력은 공개 facts이며 CRL의 issuer·서명 검증에 필요한 정보·번호·기간·폐기 항목을 포함한다. 파서가 DB ID나 issuer 관계를 임의 생성하지 않고 app이 검증 후 연결한다. 키 입력은 secret.Input이고 CA/internal_tls 목적과 인증서 공개키 일치를 검증한다. 검증된 키 입력은 호출자가 KeyEngine.Import 후 Close하며, 중간 실패 시 파서가 이미 만든 비밀을 닫는다. 일반 leaf 개인키 import는 허용하지 않는다. 포맷·암호화·자원 상한은 §6과 pki-import를 따른다.
5. Query.ListAuthority/GetAuthority, ListSeries/GetSeries, ListCertificate/GetCertificate, ListRevocation/GetRevocation, ListTransition/GetTransition, ListImport/GetImport, ListJob/GetJob, ListAudit/ExportAudit, GetCRLStatus/ReadPublicCA를 각각 별도 Action으로 선언한다. 실제 API에 없는 단일 Audit 조회는 신설하지 않는다. TLS.Bootstrap과 TLS.Reconcile도 별도 Action이며 대응 내부 operation만 허용한다. 미정의 Action은 거부한다.
6. idempotency input hash v1은 작업별 전용 typed 정규화 DTO의 Go encoding/json 바이트를 SHA-256으로 계산한다. envelope에 schema_version=1, operation, path 대상 ID와 모든 검증된 업무 입력을 포함한다. UUID/지문은 소문자, 시간은 UTC 마이크로초로 정규화한다. SAN은 domain 정규화 후 type/value 순 정렬·중복 제거하며 나머지 문자열은 업무 정책 외 임의 trim/case folding을 하지 않는다. 선택값 생략은 명시값과 구별해 보존한다. 설치 기본값 적용 전에 해시를 계산하고 첫 실행의 해석값은 결과에 저장해 설정 변경 이후에도 같은 요청을 재생한다. actor와 idempotency key는 조회 키이며 trace RequestID/IP/세션 토큰/If-Match는 해시에서 제외한다. import는 파일 ID 순 정렬한 공개 manifest의 종류·원본 파일 SHA-256·issuer 연결 및 CA 지문 순 정렬한 takeover 입력을 포함하며 passphrase·개인키 원문은 제외한다. command 전체를 무차별 직렬화하지 않는다. 입력이 다르면 conflict, 같으면 기대 version 검사 전에 성공 결과를 재생한다. B03은 작업별 필드 변경·생략·설정 변경 후 재생 테스트를 갖춘다.
7. ImportBatchID·TakeoverID 추가를 승인한다. 다른 저장 엔티티 ID와 동일한 UUID 검증을 적용한다.

B02 재검토에서 version 없는 행의 잠금 방식을 확정한다. SaveLeafKeyGeneration(generation)은 별도 expectedVersion 없이 유지하며 version 컬럼을 추가하지 않는다. app은 같은 Write에서 GetSeriesForUpdate로 부모 Series와 현재 키 세대를 잠그고 소속·현재 세대를 재검사한 뒤 SaveLeafKeyGeneration과 SaveSeries(expectedVersion)를 함께 커밋한다. 두 저장의 호출 순서와 무관하게 Series 충돌 시 전체를 rollback한다. 트랜잭션 밖에서 읽은 generation을 그대로 저장하지 않는다. SaveSession/SaveResetToken 역시 같은 Write에서 최신 행을 잠그고 도메인 전이 후 저장하며, Account 잠금·epoch·상태 검사를 함께 수행한다. SQL 어댑터는 이 행 잠금 계약을 구현해야 한다.

로그인 이름은 Credentials의 ASCII 문자·길이 검증을 먼저 적용하고 NormalizeLoginName의 ASCII 소문자화를 생성·조회에 공통 적용한다. 공백이 포함된 외부 입력을 정규화로 구제하지 않는다. 키 유출 반복 보고는 이른 compromised_at을 보존하는 구현을 승인한다. 시각은 0이 아니어야 하고 유출 표시가 설정되면 시각과 무관하게 즉시 발급/재사용을 차단한다. 과거 인증서의 신뢰 구간을 서버가 자동 판정한다는 의미는 아니다. Import Preview는 batch를 영속화하지 않으며 Commit의 결과 batch는 write-once로 유지한다. previewed 스키마 값 때문에 별도 저장 흐름을 추가하지 않는다. 실패 기록은 rollback된 업무 변경을 재커밋하지 않는 별도 오류/감사 처리 규칙을 따른다.

작업의 새 요구가 succeeded/failed 행에 도착하면 같은 행을 pending으로 재개하고 이전 lease와 재시도 지연을 정리한다. running의 새 요구는 실행 lease를 유지한다. ImportBatch/Takeover의 모든 가변 필드는 대역 입출력에서 깊은 복사를 적용해 callback rollback과 읽기 snapshot을 보장한다. TLS prepared handle은 호출자가 검증된 payload를 교체하거나 가변 설정 참조를 획득할 수 없어야 한다. 구현은 installer 내부 registry 등으로 결정하되 성공·실패·미적용 취소 시 준비 자원의 해제 경로도 명시한다.

TLSInstaller는 `Discard(prepared PreparedTLSConfig)`를 제공한다. 서비스는 Prepare 성공 직후 Discard를 defer해 DB rollback·commit_unknown·취소·panic에서도 미적용 registry 항목을 정리한다. Discard는 해당 installer가 소유한 항목만 제거하며 멱등이고, 취소된 request context에 의존하지 않으며 활성 listener를 변경하지 않는다. Apply는 handle을 한 번만 소비한다. 성공 시 registry에서 제거한 설정의 소유권을 활성 listener로 넘기고, 실패 시 registry 항목을 제거하되 기존 listener를 유지한다. 이미 소비·폐기된 handle의 재Apply는 거부한다. 성공 후 defer된 Discard는 활성 설정을 지우지 않는다. B02는 외부 패키지 대역으로 Prepare→Discard, Apply 성공/실패, 반복 Discard 및 재Apply 거부 계약을 검증하고 실제 TLS 자원 처리는 B05가 구현한다.

ListRecoveryRequired는 단일 인스턴스 재시작의 배타적 복구 경로에서 이전 프로세스가 남긴 running 작업을 모두 조회한다. 이전 lease의 시각이 아직 미래여도 복구 관찰 대상이며, 일반 worker의 ClaimDue 만료 판정과 구분한다. 살아 있는 다른 프로세스의 작업을 빼앗는 호출 경로로 사용하지 않는다. Takeover의 CAKeyGenerationID는 생성 후 업무적으로 불변이다. 정상 ConfirmTakeover는 이 식별자를 바꾸지 않으며 저장소의 변경 거부는 방어적 불변 조건 보강으로 다룬다.

저장소 대역도 실제 port 계약을 따른다. TLS.SetActive는 installation.version을 검사하고 활성 TLS ID와 version을 원자적으로 갱신한다. jobs는 실행 중에도 dedup_key당 한 행을 유지하고 새 요구 병합 시 version을 올리며, 만료된 running lease를 재획득한다. 경합 오류는 SQL과 대역이 공유하는 port 계약으로 식별 가능해야 한다. TLS prepared 값은 다른 패키지의 어댑터와 테스트 대역이 만들 수 있는 opaque handle로 표현하고 Apply에서 소유 installer·유효성을 검사한다. private 입력과 복호화된 다운로드 payload에도 비밀 JSON 거부·로그 redaction·명시적 수명 계약을 적용한다.

계약 완결성 검토에는 로그인 이름 조회·rate-limit 읽기·세션 만료 갱신·reset token 소비 저장, import batch/takeover 저장·조회, PKI의 키 유출 표시·ID 기반 조회도 포함한다. 범용 raw SQL 우회 대신 소비 서비스가 필요한 typed port를 추가한다. 서비스 본체 구현을 B02에 앞당긴다는 뜻은 아니다.

## 14. B03 서비스 계약 확정 사항

PR #3의 질문 번호에 대응한다. 기존 HTTP·수명 정책에서 이미 정한 동작은 그대로 구현하고, 아래 port 보완은 B03 서비스와 대역까지 함께 반영한다. 실제 암호화·SQL·HTTP 어댑터의 구현 단계는 앞당기지 않는다.

1. **수령 실패 폐기:** 전송 실패·수령 만료·잔류 transferring 복구의 기본 reason은 unspecified, source는 cascade로 확정한다. cascade는 시스템 정책에 따른 파생 폐기를 포함한다. 실제 키 유출 신고만 key_compromise를 사용하며, 더 강한 기존 폐기 사유를 낮추지 않는다. 감사 action/failure_code로 transfer_failed·delivery_expired·interrupted_transfer 원인을 구별한다. 새로운 CRL reason이나 DB enum은 추가하지 않는다.
2. **고정 체인과 저장 관계:** PKIRepository에 GetCAKeyGeneration(id), GetLeafCertificateRecord(certificateID), GetCACertificateRecord(certificateID) 및 해당 subtype 저장 계약을 추가한다. leaf_certificates/ca_certificates의 issuer_ca_certificate_id를 따라 대상 인증서부터 self-signed Root까지 연결하고, 그 당시 경로를 유지한다. 현재 Authority.IssuanceCertificateID나 management_parent로 과거 체인을 대체하지 않는다. subtype은 data-model의 series/key generation/previous certificate/operation/policy snapshot 등 기존 필드를 보존하며 인증서·subtype·계보 변경을 같은 Write에 저장한다. app의 공통 조회 함수가 이 typed port로 chain을 구성한다. 누락·순환·issuer 키 불일치는 인코딩 전에 오류이며 빈 chain으로 성공하지 않는다. 내부 ChainDER는 대상 인증서를 제외한 issuer→Root 순서다. 공개 PEM part=chain은 대상→Root, ZIP의 certificate.pem은 대상, chain.pem은 issuer→Root다.
3. **공개 인코딩:** PublicCertificateEncoder.Encode(ctx, input) → EncodedBundle을 Distribution에 주입한다. 입력은 대상 Certificate, ChainDER, Format, PEMPart의 공개 자료만 갖고 비밀/복호화 의존성이 없다. PEM은 실제 CERTIFICATE PEM, ZIP은 certificate.pem과 chain.pem으로 인코딩한다. DER를 그대로 보내고 PEM/ZIP이라고 표시하는 구현은 허용하지 않는다. private DeliveryEncoder의 leaf_delivery 목적 제한은 유지한다. 포맷 선택·실패 시 무소비는 서비스 대역으로 검증하고 실제 형식 호환성은 B05에서 검증한다.
4. **공개 PKCS#12:** api-contract의 기존 규칙대로 거부한다. public은 PEM certificate/chain 또는 공개 ZIP만 허용한다. private는 private_key PEM·키/인증서/체인 ZIP·PKCS#12를 허용한다. 금지 조합은 소비 전에 거부한다. 새 공개 PKCS#12 형식을 설계하지 않는다.
5. **공개 후처리 오류:** OperationalLogger.Record(event)를 Distribution에 필수 주입한다. typed event에는 정해진 code, request ID, grant/delivery/certificate ID, 처리 단계만 넣고 원문 error·URL·token·개인키·입력 command를 넣지 않는다. Record는 context 취소에 의존하지 않는 best-effort 비차단·비panic 계약이며 업무 성공/실패를 뒤집는 오류를 반환하지 않는다. 공개 후처리 실패를 여기 기록하고 추가 JSON 응답·개인키 폐기는 하지 않는다. 운영 로그는 감사 DB의 대체 성공 기록이 아니다.
6. **다운로드 감사 scope:** 일반 Leaf 다운로드 이벤트의 scope는 leaf subtype→Series.ManagementAuthorityID 한 개로 저장한다. 상위 관리 Authority를 동일 이벤트의 추가 scope로 복제하지 않는다. 장기 ACL에서 Root 관리자의 하위 감사 접근은 저장된 management_parent 관계에 따른 권한 상속으로 판정한다. 복수 scope는 모든 관련 범위의 권한을 요구하므로 조상을 추가하면 Intermediate 관리자의 자기 범위 조회까지 막게 된다. 현재 MVP도 scope를 비워 저장하지 않는다. 인증서의 역사적 발급 체인은 2번 경로로 별도로 구하고 관리 관계와 혼용하지 않는다. 전환으로 여러 CA가 관련된 작업은 기존 복수 scope 감사 규칙을 적용한다. 성공/실패/복구 감사에서 동일한 관계 기반 scope를 사용하며 caller가 넘긴 AuthorityID를 신뢰하지 않는다.
7. **시간과 저장 결과:** domain.Instant에 이 문제를 우회하기 위한 범용 JSON marshaller를 추가하지 않는다. HTTP 시간은 전용 mapper의 UTC 문자열, 저장 replay DTO는 명시적인 UTC UnixMicro 필드를 사용한다. nullable 시각은 포인터/null로 보존한다. 저장 DTO는 schema_version=1을 포함하고 알 수 없는 version·손상된 값은 오류로 처리한다. domain 객체의 비공개 필드를 json.Marshal로 저장하지 않는다. 재생 시 인증서 식별자·발급 당시 정책은 유지하되 수령 상태는 현재 저장값으로 조회한다.
8. **Settings JSON v1:** service_settings.schema_version=1의 settings_json은 OpenAPI Settings에서 version을 제외한 필드명/구조를 사용한다. leaf_validity/root_validity/intermediate_validity는 각각 {value,unit}, 나머지는 service_url, rotate_every, private_delivery_seconds, public_link_seconds, crl_interval_seconds, crl_validity_seconds, audit_retention_days다. 공통 typed codec을 만들어 B03 읽기와 B04 쓰기가 공유한다. 저장 시 기본값을 모두 해석해 완전한 snapshot을 저장한다. 평탄화된 leaf_validity_value/unit은 사용하지 않는다. 알 수 없는 schema version·깨진 JSON·누락/범위 오류를 공장 기본값으로 덮지 않는다. 초기 미설정은 Setup의 명시적 초기화 경로로만 처리하며 운영 발급은 검증된 snapshot을 요구한다. 설정 version이 준비 후 바뀌면 commit 전에 다시 준비하되 이미 성공한 요청 재생에는 현재 기본값을 덮지 않는다.
9. **서명 CA 키 조회:** Authority.CAKeyGenerationID→GetCAKeyGeneration→KeyMaterialID→ca_signing secret 경로로 명시한다. 선택한 issuance CA 인증서의 CA key generation/key material 일치, 키 파기·유출·인수·issuer 상위 차단 상태를 준비와 commit에서 확인한다. CA 인증서는 issuer DN/확장/유효기간 검증용이며 세대 행 조회를 대신하지 않는다. bootstrap은 별도 허용 intent에서 bootstrap_ca 목적을 사용한다.
10. **서명 입력:** CertificateSigningRequest는 Plan, CertificateID, KeyMaterialID, SubjectPublicKey, Serial, Kind, CreatedByAccountID, IssuerCertificate, CRLDistributionPoints를 명시한다. IssuerCertificate는 일반 발급에서 선택한 CA 공개 인증서이고 Root 자체 서명에서만 생략 가능하다. SubjectPublicKey는 신규 생성 결과 또는 GetKeyMaterial로 읽은 기존 공개키이며 재사용 갱신에 leaf 개인키를 요구하지 않는다. SerialGenerator.NewSerial(ctx) → domain.SerialNumber를 주입해 서명 전에 serial을 정하고, 기존 정책에 맞는 암호학적 난수 serial을 만든다. signer는 지정된 ID·serial·키·정책에 맞는 domain.Certificate를 반환하며 DER와 해석 필드의 일치를 보장한다. app은 반환 ID/serial/issuer/window/subject/SAN/kind/profile/algorithm이 요청과 일치하는지 검사하고 불일치는 오류로 처리한다. 반환 DER에 관계없는 metadata를 다시 조립해 성공으로 만들지 않는다. B03은 recording signer 대역으로 public key·ID·serial 전달과 불일치 거부를 검사하고 B05는 실제 DER 공개키·서명·확장을 대조한다. serial 충돌만의 재시도는 같은 요청과 키에 새 serial을 사용해 다시 서명한다. TLS 내부 발급에도 같은 입력 계약과 SerialGenerator를 사용한다.


### 14.1. B03 후속 질문 확정

- 일반 갱신의 leaf_certificates.operation은 동일 키 재사용이면 renew, 키 교체이면 rekey다. 명시적인 CA 전환 및 긴급 전환 서비스에서는 각각 migrate/emergency를 사용하며, 키 교체 여부만으로 전환 작업의 의미를 덮지 않는다.
- 운영 Leaf의 CRLDistributionPoints는 검증된 Settings.service_url의 끝 슬래시를 제거한 값에 `/pki/ca-certificates/{issuer_certificate_id}/crl.der`를 붙인 단일 절대 URL이다. 이는 api-contract의 기존 공개 경로이며 `/api/v1`을 삽입하지 않는다. issuer_certificate_id는 이번 서명에 선택한 CA 인증서 ID이며 Leaf 자신의 ID나 Authority ID가 아니다. service_url에 설치 경로가 있으면 보존하고 사용자 정보·query·fragment·빈 host를 허용하지 않는다. 이 URL의 서버 조회는 해당 CA 인증서의 키 세대에 속한 최신 published CRL을 반환한다. 과거 인증서의 URL과 issuer 링크는 CA 인증서 선택 변경 이후에도 유지한다.
- 최초 발급·갱신·serial 충돌 재서명 모두 같은 준비 snapshot의 CRLDistributionPoints를 signer에 전달한다. 운영 Leaf에서 빈 목록으로 서명하지 않는다. 설정 변경 시 기존 재준비 규칙을 적용하고, B03에서는 recording signer로 URL 및 재시도 시 보존을 검사한다. 실제 X.509 확장 인코딩은 B05에서 검증한다. 자체 서명 Root/bootstrap의 별도 정책에 이 Leaf 규칙을 무조건 적용하지 않는다.
- 서비스 설정 행이 아직 없는 발급 요청은 conflict(`issuance_settings_not_configured`)로 거부한다. 저장된 설정의 손상·지원하지 않는 schema는 unavailable로 구분하며 기본값으로 복구하지 않는다.
