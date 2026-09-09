# MVP API 계약

[데이터 모델](./data-model.md)의 업무 작업을 HTTP에 매핑한 설계다. 경로·필드·상태 코드와 실패 동작을 정의하며 [실제 OpenAPI 파일](../api/openapi.json)을 작성했고 핸들러는 아직 구현하지 않았다. HTML/HTMX 화면과 JSON API는 같은 서비스 계층을 호출한다.

## 공통 규칙

- 관리 API 접두사는 `/api/v1`. JSON은 UTF-8, 필드는 snake_case, ID는 UUID 문자열, 시각은 UTC RFC 3339 문자열이다. DB의 마이크로초 정수는 외부에 노출하지 않는다.
- 일련번호·CRL 번호는 데이터 모델과 동일한 hex 문자열이다. `serial_hex`, `number_hex`처럼 필드에서 표현을 명시한다.
- 단일 결과는 `{ "data": ... }`, 목록은 `{ "data": [...], "next_cursor": null }`. 목록은 기본 50, 최대 200개이며 `(created_at,id)` 기준 커서 페이지네이션을 사용한다. 감사는 `(occurred_at,id)` 기준이다. 커서는 권한 증명이 아니며 매 요청 필터·권한을 다시 적용한다.
- POST 생성 성공은 201, 조회·수정·동일 요청 재생은 200, 본문 없는 성공은 204, 비동기 CRL 작업 접수는 202다. 발급 성공과 CRL 게시 성공을 동일시하지 않는다.
- JSON의 알 수 없는 필드는 422로 거부한다. HTTP 메서드 오용은 405, 본문 크기 초과는 413이다. 기본 JSON 최대 1 MiB, import·TLS multipart 전체 최대 16 MiB·100개 파일, 개별 파일 최대 4 MiB로 제한한다. 스트림을 제한하며 평문 개인키를 임시 파일에 기록하지 않는다.
- 일반 관리자 API는 DB 세션과 CSRF 검증을 사용한다. 쿠키는 `__Host-certme_session`, Secure·HttpOnly·SameSite=Strict·Path=/이다. CORS는 기본 비활성화한다.
- 상태 변경은 `X-CSRF-Token`과 Origin 검증을 요구한다. 로그인·최초 관리자 생성도 동일 출처 화면에서 받은 짧은 수명의 서명된 pre-auth CSRF 토큰으로 보호한다. 비밀번호 재설정 화면도 재설정 토큰과 별개의 CSRF 검증을 적용한다.
- 세션 생성 시 응답 본문/HTML에 CSRF 원문을 한 번 전달하고 DB에는 해시를 저장한다. 기존 세션의 화면 재진입은 새 CSRF 토큰 발급 경로를 사용하며 이전 값은 무효화된다. CSRF 재발급은 동일 출처 GET만 허용하며 `no-store`다. 브라우저 GET은 Origin이 없을 수 있으므로 Sec-Fetch-Site와 검증된 Referer를 사용하고 출처를 확인할 수 없으면 거부한다. pre-auth 토큰은 짧은 수명의 Secure·HttpOnly·SameSite=Strict 쿠키 nonce에 결합하며 이 쿠키는 초기 설정 승인 토큰이 아니다.
- 관리 응답은 `Cache-Control: no-store`. 로그는 경로 템플릿과 내부 대상 ID만 기록하며 토큰 경로·비밀번호·개인키·전용 암호 헤더를 제외한다.

오류 형식은 다음과 같다. `request_id`는 진단용이며 업무 중복 방지 키와 다르다.

```json
{"error":{"code":"delivery_not_available","message":"개인키 수령이 불가능합니다.","request_id":"...","fields":{}}}
```

| HTTP | 코드 예 | 의미 |
| --- | --- | --- |
| 400 | malformed_request | JSON·multipart 파싱 실패 |
| 401 | authentication_required, invalid_credentials | 세션 없음·만료 또는 일반적인 로그인 실패 |
| 403 | permission_denied, csrf_failed | 권한·CSRF 실패 |
| 404 | not_found, download_not_available | 대상 없음 또는 유효하지 않은 공개 토큰. 미인증 토큰 요청은 만료/소비/미존재 구분 없음 |
| 409 | issuer_stopped, delivery_not_available, duplicate_public_key, serial_conflict, idempotency_conflict, setup_closed | 업무 상태·중복 충돌 |
| 412 / 428 | version_conflict / precondition_required | If-Match 불일치 / 필수 헤더 누락 |
| 422 | invalid_profile, invalid_chain, validity_exceeds_issuer, unsupported_import | 파싱 가능하지만 정책 위반 |
| 429 | rate_limited | Retry-After 포함 |
| 503 | maintenance_mode, storage_unavailable, signing_unavailable | 서비스 재개·저장소·서명 준비 필요 |

관리자 인증 후 계정 상태 조회에는 reset_pending을 표시할 수 있지만, 로그인 실패에서 계정 존재 여부나 복구 대기 여부를 노출하지 않는다. 최초 설정 종료 여부는 공개 setup 상태의 일부다.

## 버전과 요청 재시도

수정 가능한 단일 리소스 조회는 `ETag: "v7"`처럼 version을 반환한다. PATCH, 갱신·재발급, 수령 실패 신고, CA 상태 변경·전환 완료 등 기존 상태에 의존하는 명령에는 If-Match를 요구한다. 목록 응답에는 각 항목 version을 포함한다. 토큰 GET은 별도 원자적 소비 규칙을 사용한다.

발급·갱신·재발급에는 `Idempotency-Key` UUID를 필수로 요구한다. 동일 계정·작업·키와 정규화한 본문·대상 ID가 같으면 기존 결과를 반환하고 다르면 409다. 갱신 재시도는 저장된 성공 결과를 먼저 확인하므로 첫 성공으로 바뀐 ETag 때문에 412가 되지 않는다. 권한·계정 상태는 재생 때도 검사한다. 새로운 작업은 If-Match를 검사한다.

인증서 발급 응답에는 토큰 원문이나 개인키가 없다. 결과는 `series_id`, `certificate_id`, `key_generation_id`, `renewal_count`, `key_rotated`, `delivery`(없으면 null), 관련 리소스 URL을 포함한다. 발급 성공 후 링크 생성은 별도 요청이다. 이 분리로 응답 재생이 개인키나 분실한 토큰을 다시 노출하지 않는다.

링크 생성은 새 토큰을 생성·기존 미사용 토큰을 무효화하며 URL을 그 응답에만 반환한다. 응답 손실 시 새 링크를 요청한다. 소비된 수령 권한이나 기존 기한은 복원하지 않는다.

## 설정·로그인

| 메서드·경로 | 입력 / 결과 |
| --- | --- |
| GET `/setup` | 공개 setup_stage와 임시 HTTPS 여부만 반환 |
| GET `/auth/csrf` | pre-auth 또는 현재 세션의 CSRF 토큰. 동일 출처 화면 전용 |
| POST `/setup/admin` | login_name, password → 최초 계정 생성, 자동 로그인하지 않음 |
| POST `/auth/login` | login_name, password → 세션 쿠키·CSRF 토큰·계정 |
| POST `/auth/logout` | 현재 세션 삭제, 쿠키 제거 |
| GET `/auth/me` | 계정과 세션 만료 시각 |
| POST `/auth/password-reset` | reset_token, new_password → 소비·비밀번호 변경·세션 삭제, 204 |
| GET / PATCH `/settings` | 전체 설정 조회 / 허용된 설정 필드 수정, If-Match |
| POST `/setup/complete` | 설정 version → URL·최소 한 Root·선택한 생성/import 절차 완료 검증 |

재설정 링크 화면은 `/reset-password/{token}`이며 GET은 토큰을 소비하지 않는다. 웹 API에는 재설정 링크 발급 경로가 없다. 내부 CLI만 발급하며 유효기간은 3시간이다. 설정 완료는 서명 불가능한 이력 보관용 import도 허용한다. signer 활성화는 별도 CA 조건을 검사한다.

## CA·Leaf·폐기

아래 표의 `{id}`는 해당 리소스의 UUID다. 공통 목록 필터는 q, cursor, limit이며 인증서에는 authority_id, expires_before, revoked, affected를 추가한다.

| 메서드·경로 | 입력 / 결과 |
| --- | --- |
| GET / POST `/authorities` | 목록 / kind(root 또는 intermediate), name, parent_authority_id, subject, key_algorithm, validity로 생성. Idempotency-Key 필수 |
| GET `/authorities/{id}` | 관리·발급·키·CRL·유효 상태를 분리해 반환 |
| PATCH `/authorities/{id}` | name만 수정. 상태·키를 임의 PATCH하지 않음 |
| POST `/authorities/{id}/issuance-state` | state(enabled/stopped). 키·인수·유효성·긴급 차단 검사 |
| POST `/authorities/{id}/key-destruction` | key_generation_id, justification. 종료 조건 확인 후 secret 삭제 |
| POST `/authorities/{id}/archive` | 발급 중지 및 종료 조건 확인, 공개 자료 유지 |
| GET / POST `/leaf-series` | 목록 / 초기 발급 입력. Idempotency-Key 필수 |
| GET / PATCH `/leaf-series/{id}` | 상세 / name, validity, rotate_every 수정. 기존 인증서·기한 불변 |
| POST `/leaf-series/{id}/renewals` | source_certificate_id, target_authority_id(선택), transition_id(선택). 횟수에 따라 키 유지/교체 결정 |
| POST `/leaf-series/{id}/reissues` | source_certificate_id, reason, target_authority_id(선택), transition_id(선택). 항상 새 키 |
| POST `/leaf-series/{id}/archive` | 관리 목록 보관 표시. 폐기·CRL·공개 다운로드 이력은 유지 |
| GET `/certificates` / `/certificates/{id}` | 개별 인증서 목록 / DER 지문·프로필·SAN·계보·수령·영향·폐기 상태 |
| POST `/certificates/{id}/revocations` | reason, justification → 폐기 기록과 CRL 반영 상태. 반복 동일 폐기는 기존 결과 |
| POST `/key-materials/{id}/compromise` | justification → 키 유출 기록 및 같은 키의 유효 인증서 폐기. CA 키는 긴급 전환 경로 사용 |
| POST `/key-deliveries/{id}/failure` | justification → 수령 실패 및 인증서 폐기. 자동 재발급 없음 |
| GET `/revocations` | authority_id, serial_hex 등으로 조회. 인증서 없는 항목 포함 |
| POST `/revocations/{id}/corrections` | revoked_at, reason, justification → 정정 이력 생성, 폐기 해제 불가 |
| GET `/authorities/{id}/crl` | 번호·반영 세대·게시/만료·실패 상태 |
| POST `/authorities/{id}/crl-publications` | 새 게시 작업 요청 → 202, job_id |
| GET `/jobs/{id}` | 권한 범위 안에서 상태·정제된 실패 원인 조회 |

초기 Leaf 발급 입력 예시다. subject의 허용 필드는 common_name, organization, organizational_unit, country이며 profile이 SAN·KeyUsage/EKU를 결정한다. 클라이언트 식별 이름은 common_name이다.

```json
{
  "name": "nas.internal",
  "authority_id": "<intermediate UUID>",
  "profile": "server_tls",
  "subject": {"common_name": "nas.internal"},
  "sans": [{"type": "dns", "value": "nas.internal"}],
  "key_algorithm": "ecdsa_p256",
  "validity": {"value": 1, "unit": "years"},
  "rotate_every": 3
}
```

profile은 server_tls/client_mtls/dual, key_algorithm은 ecdsa_p256/ecdsa_p384/rsa_2048/rsa_3072/rsa_4096이다. validity 단위는 years/months/days 중 하나다. 생략된 기본값은 발급 시 확정해 결과에 포함한다. 서버가 정한 공개 다운로드 정책·임시 보관 목적을 사용자 입력으로 변경할 수 없다. 갱신은 현재 프로필/SAN을 계승하며 새 인증서에서 식별 대상을 바꾸려면 새 계보를 발급한다.

reissues reason은 delivery_failed/delivery_expired/key_compromise/manual_rotation/emergency다. 실패·만료·유출은 관련 폐기 여부까지 검사·보완한다. 단순 수동 교체는 이전 인증서를 자동 폐기하지 않는다. emergency는 긴급 전환과 대상 CA를 검증하고 기존 키 사용을 거부한다.

## 다운로드

| 메서드·경로 | 인증 / 동작 |
| --- | --- |
| POST `/api/v1/certificates/{id}/download-links` | 세션+CSRF. purpose=public/private → url, expires_at, token_id. private는 해당 delivery를 사용 |
| GET `/download/{token}` | 토큰만으로 다운로드. 용도·대상은 서버 저장값으로 결정 |
| GET `/pki/ca-certificates/{id}/certificate.pem` | 인증 없이 해당 불변 CA 인증서 |
| GET `/pki/ca-certificates/{id}/chain.pem` | 인증 없이 해당 CA 인증서부터 Root까지 고정 체인 |
| GET `/pki/ca-certificates/{id}/crl.der` | 인증 없이 해당 CA 키의 최신 게시 CRL |

다운로드 query는 format=pem/zip/pkcs12, PEM은 part=certificate/chain/private_key로 선택한다. public 토큰은 PEM certificate/chain 또는 공개 ZIP만 허용한다. private 토큰은 private_key PEM, 키·인증서·체인 ZIP, PKCS#12 중 하나를 수령한다. private 토큰으로 공개 자료만 받는 조합은 422이며 소비하지 않는다. 체인에는 대상 인증서부터 Root까지 포함하고 ZIP의 별도 chain.pem은 issuer부터 Root까지 포함한다.

PKCS#12는 `X-CertMe-PKCS12-Password` 헤더를 요구한다. 대시보드는 fetch로 메모리 blob을 받은 후 저장하며 서비스 워커나 사전 가져오기를 사용하지 않는다. 헤더는 이 경로의 PKCS#12 요청에만 허용하며 모든 로그에서 제외한다.

HEAD는 다운로드 파일과 소비 없이 405다. private의 Range·조건부 요청은 400으로 거부하고 소비하지 않는다. public 토큰도 부분·조건부 응답을 지원하지 않고 전체 GET 한 번만 허용한다. 포맷·정책·토큰·기한을 확인하고 응답 생성 후 재검증·소비 커밋을 거쳐 전송한다. 오류 응답에는 파일 조각을 포함하지 않는다.

모든 토큰 페이지·응답은 no-store 및 Referrer-Policy: no-referrer다. 고정 CA 인증서는 DER 지문 ETag를 사용할 수 있다. CRL은 재검증을 요구하는 Cache-Control: no-cache를 사용하고 최신 게시본이 없으면 503을 반환한다. 마지막 CRL이 만료됐어도 원본 제공은 유지하며 관리자 상태에서 만료를 표시한다.

## Import·전환·HTTPS·감사

| 메서드·경로 | 입력 / 결과 |
| --- | --- |
| POST `/imports/previews` | multipart 인증서·CRL·선택 CA 키·해제 암호 → 공개 자료 지문 기반 manifest와 항목별 신규/중복/충돌 |
| POST `/imports` | multipart 원본 재제출, preview_manifest, 인수 확인 선택 → 재검증 후 원자 반영, import_id. Idempotency-Key 필수 |
| GET `/imports/{id}` | 공개 manifest·결과만 조회 |
| POST `/authorities/{id}/signing-key` | multipart CA 키·암호 → 동일 인증서의 키 연결. 다른 인증서 생성 불가 |
| POST `/authorities/{id}/takeover` | history_assertion, previous_max_number_hex, external_issuer_stopped_at, evidence → 인수 검증·기록 |
| GET / POST `/transitions` | 목록 / source_authority_id, target_authority_id(선택), mode, reason → 정상/긴급 전환 생성 |
| GET / PATCH `/transitions/{id}` | 영향 목록·진행 / 후속 CA 연결. 긴급 신고를 취소해 차단 해제하는 수정 불가 |
| POST `/transitions/{id}/deployment-confirmations` | target_label, certificate_id(선택), action → 수동 대상별 확인 |
| POST `/transitions/{id}/complete` | 외부 전환 확인 및 종료 조건 검증 |
| GET `/tls` | 현재 버전·만료·bootstrap 여부·진행 중 교체 |
| POST `/tls/candidates` | multipart certificate, chain, key, passphrase → 검증된 외부 스냅샷 |
| POST `/tls/issuances` | authority_id, subject, sans, key_algorithm, validity → 내부 보관용 인증서 후보. Idempotency-Key 필수 |
| POST `/tls/reloads` | 구성된 외부 파일을 명시적으로 다시 읽어 후보 생성. 임의 서버 경로 입력 불가 |
| POST `/tls/activations` | candidate_id, If-Match → 활성 교체. 응답 손실 시 GET /tls로 확인 |
| GET `/audit-events` | 기간·계정·CA·인증서·작업·IP·결과 검색 |
| GET `/audit-events/export` | 동일 필터/권한, format=json/csv. CSV 수식 실행을 막는 셀 인코딩 적용 |

preview는 개인키를 저장하지 않는다. 브라우저는 선택 파일을 완료까지 유지하고 commit 시 재제출한다. 원본 해제 암호도 다시 전달하며 서버 세션·DB·job에는 보관하지 않는다. 미리보기 manifest는 승인이나 현재 DB 검증을 대체하지 않는다. CRL만 추가하는 import도 같은 경로를 사용한다.

전환 완료는 외부 확인과 CA 발행 종료를 구분해 반환한다. 정상 외부 전환이 끝나도 하위 인증서 만료까지 기존 CRL이 계속 필요할 수 있다. HTTPS 후보 생성은 활성화와 별개이며 일반 개인키 수령 경로를 만들지 않는다.

rotate·restore-finalize·재설정 링크 발급·bootstrap 재생성은 내부 CLI 전용이다. 일반 웹 API가 저장 암호화 키를 받거나 유지보수 잠금을 우회하지 않는다. 실행 중 CLI의 비밀번호 재설정 요청은 로컬 전용 Unix 소켓을 통해 같은 서비스 계층에서 처리하며, 오프라인에서는 배타 잠금 획득 후 실행한다. 소켓은 컨테이너 운영자만 접근하도록 파일 권한으로 제한하고 외부 HTTP에 노출하지 않는다.

import 요청의 중복 방지 해시는 인증서/CRL 지문·제공한 CA 키의 SPKI·인수 선택 등 정규화한 업무 입력을 사용한다. 해제 암호·토큰 원문·multipart 경계는 포함하지 않는다. 입력 키의 일치 검증 없이 지문만 믿고 재생하지 않는다.


## 확정 HTTP 보안 규칙

- 상태 변경의 Origin은 HTTPS origin(스킴·정규화 호스트·유효 포트)으로 파싱하고 현재 설정 service_url의 origin과 정확히 비교한다. null·복수·잘못된 Origin은 거부한다. service_url의 userinfo/fragment는 금지한다. X-Forwarded-Host/Proto는 비교 기준이 아니다. 설정 이전에는 직접 받은 HTTPS 요청 authority와 Origin의 일치를 요구하며 pre-auth nonce를 그 origin에 결합한다. 이는 최초 설정 승인 수단이 아니므로 [제한된 초기 노출](./architecture.md)의 운영 전제가 적용된다. 설정 후 이전 출처의 pre-auth 토큰은 거부한다.
- pre-auth 쿠키는 `__Host-certme_preauth`, Secure·HttpOnly·SameSite=Strict·Path=/·Max-Age=600이다. 32바이트 난수 nonce와 서명 토큰의 만료·origin·목적(pre-auth)을 함께 검증한다. 서명 키는 프로세스 시작마다 생성하는 메모리 전용 난수 키이며 재시작 시 기존 pre-auth가 무효화된다. 세션 CSRF와 pre-auth는 대체할 수 없다. `/auth/csrf` GET은 Sec-Fetch-Site가 있으면 반드시 same-origin이어야 하며 Origin 또는 Referer 중 존재하는 출처 값은 모두 기준 origin과 일치해야 한다. Sec-Fetch-Site도 없으면 검증된 Origin/Referer 중 하나가 필요하고 아무 증거도 없으면 403이다.
- 전체 HTML 응답에 `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'`를 적용한다. unsafe-inline/unsafe-eval은 허용하지 않는다. JS/CSS는 embed한 동일 출처 파일만 사용하고 inline handler를 쓰지 않는다. HTMX의 allowEval=false, allowScriptTags=false, includeIndicatorStyles=false를 초기화한 뒤 처리하며 필요한 indicator CSS는 로컬 파일로 제공한다.
- 신뢰되지 않은 Subject·SAN·이름·파일명·오류는 html/template의 문맥별 escape를 유지한다. 외부 값을 template.HTML/JS/URL 등 안전 타입으로 승격하지 않는다. HTMX 조각도 같은 템플릿 규칙을 따른다. 전체 응답에 nosniff와 no-referrer, HTML에 X-Frame-Options: DENY를 적용한다. TLS 최소 버전은 1.2이며 암호군은 고정 Go toolchain의 안전 기본값을 사용하고 레거시 추가는 허용하지 않는다. HSTS는 MVP 기본 비활성화, preload/includeSubDomains는 발행하지 않는다.
- 재설정 페이지는 링크 토큰을 메모리로 옮기고 최초 로드 시 history.replaceState로 현재 주소를 `/`로 바꾼다. 토큰을 local/sessionStorage·hidden HTML·URL에 다시 저장하지 않는다. 제출 시 메모리 토큰을 기존 재설정 POST 본문에 넣는다. 새로고침으로 메모리 토큰이 사라지면 원래 링크를 다시 열도록 안내한다. GET만으로 토큰을 소비하지 않는다. 이 조치는 이미 남은 외부 로그를 삭제하지 않는다.
- 다운로드에는 안전한 고정 파일명으로 Content-Disposition: attachment를 사용한다. 토큰·Subject·사용자 파일명을 파일명에 삽입하지 않는다. 대시보드의 다운로드 Blob URL은 사용 완료 후 revoke한다. 헤더 수신 제한 10초, 요청 본문 수신 최대 60초, idle 60초, 헤더 최대 32 KiB를 기본값으로 한다. 본문 제한 시간과 KDF 실행 시간은 별개이며 context 취소만으로 KDF 중단을 보장하지 않는다.
- 개인키 전송 Send는 소비 커밋 후 최대 60초의 실제 쓰기 deadline을 적용한다. HTTP adapter는 writer deadline 지원을 보장하며 불가능하면 소비 전에 거부한다. private 동시 준비/전송은 최대 4건, 대기 최대 5초, 인코딩 payload는 건당 최대 16 MiB다. 자원 초과는 소비 전에 503 또는 크기 정책 오류로 반환하며 새 발급/토큰을 자동 생성하지 않는다. 메모리 버퍼는 한도를 확인하며 증가시키고 종료 때 정리한다.

import의 공개 manifest/evidence는 아래 버전 1 스키마만 허용한다. 모든 객체에서 미지정 속성을 거부하고 JSON 중첩 깊이는 16을 넘지 않는다. metadata 전체는 UTF-8 256 KiB 이하이며 기존 multipart 16 MiB 한도도 적용한다.

| 스키마 | 허용 필드 |
| --- | --- |
| ImportManifest | schema_version=1, files(1~100개 ImportManifestFile) |
| ImportManifestFile | file_id(요청 파일 식별자, 최대 128자), kind(certificate/crl/ca_key), sha256(인증서/CRL 원본 DER 지문 또는 키의 정규화 공개 SPKI 지문), issuer_certificate_id(선택 UUID) |
| TakeoverEvidence | schema_version=1, crl_sha256(0~100개 DER 지문), issuance_records_checked(boolean), crl_routes_checked(boolean) |

manifest는 서버가 파싱한 공개 자료로 재구성한다. private 키 파일의 원본/암호문 지문·passphrase·입력 metadata 전체를 공개 manifest에 복사하지 않는다. 파일명은 요청 내 식별에만 쓰고 서버 경로로 해석하지 않는다. 중복 file_id/파일명·누락/초과 매핑은 거부한다. preview_manifest와 파일의 대응은 commit에서 다시 비교하고 현재 DB 검증을 수행한다. preview_manifest는 commit 필수이며 preview 요청에는 생략한다. evidence의 CRL 지문은 실제 제공 또는 등록된 해당 CA의 검증된 CRL과 결합해 검사하고, 발급 자료/경로 확인 boolean은 둘 다 true여야 takeover를 확정한다. 외부 시스템을 자동 조회해 이 진술을 검증하지 않는다.
