# 논문 자료 공개 전 검토 기록

- 검토일: 2026-10-28
- 대상: `evidence/aws_export/avep-paper-data-20260920.tgz`와 함께 추가된 논문·실험 자료
- 원본 압축파일 SHA-256: `949d0bc3f84e2219264f96cea09b1bb54a13f30b1966d6ae363bdc4ba6db952e`

## 검토 범위

원본 압축파일의 일반 파일 8,058개, 중첩된 tar/gzip/xz/zip 및 Base64 묶음, 저장소에 추가된 자료를 검사했다. 중복을 포함한 검사 경로는 16,248개였다. 검사 항목은 실제 실험 토큰 21개의 재등장, 개인키, AWS 접근 키, GitHub 토큰, Hugging Face 토큰, 모델 API 키, 인증정보 대입문, 이메일·네트워크 주소와 위험한 압축 경로였다. 중첩 압축파일의 읽기 오류와 경로 탈출·특수 파일 항목은 없었다.

## 공개에서 제외한 항목

- `.avep_*_tenant_credentials.json` 계열 파일 7개: 각 실험의 attacker, victim, upstream 인증 토큰 총 21개가 포함되어 있어 제외했다.
- 압축파일 안의 macOS AppleDouble 메타데이터 65개: 연구 재현에 필요하지 않아 제외했다.
- 저장소에 추가된 `.DS_Store` 3개: Git 추적에서 제외했으며 로컬 파일은 보존했다.
- 원본 `avep-paper-data-20260920.tgz`: 실제 인증정보가 포함되어 있고 GitHub의 파일 크기 제한도 초과하므로 로컬에 보관하고 공개 커밋에서 제외했다.

실제 토큰 21개는 위 인증 파일 7개에서만 발견됐다. 나머지 자료와 중첩 묶음에서는 같은 토큰이나 AWS·GitHub·Hugging Face·모델 API 키 형식, 개인키가 발견되지 않았다. 코드의 `local-research-only` 값은 localhost 실험용 기본 예시 문자열이며, `tenant_key`는 변수명으로 확인했다.

## 공개본 구성과 무결성

- 공개 폴더: [`aws_export/avep-paper-data-20260920/`](aws_export/avep-paper-data-20260920/)
- 공개 파일 수: 7,986개
- 공개 파일의 전체 크기: 2,127,354,868바이트
- 공개 파일 목록·개별 SHA-256·제외 목록: [`aws_export/PUBLICATION_MANIFEST.json`](aws_export/PUBLICATION_MANIFEST.json)
- 가장 큰 개별 파일: 68,514,751바이트로 GitHub의 100MiB 제한 미만

제외한 파일을 빼고 모든 공개 파일은 원본 압축파일의 바이트를 그대로 보존했다. 따라서 실험 수치, 결과 JSON, 로그, 실패·중단 기록, 실행 스크립트와 패치의 내용은 변경하지 않았다. 원본에 들어 있던 중첩 실험·배포 압축본도 내부를 검사한 뒤 보존했다.

기존 `.sha256` 파일과 실험 중 생성된 체크섬은 원본 당시 산출물에 대한 기록이다. 공개된 압축 해제 파일의 검증에는 `PUBLICATION_MANIFEST.json`의 개별 파일 체크섬을 사용한다.

## 저장소와 웹 배포

`.gitignore`에 실제 인증 파일·개인키·macOS 메타데이터와 원본 대형 압축파일의 제외 규칙을 추가했다. 공개 실험 자료는 GitHub 저장소에서 제공하며, `_config.yml`에서는 `evidence/`를 발표용 Pages 배포에서 제외해 1GB 사이트 용량 제한을 넘지 않도록 했다.
