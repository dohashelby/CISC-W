# AVEP 논문 자료 보관본

이 폴더는 온라인 적응형 LLM 서빙 제어기의 인증 주체 간 상태 오염 논문을 작성하면서 사용한 자료를 한곳에 모은 보관본이다.

## 폴더 구성

- `manuscript/`: 논문 본문 초안과 한컴 입력용 분리본
- `source_notes/`: 최초 취약점 후보 문서, 논문 가능성 평가, 학술대회 양식
- `experiment/`: 실험 프로토콜, 사전 결정 규칙, 분석 코드, 결과 보고서와 로컬 원자료
- `aws_export/`: AWS EBS에서 회수한 실험 자료의 공개용 압축 해제본, 원본 SHA-256과 공개 파일 명세

## 주요 실증 자료

- `FACTORIAL_CONFIRMATORY_V2_RESULT_REPORT.md`: 논문의 주된 2×2 인과 실험 결과
- `CAUSAL_ABLATION_RESULT_REPORT.md`: estimator update 차단을 사용한 인과 절제 결과
- `results_20260918/FINAL_EXPERIMENT_REVIEW.md`: 초기 논문 실험의 최종 검토
- `results_20260918/avep-paper-results.tgz`: 초기 논문 실험 원자료
- `results_20260920/CTFR_V2_GATE_FAILURE_REPORT.md`: CTFR 예비 실험의 실패 경계

## 주장 범위

실증 범위는 시험한 vLLM commit, 모델 조합, 단일 L40S worker와 gateway로 구분한 두 인증 주체에 한정된다. CTFR은 검증 완료된 방어책이 아니라 설계 제안과 예비 구현 관찰로만 사용한다.

## 원격 보관본

AWS에서 회수한 `avep-paper-data-20260920.tgz`는 `/home/ubuntu/avep` 가운데 모델 캐시와 재현 가능한 8 GiB vLLM 작업 트리만 제외하고, 실험 결과·로그·분석기·실행 스크립트·패치·배포 입력을 보존한 압축본이다. 대응하는 `.sha256` 파일은 원본 압축파일의 무결성을 기록한다.

공개용 압축 해제본은 [`aws_export/avep-paper-data-20260920/`](aws_export/avep-paper-data-20260920/)에 있다. 실제 실행 시 생성된 인증 파일 7개와 macOS 메타데이터 65개를 제외했으며, 나머지 파일은 원본 바이트를 그대로 보존했다. 인증정보가 포함된 원본 압축파일은 로컬에만 보관하며 Git 추적에서 제외한다.

공개본 검토 내용은 [PUBLICATION_REVIEW.md](PUBLICATION_REVIEW.md), 각 공개 파일의 SHA-256과 제외 목록은 [PUBLICATION_MANIFEST.json](aws_export/PUBLICATION_MANIFEST.json)에 기록했다. 이 공개본의 파일 검증에는 명세의 개별 파일 SHA-256을 사용한다.

실험 자료는 GitHub 저장소에서 제공하며, 발표용 GitHub Pages 배포에서는 `evidence/`를 제외한다.
