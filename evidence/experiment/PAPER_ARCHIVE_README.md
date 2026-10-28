# AVEP 논문 자료 보관본

이 폴더는 온라인 적응형 LLM 서빙 제어기의 인증 주체 간 상태 오염 논문을 작성하면서 사용한 자료를 한곳에 모은 보관본이다.

## 폴더 구성

- `manuscript/`: 논문 본문 초안과 한컴 입력용 분리본
- `source_notes/`: 최초 취약점 후보 문서, 논문 가능성 평가, 학술대회 양식
- `experiment/`: 실험 프로토콜, 사전 결정 규칙, 분석 코드, 결과 보고서와 로컬 원자료
- `aws_export/`: AWS EBS에서 마지막으로 회수한 원격 실험 자료와 SHA-256 파일

## 주요 실증 자료

- `FACTORIAL_CONFIRMATORY_V2_RESULT_REPORT.md`: 논문의 주된 2×2 인과 실험 결과
- `CAUSAL_ABLATION_RESULT_REPORT.md`: estimator update 차단을 사용한 인과 절제 결과
- `results_20260918/FINAL_EXPERIMENT_REVIEW.md`: 초기 논문 실험의 최종 검토
- `results_20260918/avep-paper-results.tgz`: 초기 논문 실험 원자료
- `results_20260920/CTFR_V2_GATE_FAILURE_REPORT.md`: CTFR 예비 실험의 실패 경계

## 주장 범위

실증 범위는 시험한 vLLM commit, 모델 조합, 단일 L40S worker와 gateway로 구분한 두 인증 주체에 한정된다. CTFR은 검증 완료된 방어책이 아니라 설계 제안과 예비 구현 관찰로만 사용한다.

## 원격 보관본

AWS에서 회수한 `avep-paper-data-20260920.tgz`는 `/home/ubuntu/avep` 가운데 모델 캐시와 재현 가능한 8 GiB vLLM 작업 트리만 제외하고, 실험 결과·로그·분석기·실행 스크립트·패치·배포 입력을 보존한 압축본이다. 대응하는 `.sha256` 파일로 다운로드 무결성을 확인한다.
