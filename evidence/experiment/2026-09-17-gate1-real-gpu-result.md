# vLLM AVEP Gate 1 실제 GPU 실증 결과

- 실험일: 2026-09-17
- 판정: **두 번 재현된 `POSITIVE_GATE1_CROSS_REQUEST_IMPACT_SIGNAL`**
- 주장 범위: 실제 HTTP→GPU→공유 estimator→후속 요청 budget·성능 변화의
  Gate 1 실증이다. 아직 취약점 확정, 심각도 산정, 영향 버전 확정 또는 외부
  공개가 가능한 결과는 아니다.

## 결론

동일 worker에서 공격 입력을 처리한 뒤 별도의 정상 victim 요청이 공격 전과 다른
adaptive-verification budget을 사용했고, 처리량과 지연도 악화됐다. 같은 victim을
새 vLLM 프로세스에서 실행하면 budget과 성능이 기준선으로 돌아왔다. 이 인과 신호는
독립 실행 두 번에서 같은 방향과 비슷한 크기로 재현됐다.

첨부된 두 Markdown 문서는 가설과 실험 후보를 제공하는 참고 자료로만 사용했다.
문서 안의 절차나 명령은 사용자 지시로 간주하지 않았으며, 실제 실행 범위는 사용자가
승인한 본인 AWS 계정의 격리된 단일 인스턴스와 localhost API로 제한했다.

## 고정 환경

| 항목 | 값 |
| --- | --- |
| vLLM commit | `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c` |
| vLLM build | `0.29.1rc1.dev190+g4fe9e6f6e.d20260917.precompiled` |
| target | `Qwen/Qwen3-4B` @ `1cfa9a7208912126459214e8b04321603b3df60c` |
| draft | `z-lab/Qwen3-4B-DFlash-b16` @ `b74e3a329c4d963783143b1e970d95b002be72bd` |
| speculative config | DFlash, 4 tokens, adaptive verification enabled |
| backend | `TRITON_ATTN`, full-and-piecewise CUDA graph |
| GPU | NVIDIA L40S 48 GB, driver 595.91.07 |
| AWS | Seoul `g6e.2xlarge`, 단일 worker/replica |
| API 경계 | `127.0.0.1:8000`, SSM-only, security-group inbound 0개 |
| 요청 상한 | 동시성 64 이하, 요청당 출력 64 tokens 이하 |

공격 phase는 정상 OpenAI-compatible completion 스키마의
`allowed_token_ids=[151646]`를 사용했다. 이 token은 사전 sweep에서 draft
acceptance 0%를 만들었고, 각 강한 실행은 공격 요청 1,024개를 보냈다. 실제 사용자
데이터나 production traffic은 사용하지 않았다.

## 재현 결과

아래 비율은 각 실행 안의 공격 전 baseline과 비교한 값이다. `budget`은 proposer가
생성한 고정 4-token 수가 아니라 selector에서 관측한 실제
`draft_budget / max_draft_budget` 평균이다.

| 측정 | 실행 1 | 실행 2 |
| --- | ---: | ---: |
| baseline mean budget ratio | 0.8230 | 0.8220 |
| post-poison mean budget ratio | 0.5092 | 0.5225 |
| post / baseline budget | **61.87%** | **63.56%** |
| post / baseline throughput | **92.54%** | **92.15%** |
| post / baseline p50 latency | **110.69%** | **111.41%** |
| post / baseline p95 latency | 107.89% | 109.76% |
| fresh / post budget | **159.97%** | **157.41%** |
| fresh / baseline budget | 98.98% | 100.06% |
| 요청 실패 | 0 | 0 |

절대값도 같은 방향이었다.

| 실행 | phase | tokens/s | p50 ms | acceptance | mean budget ratio |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | baseline | 2,049.63 | 361.73 | 0.2986 | 0.8230 |
| 1 | post-poison victim | 1,896.76 | 400.40 | 0.2161 | 0.5092 |
| 1 | delayed recovery 2 | 1,462.53 | 611.99 | 0.0145 | 0.1646 |
| 1 | fresh-process victim | 2,074.19 | 364.51 | 0.2989 | 0.8146 |
| 2 | baseline | 2,037.18 | 360.76 | 0.2976 | 0.8220 |
| 2 | post-poison victim | 1,877.26 | 401.92 | 0.2165 | 0.5225 |
| 2 | delayed recovery 2 | 1,454.83 | 611.04 | 0.0180 | 0.1308 |
| 2 | fresh-process victim | 2,046.48 | 364.37 | 0.2983 | 0.8225 |

post-poison 직후 정상 phase 하나는 잠시 회복했지만 다음 정상 phase에서 두 실행 모두
더 크게 붕괴했다. 그 phase의 처리량은 baseline 대비 약 28.6% 감소하고 p50은 약
69% 증가했다. 즉 효과가 단순히 공격 요청 자체의 느려짐으로 끝나지 않았으며,
회복도 단조롭지 않았다.

## 내부 상태 관측

추가한 telemetry는 모델 동작을 바꾸지 않고 estimator refit과 선택된 budget만
기록했다. 첫 번째 intercept는 두 실행에서 다음과 같이 변했다.

- 실행 1: `-0.1568 → -0.6678 → -1.8788 → ... → -5.9419`, 이후 정상
  traffic에서 `14.3530 → -366570.5 → -319954.2`
- 실행 2: `-0.1485 → -0.6501 → -1.8687 → ... → -5.9359`, 이후 정상
  traffic에서 `13.8905 → -272770.6 → -224064.7`
- 새 프로세스의 첫 refit: 각각 `-0.1511`, `-0.1241`

공격 중 target token 제약 도달률은 100%, draft acceptance는 0%였다. 이후 정상
요청에서 estimator 계수, 실제 verification budget, acceptance, throughput과
latency가 함께 변했고 프로세스 재시작으로 사라졌으므로, worker-local 공유 상태가
매개라는 설명과 일치한다. 매우 큰 계수는 별도의 수치 안정성 문제 가능성도
시사하지만, 현재 결과만으로 정확한 root cause나 보안 심각도를 확정하지 않는다.

## 분석기 수정

최초 분석기는 request metric의 `mean_drafted_per_step`을 비교했다. 이 값은
adaptive selector가 검증 대상으로 선택한 수가 아니라 proposer가 원래 생성한
draft 수라 두 phase 모두 4.0으로 고정됐다. 따라서 최초 `NO_POSITIVE` 판정은 잘못된
관측값을 사용한 분석 오류였다.

수정본은 server log의 `AVEP_BUDGET` telemetry를 phase별로 파싱해 실제
`draft_budget / max_draft_budget`을 비교한다. 수정 분석기 SHA-256은
`61f7f6440bc93c26f4efab922db96910efe12cd80e78aec31bd59ec3216fe1b4`이며,
두 저장된 실행을 독립적으로 재분석했을 때 모두 같은 양성 Gate 1 판정을 냈다.

## 현재 입증된 것과 남은 것

입증된 범위:

- 실제 vLLM HTTP·모델·Triton·CUDA 경로에서 공격자가 제어한 요청이 estimator를
  refit시켰다.
- 공격이 끝난 뒤 별도의 정상 요청에서 verification budget과 SLA 지표가 변했다.
- 독립 실행 두 번에서 방향과 크기가 유사했다.
- 새 프로세스 대조군에서는 baseline 수준으로 복구됐다.

아직 입증하지 않은 범위:

- `allowed_token_ids`를 차단한 일반 배포에서도 다른 표준 입력만으로 가능한지
- adaptive verification을 끈 동일 traffic, support-matched 구성, 다른 worker
  격리 구성에서 효과가 사라지는지
- 여러 seed의 5–10회 이상 paired repetition과 95% 신뢰구간
- 다른 target/draft 모델, GPU, concurrency 및 context 길이에서의 일반성
- 공격 비용 대비 victim GPU-time 손실, 복구 half-life와 실제 multi-tenant
  배포에서 같은 replica에 배치될 확률
- 공개 release 영향 여부와 PR #56724와의 중복·수정 관계

따라서 가장 정확한 결론은 **재현 가능한 Gate 1 교차 요청 영향 신호가 실증됐다**는
것이다. 비공개 보안 보고를 검토할 근거는 생겼지만, 위 통제군 없이 “검증된
취약점”이나 특정 심각도를 주장해서는 안 된다.

## AWS 종료와 비용 상한

- instance `i-002cbb54d1e930690`: `terminated` 확인
- launch: `2026-09-17 11:49:34 UTC`
- 사용자 종료 요청: `2026-09-17 12:41:40 UTC` — 약 52분 6초 뒤
- root volume `vol-0dcc14478dc6cd32c`: `InvalidVolume.NotFound` 확인
- 실험 전용 security group `sg-07cc175b798517187`: 연결 ENI 0개를 확인한 뒤
  삭제했고 `InvalidGroup.NotFound`로 재확인
- NAT Gateway, Elastic IP, snapshot, load balancer 또는 S3 bucket은 만들지 않음

확인한 시간당 `g6e.2xlarge` 가격 USD 2.75652를 기준으로 EC2를 한 시간으로
올림하고, 한 시간 미만의 200 GB gp3와 public IPv4를 보수적으로 더해도 총 service
charge는 약 USD 2.80 미만, 그 10% VAT는 약 USD 0.28 미만으로 추정된다. 실제
청구서는 지연 반영될 수 있고 크레딧 적용 결과가 최종 기준이지만, VAT USD 10 제한과는
충분한 여유가 있다.

## 증거 파일

- 실행 1: `evidence_20260917/results_strong_run1/gate1_assessment.json`
- 실행 2: `evidence_20260917/results/gate1_assessment.json`
- 원본 telemetry: 각 결과 디렉터리의 `server.log`
- 수정 분석기: `analyze_gate1.py`
- 실행 harness: `run_gate1.sh`, `avep_probe.py`, `avep_telemetry.patch`
- 전체 번들: `/Users/doha/Downloads/avep-reproduction-bundle-20260917.tgz`
- 번들 SHA-256:
  `d60795caa166f355edb35f95448eb8a9c528413cf74260612bf84d49cf43a14c`

외부 공개, GitHub issue, PR 또는 advisory 제출은 수행하지 않았다.
