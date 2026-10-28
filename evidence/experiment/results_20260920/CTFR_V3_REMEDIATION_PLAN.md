# CTFR v3 사전 보완 계획

이 문서는 v2 실패를 사후에 통과시키기 위한 계획이 아니다. v2는 음성
결과로 동결하고, 확인된 두 문제를 새 프로토콜에서 해결한 뒤 새로운
사전등록과 전체 게이트를 수행하기 위한 계획이다.

## v2에서 확인된 두 차단 요인

1. benign pair의 aggregate가 decision trust region을 약 1.4714% 초과해
   retirement가 거부됐다.
2. 동일한 동결 상태와 `temperature=0`에서도 fresh process 및 wave에 따라
   held-out token sequence가 달라졌다. 다섯 arm 모두 같은 output hash를 낸
   ordinal은 baseline 145/256, post-evaluation 143/256뿐이었다.

두 번째 문제 때문에 retirement만 수정한 채 바로 8-block Stage D를 돌리면
안 된다.

## A. bounded fractional retirement

안전 한도 `max_probability_shift=0.15`는 완화하지 않는다.

1. 두 독립 principal candidate의 clipped delta와 cosine agreement를 기존과
   동일하게 계산한다.
2. 평균 aggregate를 먼저 `max_commit_norm` 구에 투영한다.
3. 사전등록한 고정 scale grid에서 `base + scale * aggregate`를 평가한다.
4. probability shift가 `0.15` 이하인 가장 큰 scale을 결정론적으로 선택한다.
5. scale이 최소 유효값보다 작으면 fail closed하고, 아니면 scaled update만
   원자적으로 commit한다.
6. raw/clipped/projected norm, 모든 평가 scale, 선택 scale, probability shift,
   credit debit을 결과와 로그에 기록한다.

필수 단위 테스트:

- 원 aggregate가 한도 안이면 scale 1.0과 기존 결과가 일치한다.
- v2 재현 geometry에서는 0보다 크고 1보다 작은 scale이 선택된다.
- 어떤 양의 scale도 안전하지 않으면 상태가 byte-for-byte 불변이다.
- 경계값, 비유한 값, zero delta, disagreement, credit 부족은 fail closed한다.
- 실패 경로에서는 version, coefficients, credits, counters, shadows가 변하지
  않는다.
- 동일 입력에서 선택 scale과 로그가 반복 실행 간 동일하다.

## B. held-out output divergence 진단 게이트

GPU 본 실험 전에 작은 fresh-process 진단을 수행한다. 모델, revision,
manifest, seed, baseline은 모두 고정하고 controller update는 끈다.

비교할 조건:

1. 현재 조건: concurrency 32, 16 waves/batch.
2. 고정 소배치: concurrency 2, 1 wave/batch.
3. 조건 2에 eager execution 및 가능한 deterministic CUDA 설정을 추가.
4. 동일 프로세스 반복과 fresh-process 반복을 각각 수행.

각 조건에서 ordinal별 token ID, 최초 divergence position, request admission
순서, scheduler batch membership, draft budget sequence, target argmax margin을
기록한다. 정책이 동일한 control끼리 이미 diverge하면 controller 효과가
아니라 serving/GPU 실행 비결정성으로 분류한다.

### v3 semantic endpoint 선택 규칙

- 현실적인 동시성에서 exact output equality가 재현되면 기존 hash gate를
  유지한다.
- 고정 소배치에서만 재현되면 exactness 검사는 별도의 deterministic replay로
  분리하고, 성능 실험은 원래 동시성을 유지한다.
- deterministic replay에서도 재현되지 않으면 exact cross-process hash를
  confirmatory endpoint로 쓰지 않는다. 대신 사전등록한 두 층을 사용한다:
  (a) 고정 reference completion에 대한 common-support teacher-forced replay,
  (b) 현실적인 동시성에서 task accuracy/semantic score의 paired
  non-inferiority. 이 변경은 v2 결과를 살리는 사후 기준이 아니라, v2에서
  드러난 측정 불가능성을 해결하는 새 v3 설계로 명시한다.

## C. v3 실행 순서와 중단 규칙

1. 로컬 구현 및 단위 테스트.
2. 저비용 output-divergence 진단만 실행하고 인스턴스 중지.
3. 진단 결과를 바탕으로 semantic endpoint를 하나만 선택해 동결.
4. 새 source digest, corpus/manifests, baseline pilot, declaration, analyzer 및
   test digest를 생성한다.
5. fresh root에서 다섯 arm gate 전체를 한 번 실행한다.
6. retirement 또는 semantic gate가 실패하면 즉시 중단한다. selective retry는
   하지 않는다.
7. 게이트가 통과한 뒤에만 8-block Stage D, Stage E, overhead 순서로 간다.

## 비용 통제

- EC2를 시작하기 전 로컬 테스트와 declaration 검증을 모두 완료한다.
- 각 원격 단계는 별도 cost stop으로 둔다.
- 작은 determinism 진단 후 바로 중지하고 결과를 검토한다.
- 다섯 arm gate 예상 compute는 약 USD 2.76--5.51이며, 실제 시작 전 다시
  견적을 확인한다.
- Stage D/E/overhead는 게이트 통과와 사용자 승인을 모두 받은 뒤에만
  실행한다.

## 허용 가능한 논문 해석

v3 gate 전에는 CTFR가 benign adaptation을 보존한다고 주장하지 않는다.
현재 v2가 지지하는 것은 다음의 제한된 관찰뿐이다.

- authenticated principal별 shadow attribution이 작동했다.
- retirement 전 committed estimator state는 불변이었다.
- shared와 frozen 사이에 adaptation opportunity가 관측됐다.
- tenant-local refit control이 정상 동작했다.
- 기존 all-or-nothing retirement는 사전등록 decision trust region에서
  fail closed했다.

bounded fractional retirement의 유용성, output semantics, 공격 완화,
overhead는 모두 v3의 새로운 실증 대상이다.
