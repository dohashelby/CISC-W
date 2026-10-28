# 논문 구성안: Cross-Principal Adaptive Control-State Contamination

## 1. 권장 논문 포지셔닝

현재 증거로 가장 강하면서도 방어 가능한 주장은 다음과 같다.

> 온라인 적응형 LLM 서빙은 모델 가중치와 별개로, 요청에서 생성된 feedback을
> 이용해 이후 요청의 처리 정책을 바꾸는 mutable control state를 유지한다. 이
> 상태가 인증 principal 사이에 공유되면 한 principal의 추론 요청이 다른
> principal의 후속 verification policy와 성능에 영향을 줄 수 있다. 우리는 이
> 문제 구조를 정의하고, 고정된 vLLM adaptive-verification 구성에서 실제 경로와
> estimator-mediated impact를 실증한다.

논문의 일반 기여는 모든 서빙 엔진이 취약하다는 주장이 아니라, 일반적인 보안
문제와 검사 조건을 정의하는 것이다. 실증 기여는 vLLM 한 구성의 case study로
한정한다.

권장 제목은 다음과 같다.

**온라인 적응형 LLM 서빙의 인증 주체 간 제어 상태 오염: vLLM Adaptive
Verification 사례 연구**

영문 제목:

**Cross-Principal Control-State Contamination in Online-Adaptive LLM
Serving: A vLLM Adaptive Verification Case Study**

`Cross-Tenant`보다는 `Cross-Principal`이 정확하다. 실험의 경계는 vLLM이 제공한
native tenancy가 아니라 gateway가 인증한 두 principal이기 때문이다.

## 2. 논문의 중심 질문

현재 자료로 답할 수 있는 연구 질문은 세 개로 제한하는 것이 좋다.

- **RQ1 — Reachability:** 권한 없는 내부 접근 없이 정상 추론 API 요청만으로
  shared online acceptance estimator와 verification budget을 바꿀 수 있는가?
- **RQ2 — Cross-principal propagation:** 공격 principal의 요청이 끝난 뒤 같은
  worker의 다른 인증 principal이 변경된 정책과 성능을 경험하는가?
- **RQ3 — Causality:** 동일한 공격 workload에서 estimator update만 차단하면
  상태 변화, 정책 변화, victim 성능 저하가 사라지는가?

공격 비용 증폭, recovery half-life, 방어 효과, cross-engine generality는 아직
완전히 답하지 못했으므로 현재 논문의 주 RQ로 선언하지 않는다. 추가 실험 후
RQ4와 RQ5로 승격할 수 있다.

## 3. 핵심 기여 문장

현재 상태에서 contribution은 다음 세 가지가 적절하다.

1. **문제 정의.** 비신뢰 추론 요청이 생성한 feedback이 principal 경계를 넘어
   공유 adaptive serving state를 갱신하는 `cross-principal adaptive
   control-state contamination` 문제를 정의하고, 성립 조건을 제시한다.
2. **측정 방법.** 두 인증 principal, 동일 worker 증명, gateway audit의 1:1 join,
   fresh-process blocked factorial repetition, phase non-overlap, fail-closed
   analyzer를 포함한 재현 가능한 실험 방법을 제시한다.
3. **인과 실증.** 고정된 vLLM 구성에서 attack/placebo workload와 estimator
   update shared/blocked를 교차한 사전등록 factorial 실험을 통해, 공격에 특이적인
   후속 victim policy 및 성능 저하가 공유 estimator update에 의해 매개됨을
   보인다.

아직 구현하지 않은 방어를 contribution으로 쓰면 안 된다. 방어 실험을 추가하면
네 번째 기여로 `influence-bounded` 또는 `principal-scoped` adaptation을 넣을 수
있다.

## 4. 초록 초안

대규모 언어 모델의 가중치는 추론 중 고정되어 있지만, 최신 LLM 서빙 엔진은
실시간 verification feedback을 이용해 speculative decoding의 검증량과 같은
처리 정책을 온라인으로 조정한다. 본 논문은 이 적응 상태가 인증 주체 사이에
공유될 때 발생하는 cross-principal control-state contamination 문제를 정의한다.
공격자가 정상 추론 API의 요청별 sampling 정책을 통해 verification feedback을
편향시키면, 공유 acceptance estimator가 갱신되고 공격 종료 후 다른 principal의
verification budget과 SLA가 변할 수 있다. 우리는 두 gateway-authenticated
principal이 하나의 worker를 공유하는 고정된 vLLM adaptive-verification 환경에서
사전등록된 2x2 factorial 실험을 수행하였다. 공격/대조 workload와 estimator
update 허용/차단을 교차한 8개 fresh-process block에서 메커니즘 게이트의 여섯
조건이 모두 통과했다. 8-window 사전정규화 처리량의 attack-by-update interaction은
평균 -0.2478(95% bootstrap interval [-0.2586, -0.2380])이었으며 8/8 block이
adverse 방향이었다(one-sided exact sign-test p=0.00390625). p50 및 p95 latency
interaction도 각각 +0.5053과 +0.4788이었다. 결과는 한 고정 구성에 한정되지만,
공격 workload 자체와 shared-update mode 자체를 동시에 통제해 비신뢰 요청
feedback과 공유 적응 상태 사이에 새로운 서빙 trust boundary가 필요함을
보여준다.

## 5. 일반 문제 모델

principal `A`의 요청에서 생성된 feedback이 공유 상태를 바꾸고, 이후 principal
`B`의 정책이 그 상태를 읽는 구조를 다음처럼 정의한다.

```text
s(t+1) = F(s(t), y_A(t), c_A(t))
b_B(t+1) = pi(s(t+1), x_B(t+1))
```

- `s`: worker가 유지하는 mutable adaptive-control state
- `y_A`: A의 요청에서 생성된 verification feedback
- `c_A`: feedback의 의미를 결정하는 sampling/request context
- `b_B`: B에게 적용되는 verification budget 또는 serving decision

다음 조건을 모두 만족하는 시스템은 별도 검증이 필요한 attack surface를 가진다.

1. controller state가 요청 또는 principal 사이에 공유된다.
2. 비신뢰 요청이 update feedback에 영향을 줄 수 있다.
3. estimator가 sampling support, workload class 또는 principal context를 충분히
   구분하지 않는다.
4. 갱신된 state가 후속 요청의 자원 배분 또는 정책을 바꾼다.
5. 공격 요청이 끝난 뒤에도 state가 유지된다.
6. principal별 격리나 update contribution bound가 없다.

이 모델은 model-weight poisoning, KV-cache contamination, prompt injection 및
동시 부하에 의한 noisy-neighbor와 구분해야 한다. 공격자와 victim traffic이
겹치지 않아도 효과가 남고, 모델 가중치는 변경되지 않기 때문이다.

## 6. 권장 본문 구성

### 1장. 서론

- 모델은 고정되어 있어도 serving controller는 온라인으로 학습한다는 문제 제기
- request data plane과 shared adaptive-control state 사이의 trust boundary
- 단순 persistence나 acceptance collapse가 novelty가 아님을 명시
- 정확한 novelty: 인증 principal A의 feedback이 B의 후속 정책을 바꾸는 영향력
- RQ1–RQ3와 세 contribution 제시

서론 마지막 문장은 다음 정도가 적절하다.

> We do not claim that online-adaptive serving engines are generally
> vulnerable; we define a general risk structure and demonstrate one concrete,
> causally validated realization in a pinned vLLM configuration.

### 2장. 배경 및 선행연구

#### 2.1 Speculative decoding과 adaptive verification

- draft/target verification 구조
- acceptance feedback과 verification budget
- 모델 학습이 아니라 serving controller의 runtime adaptation임을 설명

#### 2.2 vLLM online acceptance estimator

- pooled slope/intercepts, refit, worker-local lifetime
- per-request confidence와 shared estimator의 구분

#### 2.3 관련 보안 연구

- 현재 요청의 speculative acceptance를 무너뜨리는 공격
- online-learning poisoning
- shared serving의 noisy-neighbor와 cross-request interference
- workload adaptation 및 pooled estimator 연구

#### 2.4 연구 공백

이미 알려진 것은 feedback 기반 adaptation과 shared state 자체다. 본 논문의 공백은
`authenticated principal -> shared estimator -> other principal's later policy`를
명시적인 보안 경계와 causal intervention으로 측정한다는 점이다.

### 3장. 위협 모델과 보안 속성

- 공격자는 정상 inference API를 사용할 수 있지만 host, model weights, telemetry
  RPC에는 접근할 수 없음
- attacker와 victim은 서로 다른 gateway-authenticated principal
- 같은 worker에 배치될 때만 경로가 성립
- 공격과 victim phase는 시간적으로 비중첩
- 목표는 기밀성·출력 무결성이 아니라 후속 victim의 availability/performance
- 제외 범위: 다른 worker, adaptive verification off, confidence-head 방식 등

보안 속성은 다음처럼 서술한다.

> 한 principal의 request-specific policy에서 생성된 feedback은 그 context가
> 일치하지 않는 다른 principal의 장기 serving policy를 제한 없이 바꾸어서는 안
> 된다.

### 4장. vLLM 사례의 원인 경로

소스와 실제 계측을 연결해 다음 경로를 제시한다.

```text
target-only request transform
  -> draft/target verification-support mismatch
  -> attacker-controlled accept/reject observations
  -> worker-shared OnlineAcceptanceEstimator
  -> adaptive verification budget
  -> later victim throughput and latency
```

현재 factorial confirmation은 `estimator update -> victim effect`를 직접 지지한다.
다만 `support mismatch`가 유일한 root cause임을 확정하려면 support-matched
실험이 더 필요하므로, 그 부분은 source-grounded mechanism hypothesis로 표현한다.

### 5장. 실험 방법

#### 5.1 환경

- vLLM commit `4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c`
- Qwen3-4B target과 Qwen3-4B-DFlash-b16 draft의 고정 revision
- L40S, `g6e.2xlarge`, `TRITON_ATTN`, 단일 worker
- localhost-only API와 두 principal 인증 gateway

#### 5.2 독립 단위와 통계

- 독립 단위는 request가 아니라 네 fresh-process arm으로 구성된 temporal block
- 요청 수를 표본 수로 세는 pseudoreplication 금지
- block-level factorial interaction과 paired-block bootstrap interval 사용
- Williams-balanced 고정 arm order, phase non-overlap, zero-failure 및 audit-join
  조건

#### 5.3 증거의 단계

실험을 숨기지 말고 다음 순서로 공개한다.

| 단계 | 판정 | 논문에서의 역할 |
|---|---|---|
| 초기 GPU Gate 1, 2회 | 탐색적 양성 | 현상 발견과 worker-local 가설 |
| 최초 6-pair attack/placebo | 유효하지만 `INCONCLUSIVE` | 반복 token이 예측 가능해진 음성 결과와 설계 교정 근거 |
| 인증 두-principal 4-pair | `EXPLORATORY_SHORT_HORIZON_SIGNAL` | 교차-principal propagation 증거 |
| causal ablation v1 | `INVALID` | token-ID 계측 실패 공개, 효과량에 포함 금지 |
| causal ablation v2, 6-pair | `TARGETED_CAUSAL_SIGNAL` | estimator update의 인과적 매개 증거 |
| factorial confirmatory v1 | `INVALID` | 사전등록한 post-1 budget gate 실패; 지연 반응을 보인 pilot |
| factorial confirmatory v2, 8 block | `CONFIRMATORY_FACTORIAL_SIGNAL` | attack workload와 update mode를 함께 통제한 주 확인 결과 |

음성 결과를 포함하면 intervention을 결과에 맞춰 임의 조정했다는 인상을 줄이고,
왜 `max_tokens=2`와 명시적인 mediator ablation이 필요했는지 설명할 수 있다.

### 6장. 결과

결과는 실험별이 아니라 RQ별로 조직한다.

#### 6.1 RQ1: 공격 feedback은 shared state에 도달하는가?

- attack acceptance `0.0`, placebo `0.1875` in both update modes
- `intercept[0]` attack-by-update interaction `-13.8508`
- mean 8-window normalized budget interaction `-0.5163`
- 모든 요청·인증·audit join의 구조적 유효성

#### 6.2 RQ2: 다른 인증 principal에게 전파되는가?

4-pair exploratory study의 post-1 결과:

| 지표 | 평균 paired effect | 95% interval |
|---|---:|---:|
| normalized throughput | -0.1191 | [-0.1271, -0.1110] |
| normalized p50 latency | +0.0978 | [+0.0496, +0.1264] |
| normalized p95 latency | +0.8354 | [+0.8170, +0.8457] |

4/4 throughput pair가 adverse였고, aggregate throughput contrast는 8개 post
window 모두 음수였다. 이 결과는 outcome-informed `n=4` 탐색 결과임을 표와
본문에 반복해서 표시한다. 최종 주장은 이 탐색 결과가 아니라 6.3의 독립
factorial-confirmatory cohort에 둔다.

#### 6.3 RQ3: estimator update가 원인인가?

주 확인 실험은 workload(`attack`/`placebo`)와 estimator update
(`shared`/`blocked`)를 교차한다. 동일한 4,096-request intervention과 fresh-process
구조를 유지하고, 공격 중 estimator accumulation/refitting만 조작한다.

| 관찰 | 결과 |
|---|---:|
| attack acceptance, blocked/shared | 0.0 / 0.0 |
| placebo acceptance, blocked/shared | 0.1875 / 0.1875 |
| 두 blocked estimator state | exact invariant |
| `intercept[0]` attack-by-update interaction | -13.8508 |
| 8-window normalized budget interaction | -0.5163 |
| attack shared-minus-blocked throughput | -0.3172 |
| placebo shared-minus-blocked throughput | -0.0693 |
| primary attack-by-update throughput interaction | -0.2478 |
| throughput 95% interval | [-0.2586, -0.2380] |
| adverse blocks / exact sign-test | 8/8, p=0.00390625 |
| p50 / p95 latency interaction | +0.5053 / +0.4788 |

모든 attack arm은 동일한 공격 연산과 target verification을 수행했으므로 단순
공격 workload 설명을 통제한다. 모든 placebo arm에서도 update mode의 일반 효과를
측정해 빼므로 shared mode 자체나 시간 추세라는 설명도 통제한다. 앞선 6-pair
targeted causal ablation의 방향과도 일치하지만, 논문의 주 정량 결과는 이 독립
factorial cohort로 둔다.

#### 6.4 지속성과 회복

- factorial study에서 8개 post window, arm당 1,024 victim 요청까지 interaction이
  모두 adverse 방향으로 유지
- 현재 관측 구간에서 완전 회복하지 않았음
- 관측 종료 뒤의 half-life나 무기한 persistence는 주장하지 않음

### 7장. 논의

#### 7.1 보안적 의미

- 모델 문제가 아니라 serving-engine control-state isolation 문제
- 공격 트래픽과 victim 피해가 비중첩이라는 점
- 정상 adaptation과 공격 가능성 사이의 경계

#### 7.2 다른 엔진에 대한 일반화

다른 엔진이 5장의 일반 조건을 만족하면 검사 대상이라는 주장만 한다. 실제
cross-engine 취약성은 아직 입증하지 않았다고 명시한다.

#### 7.3 가능한 완화책

- target-only transform 요청을 estimator 학습에서 제외
- draft와 target의 sampling support 정렬
- principal/workload-signature별 estimator 분리
- principal별 update contribution clipping 또는 bounded influence
- decay, coefficient bound, state-change monitoring

실험하지 않은 방어는 설계 제안으로만 쓴다.

### 8장. 한계와 책임 있는 공개

- 한 commit, 한 model pair, 한 GPU, 한 worker
- gateway-defined principal이며 native vLLM tenancy가 아님
- exploratory tenant experiment는 outcome-informed이고 `n=4`
- factorial v1은 사전등록 gate 실패로 `INVALID`이며 효과량에 포함하지 않음
- factorial v2의 8-window estimand는 v1의 지연·진동 반응을 pilot으로 보고 고정했지만,
  v2 요청 전에 독립 protocol, threshold, order, source hash를 선언함
- 공격 비용 대비 피해 증폭 미측정
- 8 window 이후 recovery 미측정
- 다른 engine 및 standard-prompt-only 공격 미실증
- GitHub advisory가 비공개라면 공개 허용 전에는 식별자·patch 세부사항을 싣지 않음

GitHub advisory의 인정은 취약점 보고가 maintainer 검토를 통과했다는 disclosure
근거이지, 학술 novelty의 증거는 아니다. novelty는 문제 정의, authenticated
principal 경계, 정량화, causal design 및 기존 연구와의 차이로 방어한다.

### 9장. 결론

일반 취약성을 선언하지 않고, 다음 세 문장으로 끝낸다.

1. online-adaptive serving은 새로운 mutable trust boundary를 만든다.
2. 그 위험은 고정된 vLLM 구성에서 cross-principal factorial experiment로
   인과적으로 확인됐다.
3. principal-aware 또는 influence-bounded adaptation이 향후 controller 설계의
   보안 요구사항이 되어야 한다.

## 7. 권장 그림과 표

페이지가 제한된다면 다음 네 개를 우선한다.

1. **그림 1 — 일반 attack surface:** principal A feedback, shared controller,
   principal B policy의 상태 전이.
2. **그림 2 — vLLM 원인 경로:** API transform부터 estimator와 budget까지의
   source-to-sink 흐름.
3. **그림 3 — factorial timeline과 네 arm:** warmup, pre, intervention, post 및
   attack/placebo × shared/blocked 조작.
4. **그림 4 — 확인 결과:** 8개 block interaction 분포와 8-window interaction
   trajectory를 두 패널로 표시.

필수 표는 다음과 같다.

- 위협 모델과 성립 조건
- 전체 실험 inventory와 validity label
- RQ별 핵심 effect와 interval
- 지원되는 주장과 지원되지 않는 주장

이전 tenant study와 causal study는 발견·설계 history로만 분리해 제시하고 서로
다른 control의 값을 meta-analysis해서는 안 된다. 주 효과량은 네 조건을 한 설계
안에서 측정한 factorial v2에서 가져온다.

## 8. 추가로 필요한 실험

### 완료 — 독립 사전등록 2x2 factorial 확인 실험

이전 판본에서 가장 큰 빈틈은 두 핵심 결과가 별도 연구에 있다는 점이었다.

- tenant study: `attack vs placebo`, estimator update는 둘 다 shared
- causal study: 동일한 `attack`, `shared update vs blocked update`

v2에서 다음 네 arm을 하나의 새 실험으로 묶었다.

| Workload | Estimator update shared | Attack 동안 update blocked |
|---|---|---|
| placebo | P-S | P-B |
| attack | A-S | A-B |

주 효과보다 다음 interaction을 primary endpoint로 둔다.

```text
[(A-S) - (A-B)] - [(P-S) - (P-B)]
```

token `279`, workload, 8-window endpoint와 threshold를 고정하고 새 token screen
없이 8개의 독립 block을 수집했다. 네 arm 순서는 반복 Williams design으로
고정했고, 데이터 생성 전에 rules, schedule, transitive driver hash를 남겼다.
결과는 `CONFIRMATORY_FACTORIAL_SIGNAL`이었고 8/8 block이 adverse였으며 primary
interaction은 -0.2478(95% CI [-0.2586, -0.2380], exact sign-test p=0.00390625)였다.
따라서 별도 tenant study와 causal study를 억지로 결합해야 한다는 가장 큰 reviewer
objection은 제거됐다.

### P0-1. 실제 완화책 한 개 구현 및 평가

가장 직접적인 두 후보 중 하나를 구현한다.

1. request-specific target transform이 있는 요청을 shared estimator update에서 제외
2. principal-scoped estimator 또는 principal별 bounded contribution

공격 성공률뿐 아니라 benign workload의 throughput, acceptance, adaptation speed,
메모리, p50/p95 overhead를 함께 측정한다. 현재 blocked arm은 mechanism
intervention이지 production mitigation이 아니므로, 방어 기여를 주장하려면 별도
구현이 필요하다.

### P0-2. 공격 비용 대비 victim 영향

최소한 다음 두 지표를 계산한다.

```text
victim degraded output tokens / attacker output tokens
victim lost GPU-time / attacker GPU-time
```

가능하면 SLO violation 증가와 공격 종료 뒤 누적 harm area도 보고한다. 이것이 없으면
리뷰어는 결과를 정상적인 resource-proportional workload adaptation으로 볼 수 있다.

## 9. 논문의 가치를 크게 높이는 추가 실험

### P1-1. Recovery-to-baseline

8 window에서 끝내지 말고 baseline band로 돌아올 때까지 victim window를 계속
측정한다. recovery half-life, 요청 수, 시간, cumulative harm을 보고한다. 정해진
최대 window에서 회복하지 않으면 right-censored result로 처리한다.

### P1-2. 직접적인 root-cause 대조군

- target과 draft support를 맞춘 구성
- transform 요청을 update에서 제외한 구성
- 같은 victim을 별도 worker로 보낸 구성

이 대조군은 support mismatch, shared estimator, worker locality를 각각 분리한다.

### P1-3. 최소 일반화 행렬

전체 조합을 탐색하지 말고 다음만 고정한다.

- target/draft model pair 하나 추가
- concurrency 또는 benign load 두 수준
- poison dose 세 수준

effect 방향과 dose-response가 유지되면 단일 특이점이라는 반론을 줄일 수 있다.

### P1-4. 두 번째 서빙 controller

다른 엔진에서 실제 online shared controller가 확인될 때만 동일한 검사 조건을
적용한다. 두 번째 엔진 실증 전에는 제목과 결론을 vLLM case study로 유지한다.
두 번째 구현이 어렵다면 cross-engine section은 정적 design survey와 검사
checklist로 한정한다.

## 10. 있으면 좋은 후속 실험

- `bad_words`, penalties 등 다른 request transform
- 최신 main, 최초 도입 commit, maintainer patch의 version matrix
- 실제 trace 또는 여러 benign workload class
- principal 수 증가에 따른 fairness와 Jain index
- multi-worker load balancer에서 same-worker co-location probability
- GPU utilization, clock, thermal 및 batching 로그를 이용한 교란 요인 분석

## 11. 현재 상태에서 가능한 제출 수준

현재 자료만으로 한국정보보호학회 규모의 empirical case-study 논문은 방어 가능하다.

> 온라인 적응형 serving의 cross-principal control-state risk를 정의하고, vLLM 한
> 구성에서 authenticated-principal propagation과 estimator-mediated effect를
> 실증한 사례 연구.

그러나 다음 제목 수준의 일반 공격 클래스 논문에는 아직 부족하다.

> Cross-engine attacks on online-adaptive LLM serving.

가장 효율적인 다음 순서는 `mitigation -> cost/recovery -> 최소 generality`이다.
factorial confirmation은 완료됐으며, 다음 reviewer objection은 방어가 실제로
가능한지와 공격 비용 대비 피해가 보안상 충분한지다.

## 12. 근거 파일

- `CAUSAL_ABLATION_RESULT_REPORT.md`
- `FACTORIAL_CONFIRMATORY_V2_PROTOCOL.md`
- `FACTORIAL_CONFIRMATORY_V2_DECISION_RULES.md`
- `FACTORIAL_CONFIRMATORY_V2_RESULT_REPORT.md`
- `factorial_confirmatory_v2_result_summary.json`
- `TENANT_SHORT_FOLLOWUP_PROTOCOL.md`
- `TENANT_SHORT_FOLLOWUP_DECISION_RULES.md`
- `results_20260918/FINAL_EXPERIMENT_REVIEW.md`
- `2026-09-17-gate1-real-gpu-result.md`
- `/Users/doha/Downloads/avep-causal-ablation-v2-results.tgz`
- `/Users/doha/Downloads/avep-tenant-short-followup-results.tgz`

무효 causal v1 결과는 effect estimate에 포함하지 않는다.
