# AVEP 논문 가능성 평가 메모

> 평가: **CONDITIONAL — 조건부 논문감, 현재는 논문 준비 전 단계**  
> 기준일: 2026-09-16  
> 기준 후보: VLLM-AVEP-2026-09-16  
> 관련 문서: [INCONCLUSIVE 후보 연구보고서](./2026-09-16-vllm-adaptive-verification-estimator-poisoning-candidate.md)  
> 이 문서는 보안 권고문, CVE 주장, 논문 제출본 또는 취약점 검증 결과가 아니다.

## 1. 결론

현재 확보한 정적 경로와 CPU 참조 실험만으로는 논문을 쓰기에 부족하다. 그러나
AWS의 실제 vLLM HTTP·GPU 경로에서 아래 현상이 재현되면 충분히 연구 논문으로
발전시킬 수 있다.

1. 일반 사용자의 정상 스키마 추론 요청이 shared online estimator를 바꾼다.
2. 공격 요청이 끝난 뒤에도 같은 worker의 무관한 요청이 바뀐 estimator를 사용한다.
3. 그 결과 victim의 draft budget, throughput 또는 TPOT가 통제군보다 유의하게
   악화된다.
4. 공격 비용보다 다른 사용자의 손실이 크고, 효과가 즉시 사라지지 않는다.
5. 이 현상이 PR #56724 및 기존 speculative-decoding 공격과 구별된다.

가장 적절한 현재 표현은 **새로운 공격 클래스의 후보**다. 한 vLLM 구성에서만
재현되면 구현 취약점 또는 새로운 공격 원시기법에 가깝다. 여러 모델·구성 또는
다른 적응형 추론 제어기에서도 같은 구조가 확인되어야 BOF, FSB, ROP처럼 독립된
이름을 가진 일반 공격 클래스로 강하게 주장할 수 있다.

## 2. 이름과 주장 범위

| 범위 | 권장 이름 | 사용할 수 있는 조건 |
| --- | --- | --- |
| vLLM의 구체적 메커니즘 | Adaptive Verification Estimator Poisoning, AVEP | HTTP→label→공유 estimator→후속 요청 budget 경로가 재현될 때 |
| 일반화된 공격 패턴 | Serving-Policy Poisoning, SPP | 공격자 트래픽이 장기 online controller를 오염시켜 다른 사용자의 serving decision을 바꾸는 패턴이 일반화될 때 |

일반화된 핵심 불변식은 다음과 같다.

> 한 요청의 공격자 제어 분포 변형이, 다른 요청들이 공유하는 장기 serving
> controller의 신뢰할 수 있는 학습 label로 취급되어서는 안 된다.

이름을 붙이는 것만으로 공격 클래스가 성립하지는 않는다. 논문에서는 vLLM 사례,
일반화 가능한 상태 전이, 공격 비용 대비 victim 영향, 방어 원칙을 함께 보여줘야
한다.

## 3. 현재 증거 수준

| 단계 | 필요한 증거 | 현재 상태 | 가능한 주장 |
| --- | --- | --- | --- |
| E0 | 소스상 입력→상태→sink 경로 | 있음 | 검증할 가치가 있는 가설 |
| E1 | estimator 수학의 component 재현 | 있음 | 계수와 budget 모의가 변할 수 있음 |
| E2 | 실제 HTTP→GPU→후속 요청 경로 | 없음 | 아직 exploitable이라고 할 수 없음 |
| E3 | victim SLA 피해와 공격 경제성 | 없음 | DoS·가용성 침해라고 할 수 없음 |
| E4 | 일반성, 신규성, 방어책 평가 | 없음 | 새로운 공격 클래스라고 할 수 없음 |

현재 단계는 **E1**이다. CPU 결과는 vLLM end-to-end 재현이 아니라 estimator
수학의 component 증거로만 취급한다.

### 결과별 현실적인 연구 가치

| 실제 결과 | 해석 | 현실적인 산출물 |
| --- | --- | --- |
| estimator 계수만 움직이고 victim 성능은 변하지 않음 | 보안 영향 미입증 | 설계 관찰 또는 버그 노트 |
| 공격자 자신의 요청에서만 acceptance가 붕괴 | 기존 ADSD·Mistletoe 계열과 가까움 | 차별성이 약한 후속 연구 |
| 한 모델·한 GPU에서 후속 victim 영향 재현 | 교차 요청 취약점의 유력한 증거 | 보안 보고서, workshop 또는 short paper 후보 |
| 여러 seed·부하·모델에서 낮은 비용의 지속 피해 재현 | 강한 시스템 보안 결과 | full paper 후보 |
| 둘 이상의 구현 또는 controller에서 동일 패턴과 공통 방어 검증 | 일반 공격 원시기법으로 확장 | 이름 붙은 공격 클래스 주장 가능 |

CPU 참조 실험에서는 계수와 budget steering이 보였지만, 실제 victim SLA 영향은
아직 없다.

## 4. 논문의 핵심 연구 질문

- **RQ1 — Reachability:** 일반 HTTP 추론 요청만으로 estimator의 학습 label을
  공격자가 편향시킬 수 있는가?
- **RQ2 — Cross-request persistence:** 공격 요청 종료 후 무관한 victim 요청이
  오염된 공유 상태를 실제로 사용하는가?
- **RQ3 — Impact and amplification:** 공격 토큰·GPU 시간 대비 victim throughput,
  TPOT, ITL 손실은 얼마나 큰가?
- **RQ4 — Recovery:** 정상 트래픽으로 회복되는 데 몇 step과 얼마의 시간이
  필요한가?
- **RQ5 — Generality:** 모델, draft model, 동시성, context 길이, sampling transform,
  GPU 또는 backend가 달라도 현상이 유지되는가?
- **RQ6 — Defense:** 관측 제외, support 정렬, estimator 분리, clipping·decay 중
  어떤 방어가 정확도와 가속 성능을 가장 적게 훼손하는가?

## 5. 반드시 입증해야 하는 인과 사슬

공격자는 운영자나 내부 peer가 아니라, 공개되었거나 인증을 거쳐 **일반 inference
API를 사용할 권한이 있는 client**로 정의한다. 아래 여섯 단계가 하나의
end-to-end 실험에서 연결되어야 한다.

```text
attacker HTTP request
  → target-only sampling transform
  → biased accept/reject observations
  → shared estimator coefficient shift
  → later unrelated victim's draft-budget change
  → measurable victim throughput/latency degradation
```

다음 통제군이 빠지면 인과 주장이 약해진다.

1. adaptive verification을 끈 동일 트래픽
2. 새 프로세스에서 실행한 동일 victim
3. target과 draft의 sampling support를 맞춘 구성
4. 공격 입력 없이 같은 양의 중립 트래픽을 보낸 구성
5. 가능하면 victim을 다른 worker에 보낸 격리 구성

## 6. 논문 수준의 측정 기준

- 같은 prompt, seed, 길이, 부하를 사용하는 randomized paired run을 수행한다.
- warm-up과 startup profiling 구간을 측정에서 제외한다.
- 여러 독립 실행을 반복하고 평균만이 아니라 분산, 95% 신뢰구간, p50·p95를
  보고한다.
- 계수 변화뿐 아니라 selected draft budget, accepted/drafted tokens, output
  tokens/s, TPOT, ITL, TTFT를 함께 기록한다.
- attack phase가 끝난 시점을 고정하고 회복 곡선과 half-life를 측정한다.
- 공격 효율을 `victim GPU-time loss / attacker GPU-time` 또는
  `victim degraded tokens / attacker tokens`처럼 명시적인 증폭률로 정의한다.
- 공격 문자열 하나에 과적합하지 않도록 allowed tokens, bad words, penalties 등
  서로 다른 입력군을 분리 평가한다.
- OOM, CUDA graph 재캡처, thermal drift, request batching 순서가 결과를 설명하지
  못하도록 로그와 통제 실험을 남긴다.

논문 채택 가능성을 높이는 것은 큰 숫자 하나가 아니라, 피해가 공격자 입력에서
공유 상태를 거쳐 victim에게 전달되었다는 재현 가능한 인과 증거다.

## 7. AWS 실험 단계와 예상 비용

기준 구성은 후보 보고서의 Seoul `g6e.2xlarge` 단일 L40S, 200GB gp3,
`TRITON_ATTN`, 단일 worker, TP=1, PP=1이다. API는 `127.0.0.1`에만 bind하고
SSM으로 접속한다. 실제 AWS 자원은 아직 생성하지 않았다.

| 단계 | 목적 | 예상 GPU 시간 | 같은 g6e 기준 비용 예시 |
| --- | --- | ---: | ---: |
| Gate 1 | 기동·HTTP 도달성·한 번의 교차 요청 효과 판별 | 4~6시간 | 약 1.7만~2.5만원 |
| Gate 2 | paired repetition, 회복 곡선, 공격 비용 곡선 | 30~60시간 | 약 12.5만~25만원 |
| Gate 3 | 모델·부하·입력군 일반화와 방어 평가 | 100~200시간 상당 | 약 41.7만~83.4만원부터 |

비용은 2026-09-16에 확인한 `g6e.2xlarge` 시간당 USD 2.75652, public IPv4,
200GB gp3의 시간 비례분, VAT 10%, USD 1 = KRW 1,360.66 가정을 사용한
대략값이다. Gate 3에서 다른 GPU나 여러 instance를 쓰면 달라진다. 첫 Gate가
실패하면 즉시 중단해 이후 비용을 쓰지 않는다.

## 8. 선행연구와의 차별화 경계

가장 큰 novelty 위험은 다음 네 가지다.

- [vLLM PR #52228](https://github.com/vllm-project/vllm/pull/52228)은 pooled
  online estimator, mixed clients, workload drift와 지속 refit을 이미 공개했다.
- [vLLM PR #56724](https://github.com/vllm-project/vllm/pull/56724)은 target과
  draft의 top-k/top-p 불일치가 online calibration을 훼손할 수 있음을 명시했다.
- [ADSD](https://arxiv.org/abs/2607.21804)와
  [Mistletoe](https://arxiv.org/abs/2605.14005)는 adversarial prompt로 현재
  요청의 speculative acceptance 또는 acceleration을 무너뜨리는 연구다.
- 일반적인 online-learning poisoning 자체는 이미 확립된 개념이다.

따라서 논문의 신규성은 “acceptance collapse”나 “sampling mismatch” 자체가
아니다. 방어 가능한 차별점은 다음 조합이다.

> 정상 추론 API의 요청별 정책이 장기 공유 estimator의 label을 오염시키고,
> 공격이 끝난 후 다른 tenant의 adaptive serving policy와 SLA를 바꾸는 상태 전이

논문과 보고서에서는 “세계 최초”라고 쓰지 말고, 검색 시점과 범위를 명시한 뒤
“동일한 root-cause fingerprint를 공개 기록에서 찾지 못했다”고 제한해야 한다.
PR #56724가 같은 수정으로 해결된다면 신규성은 약해지거나 중복으로 판정될 수
있다.

## 9. 실용성의 약점

- adaptive verification은 기본값이 아닌 opt-in 기능이다.
- 후보 코드는 기준일 현재 공개 release가 아니라 main에만 있다.
- 상태는 worker-local이므로 victim이 같은 replica에 배치되어야 한다.
- target output은 rejection sampling 때문에 정상 분포를 유지하도록 설계되어
  있어, 예상 피해는 기밀성·무결성이 아니라 성능·가용성이다.
- 빠른 online refit으로 즉시 회복되면 실제 피해가 작을 수 있다.

이 약점들은 숨기기보다 명시해야 한다. full paper로 만들려면 “현재 vLLM의 큰
취약점”보다 “사용자 트래픽으로 학습하는 적응형 inference controller의 새로운
trust-boundary 문제”로 프레이밍하는 편이 더 강하다.

## 10. 방어 기여가 필요한 이유

공격 재현만으로는 단일 구현 버그 논문에 머물 수 있다. 아래 방어를 구현하고
성능 손실까지 비교하면 연구 기여가 커진다.

1. draft에 반영되지 않은 target-only transform이 있는 요청을 학습에서 제외
2. estimator feature와 verifier label의 sampling support 정렬
3. sampling signature 또는 tenant별 estimator 분리
4. 요청별 update contribution 제한과 robust clipping
5. 오래된 관측의 decay, 계수 경계, 이상 변화 모니터링

각 방어는 attack success뿐 아니라 정상 workload의 acceptance rate, throughput,
메모리와 latency overhead로 평가해야 한다.

## 11. 추천 논문 구조

1. 적응형 LLM serving에서 새로 생기는 공유 학습 상태의 trust boundary
2. speculative decoding과 vLLM adaptive verification 배경
3. Serving-Policy Poisoning의 일반 모델과 공격 조건
4. AVEP vLLM 사례의 source-to-state-to-victim 분석
5. 재현 가능한 AWS 실험 방법과 통계 설계
6. 공격 비용, 지속성, victim 피해, 일반화 결과
7. 방어 설계와 성능 trade-off
8. 기존 acceptance-collapse·online-poisoning 연구와의 차이
9. 책임 있는 공개, opt-in/main-only 범위와 한계

서로 다른 논리적 tenant와 같은 worker 배치가 실제로 확인된 뒤의 제목 후보는
다음과 같다. 그전에는 제목에서도 `Cross-Request`를 사용한다.

> **Serving-Policy Poisoning: Cross-Tenant Attacks on Online-Adaptive LLM
> Inference**

## 12. Go/No-Go 판정

다음을 모두 만족하면 full paper 작업을 시작할 근거가 생긴다.

- [ ] 실제 HTTP·GPU 경로에서 공격 입력이 estimator를 바꾼다.
- [ ] 공격 종료 후 별도 neutral victim의 budget이 바뀐다.
- [ ] throughput 또는 latency 피해가 반복 실행의 noise floor를 넘는다.
- [ ] adaptive-off, fresh-process, matching-support 통제군에서는 효과가 사라진다.
- [ ] 공격 비용 대비 victim 피해의 증폭이 실용적으로 의미 있다.
- [ ] 한 구성에만 우연히 나타난 결과가 아님을 보인다.
- [ ] PR #56724와 동일 수정·동일 결함이 아님을 다시 확인한다.
- [ ] 적어도 하나의 저비용 방어가 효과와 정상 성능을 함께 보존한다.

반대로 victim SLA 영향이 없거나, 효과가 공격자 자신의 요청에만 국한되거나,
정상 refit 몇 step 안에 사라지거나, PR #56724와 같은 수정으로 완전히 해결되면
논문 주장은 크게 축소해야 한다.

현재의 정확한 판정은 **“아이디어는 논문감이 될 수 있지만, 후보 자체는 아직
INCONCLUSIVE이며 AWS end-to-end 결과가 첫 번째 결정적 관문”**이다.

양성 결과가 나오더라도 논문 공개보다 vLLM의 비공개 보안 보고와 수정 조율을 먼저
진행해야 한다.
