# CTFR 중심 4쪽 논문 구성안

## 권장 제목

**온라인 적응형 LLM 서빙 제어기의 요청 간 상태 오염 완화: vLLM에서의
Context-Tagged Feedback Retirement**

영문:

**Mitigating Cross-Request State Contamination in Online-Adaptive LLM Serving
Controllers: Context-Tagged Feedback Retirement in vLLM**

## 한 문장 논지

> CPU가 speculative side effect를 바로 architectural state에 반영하지 않고
> retire 또는 squash하듯이, 비신뢰 추론 요청이 만든 runtime feedback도 공유
> 서빙 제어기에 즉시 반영하지 않고 인증 context별 shadow state에서 검증한 뒤
> 커밋해야 한다.

CPU retirement를 유일한 중심 비유로 둔다. OCC는 원자적 검증·커밋 구현 원리,
정보흐름 무결성은 low-integrity feedback의 쓰기 금지 규칙을 설명하는 보조
도구로만 배치한다. 여러 분야의 용어를 동급으로 나열하지 않는다.

## 기여 문장

실험이 모두 통과했을 때만 다음 네 기여를 사용한다.

1. 온라인 적응형 서빙에서 request feedback을 speculative trust state로 취급하는
   retirement 경계를 정의한다.
2. committed/unretired controller state를 구분하고, retirement 전
   committed-estimator-state invariance를 정확한 불변식으로 제시한다. 결정 trace
   noninterference는 deterministic replay가 통과할 때만 별도 주장한다.
3. 인증 origin binding, complete shadowing, harness-enforced quiescent promotion을
   포함한 두-principal CTFR prototype을 고정된 vLLM adaptive-verification 구성에
   구현한다.
4. 기존 공격, 동일 policy-domain 공격, slow-drip, benign drift, Sybil 경계 실험으로
   보안성과 적응성의 trade-off를 측정한다.

동일-domain 공격 또는 benign retirement가 아직 성공하지 않으면 4번을 축소하고,
CTFR을 완성된 방어가 아니라 mechanism prototype으로 표시한다.

## 4쪽 배치

### 1쪽: 문제와 연구 공백

- 모델 가중치는 고정되어도 serving controller는 feedback으로 온라인 적응한다.
- 확인 실험의 핵심 수치만 제시한다: 8/8 adverse block, 처리량 interaction
  `-0.2478`, 95% CI `[-0.2586, -0.2380]`.
- 일반적인 poisoning persistence가 아니라 `principal A -> shared controller ->
  later principal B` 경로가 문제임을 명시한다.
- CPU predictor mistraining과 구조적 유사성을 그림 하나로 제시한다.

### 2쪽 전반: 위협 모델과 CTFR

- 공격자는 정상 API와 sampling/prompt 선택권만 가진다.
- trusted gateway principal과 fixed worker를 실험 경계로 명시한다.
- principal을 제외한 policy context `tau`, origin `kappa=(p,tau)`, committed
  `C^v`, shadow `U[kappa,v]`와 retire/squash 상태 전이를 정의한다.
- 계수뿐 아니라 sufficient statistics, observation count, refit clock을 모두
  shadowing하는 이유를 설명한다.
- 강한 보장은 retirement 전이며, retirement 후에는 조건부 영향 bound임을
  박스로 강조한다.

### 2쪽 후반~3쪽: 구현과 실험 설계

- 비교군: shared, drop, PCFR, tenant-local adaptive estimator, CTFR-shadow,
  CTFR-full. tenant-local보다 이점이 없으면 CTFR을 우월한 방어로 주장하지 않는다.
- 공격: 기존 cross-policy, same-policy, slow-drip, 1개 대 2개 공격자 credential.
- 정상성: 두 독립 benign principal의 workload drift와 controlled retirement.
- 단위는 request가 아닌 fresh-process temporal block임을 명시한다.
- exact committed-state invariant, 선택적 deterministic decision replay,
  block-level difference-in-differences를 구분한다.

### 4쪽: 결과, 한계, 결론

- 표 1: 공격 재현과 causal confirmation.
- 표 2: shared/PCFR/CTFR의 attack effect, adaptation gain, overhead.
- ablation은 tag, refit clock shadowing, quorum/influence cap 제거 중 핵심 2개만
  본문에 두고 나머지는 부록 또는 artifact로 보낸다.
- single worker, gateway-defined principal, one model pair, validator blind spot,
  quorum capture, quiescent-only publication, fixed two-bank cardinality, 다른
  엔진 미실증을 명시한다.
- 결론은 "all engines are vulnerable"이 아니라 "feedback retirement is a
  reusable security boundary and vLLM is the validated case study"로 끝낸다.

## 본문에 사용할 수 있는 cross-field 표현

> CTFR is inspired by speculative-state retirement in CPU microarchitecture.
> It reinterprets untrusted serving feedback as speculative control state:
> observations remain context-tagged and invisible to unrelated requests until
> a validator retires them at a quiescent barrier; rejected observations are
> squashed.

Stale-candidate rejection belongs to the target concurrent architecture and is
not described as a property of the first prototype.

다음 표현은 피한다.

- "SafeSpec을 LLM에 최초 적용했다"
- "retirement가 feedback의 benignness를 증명한다"
- "quorum으로 Sybil을 해결했다"
- "CTFR이 모든 online poisoning을 막는다"
- "vLLM 결과로 모든 serving engine의 취약성을 입증했다"

## 현재 증거와 남은 증거

| 항목 | 현재 상태 | 논문 사용 가능 여부 |
| --- | --- | --- |
| estimator-mediated 공격 인과성 | 독립 2x2, 8 block 확인 | 주 결과로 사용 가능 |
| PCFR 설계/코드 | 정적 준비, GPU 미실행 | baseline 설명만 가능 |
| CTFR 설계와 patch | 준비, GPU 미실행 | 제안/구현 예정으로만 표시 |
| tenant-local baseline | 미구현 | full novelty 평가 전에 필수 |
| origin-bound shadow invariant | 아직 GPU 미검증 | 다음 mechanism gate 필요 |
| same-policy superiority | workload 미선정 | novelty 강화에 필수 |
| benign retirement utility | 미실행 | "adaptive mitigation" 주장에 필수 |
| slow-drip/Sybil/overhead | 미실행 | 경계·강건성 평가에 필요 |

따라서 다음 GPU 실행은 성능 본실험이 아니라 CTFR mechanism gate여야 한다. gate가
통과한 뒤 same-policy pilot과 benign-retirement pilot의 hyperparameter를 고정하고,
서로 독립된 confirmatory cohort를 실행한다.
