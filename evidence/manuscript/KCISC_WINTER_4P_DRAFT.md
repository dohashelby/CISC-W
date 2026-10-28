온라인 적응형 LLM 서빙 제어기의 인증 주체 간 상태 오염:
vLLM 사례 연구와 피드백 격리 설계 제안

이도하*
*세종대학교 (학부생)

Cross-Principal Control-State Contamination in Online-Adaptive LLM Serving:
A vLLM Case Study and Feedback-Isolation Design Proposal

Doha Lee*
*Sejong University (Undergraduate Student)

요 약

대규모 언어 모델의 가중치는 추론 중 고정되지만, 최신 서빙 엔진은 실행 중 수집한 피드백으로 speculative decoding의 검증량 등 처리 정책을 조정한다. 본 논문은 비신뢰 요청이 생성한 피드백이 공유 제어 상태를 갱신하여 다른 인증 주체의 후속 요청에 영향을 주는 ‘인증 주체 간 제어 상태 오염’을 정의한다. 단일 vLLM worker와 두 개의 gateway 인증 주체를 사용해 공격/대조 요청과 estimator 갱신 허용/차단을 교차한 2×2 실험을 수행하였다. 8개 독립 block에서 처리량 interaction은 평균 -0.2478(95% bootstrap 신뢰구간 [-0.2586, -0.2380])이었고 모두 피해 방향이었다(p=0.00390625). 이는 공격 요청의 연산 자체가 아니라 공유 estimator 갱신이 후속 정책과 성능 변화의 필수 매개임을 보인다. 또한 CPU의 speculative-state retirement에서 착안한 Context-Tagged Feedback Retirement(CTFR)를 설계 방향으로 제안한다. CTFR은 피드백을 인증 주체·정책 문맥별 shadow state에 보관한 뒤 검증된 갱신만 retire한다. 본 연구는 CTFR의 완전한 방어 효과를 주장하지 않으며, 단일 구현·구성에서 확인한 사례 연구와 후속 검증이 필요한 설계 제안으로 범위를 제한한다.

주제어: LLM 서빙, 온라인 적응, speculative decoding, 상태 오염, vLLM

1. 서 론

LLM 서빙 보안은 주로 모델 입력·출력, 가중치와 KV cache를 중심으로 논의되어 왔다. 그러나 고성능 서빙 엔진은 모델과 별도로 변하는 runtime control state를 가진다. Speculative decoding은 작은 draft model이 제안한 토큰을 target model이 검증하여 직렬 추론 비용을 줄이며[1], 일부 시스템은 관측된 acceptance feedback으로 이후 검증량이나 draft policy를 온라인 조정한다[2]. 이때 서로 신뢰하지 않는 요청들이 하나의 controller state에 기여하면 request data plane과 장기 제어 상태 사이에 새로운 trust boundary가 생긴다.

본 연구는 이를 cross-principal adaptive control-state contamination으로 정의한다. 핵심은 단순한 동시 자원 경합이나 모델 학습 poisoning이 아니다. 공격 주체 A의 요청이 종료된 뒤에도 A가 만든 feedback이 같은 worker의 공유 상태에 남아, 시간적으로 겹치지 않는 주체 B의 serving policy를 바꾸는지가 문제다. 본 논문의 기여는 다음과 같다. 첫째, 이 위험이 성립하는 상태 전이와 검사 조건을 정식화한다. 둘째, 고정된 vLLM adaptive-verification 구성에서 두 인증 주체와 estimator-update 개입을 사용하여 공격자 feedback, 공유 estimator, 후속 victim 성능 사이의 인과 경로를 검증한다. 셋째, feedback을 즉시 공유 상태에 반영하지 않는 CTFR 설계 원칙을 제안하고 그 보안 속성과 한계를 논한다. 모든 온라인 적응형 엔진이 취약하다고 주장하지 않으며, 실증 범위는 시험한 vLLM 구성으로 한정한다.

2. 배경 및 문제 정의

2.1 온라인 적응형 검증

Speculative decoding에서 draft model은 여러 토큰을 제안하고 target model은 이를 병렬 검증한다. 제안이 자주 채택되면 긴 draft가 이득이지만, acceptance가 낮으면 불필요한 검증 비용이 증가한다. 따라서 controller는 관측된 accept/reject 기록으로 acceptance를 추정하고 다음 요청의 verification budget을 조정할 수 있다. 이는 모델 가중치의 온라인 학습과 구별되는 serving-control adaptation이다. 한편 Online Speculative Decoding은 실제 질의 분포를 이용한 지속적 적응의 성능 이점을 보여주었고[2], test-time adaptation 연구는 비신뢰 표본이 공유 적응 상태를 오염시킬 수 있음을 지적하였다[4]. 그러나 요청 주체에서 서빙 controller를 거쳐 다른 주체의 후속 policy로 이어지는 경로는 별도의 시스템 보안 경계로 다뤄져야 한다.

공유 상태를 s, 주체 p의 feedback과 문맥을 각각 y_p와 c_p, 후속 주체 q의 검증량을 b_q라 하면 다음과 같이 나타낼 수 있다.

s_(t+1)=F(s_t, y_p(t), c_p(t)),   b_q(t+1)=π(s_(t+1), x_q(t+1)).   (1)

다음 조건이 함께 존재하면 검사가 필요한 attack surface가 된다. ① mutable controller state가 요청·주체 사이에 공유되고, ② 비신뢰 요청이 feedback을 조절할 수 있으며, ③ estimator가 주체나 유효 sampling policy를 충분히 구분하지 않고, ④ 변경 상태가 후속 자원 배분을 바꾸며, ⑤ 상태가 요청 종료 뒤에도 유지되고, ⑥ 주체별 격리나 기여량 제한이 없는 경우다.

2.2 위협 모델과 원인 경로

공격자와 victim은 gateway가 인증한 서로 다른 principal이며 하나의 vLLM worker를 합법적으로 이용한다. Gateway는 외부 identity header를 제거하고 내부 principal을 부여한다. 공격자는 지원되는 inference API의 prompt, sampling parameter와 요청 수를 선택할 수 있지만 host, 모델 가중치, GPU memory, estimator telemetry 또는 실험용 update gate에는 접근하지 못한다. 측정 전 공격 queue를 비워 공격 phase와 victim phase를 비중첩시켰다. 이 principal은 실험용 trust boundary이며 vLLM이 native multi-tenancy를 제공한다는 주장이 아니다.

시험한 경로는 ‘request별 target policy 변형 → draft/target acceptance 저하 → worker-shared OnlineAcceptanceEstimator 갱신 → verification budget 변화 → 후속 victim의 처리량·지연 변화’이다. 공격은 모델 출력의 의미를 오염시키기보다 availability와 성능 정책을 겨냥한다. 다른 worker, adaptive verification이 꺼진 구성, 다른 estimator 구현은 실증 범위 밖이다.

3. vLLM 사례 실험

3.1 환경과 방법

실험은 vLLM commit 4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c, Qwen3-4B target과 Qwen3-4B-DFlash-b16 draft, 4 speculative tokens, NVIDIA L40S(AWS g6e.2xlarge) 단일 worker에서 수행하였다. 외부에서는 인증 gateway만 접근할 수 있게 하고 attacker와 victim의 audit event를 worker 요청과 1:1로 결합하였다.

주 확인 실험은 workload(attack/placebo)와 공격 phase의 estimator update(shared/blocked)를 교차한 2×2 factorial design이다. 네 arm은 placebo-shared(P-S), placebo-blocked(P-B), attack-shared(A-S), attack-blocked(A-B)이며, blocked arm도 동일한 speculative decoding과 target verification을 수행하되 estimator의 accumulate/refit만 공격 phase 동안 억제한다. 따라서 공격 workload 자체와 update mode 자체를 각각 통제할 수 있다.

각 arm은 fresh process에서 victim warm-up 1,024건, pre window 128건×4, attacker intervention 4,096건, 비중첩 victim post window 128건×8을 순서대로 수행하였다. 네 arm의 순서는 Williams-balanced order로 배치하고 총 8개 temporal block을 수집하였다. 요청을 독립 표본으로 간주하지 않고 block을 추론 단위로 사용했다. 사전 지정한 주 효과량은 식 (2)의 8-window pre-normalized throughput interaction이다.

I=[(A-S)-(A-B)]-[(P-S)-(P-B)].   (2)

신뢰구간은 paired-block bootstrap, 방향 일관성은 exact sign test로 계산하였다. 모든 32개 arm과 intervention 요청이 완료되었으며 요청 실패와 audit 누락은 없었다.

3.2 결과와 인과 해석

두 attack arm의 draft acceptance는 모두 0.0000이고, 두 placebo arm은 모두 0.1875였다. Blocked 두 arm의 serialized estimator state는 정확히 불변이었다. 반면 shared update가 허용되었을 때 intercept[0]의 attack-by-update interaction은 -13.8508, 8개 post window 평균 normalized verification-budget interaction은 -0.5163이었다. 즉 attack stimulus는 동일하지만 proposed mediator의 변경 여부에 따라 후속 policy가 달라졌다.

네 arm의 평균 post/pre 처리량은 A-S 0.6847, A-B 1.0018, P-S 0.9269, P-B 0.9962였다. 단순 shared-minus-blocked 효과는 attack에서 -0.3172, placebo에서 -0.0693이고, 이를 차감한 주 interaction은 -0.2478이었다. 95% bootstrap 신뢰구간은 [-0.2586, -0.2380]이며 8/8 block이 피해 방향이었다(one-sided exact p=0.00390625). p50과 p95 latency interaction도 각각 +0.5053과 +0.4788로 불리한 방향이었다. 처리량 interaction은 post_01부터 post_08까지 모두 음수였으므로 공격 종료 후 arm당 1,024개의 victim 요청 동안 관측되었다. 다만 이는 baseline-normalized arm 사이의 24.78 percentage-point interaction이지 모든 배포에서 24.78% raw 처리량 손실을 뜻하지 않으며, 관측 이후의 무기한 지속성도 입증하지 않는다.

두 attack arm에는 같은 4,096건의 요청, target 검증과 GPU 작업이 존재했다. 그러나 update만 차단하면 estimator와 후속 policy가 유지되었다. 또한 매 block에서 placebo의 update 효과를 빼 시간 추세나 shared mode의 일반 효과를 통제하였다. 따라서 시험한 구성에서는 ‘공격자가 조절한 verification feedback → 공유 estimator 갱신 → 후속 victim policy → 처리량·지연 저하’라는 좁지만 강한 인과 해석이 지지된다.

4. 피드백 격리 설계 제안

4.1 Context-Tagged Feedback Retirement

즉시 갱신을 단순히 금지하면 안전하지만 정상 workload에 대한 적응 이점도 사라진다. 이에 본 논문은 CPU speculative execution의 shadow state와 retire/squash 생명주기[5] 및 optimistic validation[6]에서 착안한 CTFR을 설계 방향으로 제안한다. 개별 요소 자체를 새로운 것으로 주장하지 않고, 이를 온라인 서빙 feedback의 trust boundary로 결합하는 데 초점을 둔다.

CTFR은 공개된 committed controller state C^v와 아직 공개되지 않은 shadow state U[(p,τ),v]를 구분한다. p는 gateway가 인증한 principal이고, τ는 서버가 target/draft revision, estimator feature contract, 유효 sampling policy와 verification configuration으로부터 만든 context tag이다. 요청은 C^v만 읽고, 관측된 충분통계·observation count·refit clock은 U에만 기록한다. 고정 epoch에서 각 shadow가 clipped candidate를 만들면, 최소 관측량, 서로 다른 principal의 quorum, 방향 일치, principal별 weight와 누적 influence credit, coefficient norm 및 고정 feature-grid의 확률변화 trust region을 검사한다. 모든 검사를 통과한 경우에만 quiescent barrier에서 새 version을 원자적으로 retire하고, 실패하면 candidate를 squash한다.

첫 번째 보안 속성은 retire 전 committed-state invariance이다.

C(after unretired feedback from p)=C(before feedback from p).   (3)

계수뿐 아니라 refit timing과 숨은 누적 통계까지 shadowing하지 않으면 식 (3)은 성립하지 않는다. Retirement 이후 안전성은 더 약하다. CPU branch와 달리 feedback의 benign 여부를 확정하는 resolution oracle이 없으므로, CTFR은 인증·validator coverage·bounded influence·공모 principal 수라는 가정 아래 영향력을 제한할 뿐이다.

4.2 예비 관찰과 주장 경계

단일 worker·두 principal prototype의 예비 five-arm gate(shared, frozen, tenant-local, ctfr-shadow, ctfr-full)는 총 12,960건을 오류 없이 완료했으며, ctfr-shadow에서 retire 전 committed state의 정확한 불변성을 확인했다. 그러나 정상 feedback candidate의 최대 acceptance-probability 변화가 사전 고정한 0.15 bound보다 큰 0.152207이어서 ctfr-full retirement는 fail-closed로 거부되었다. 부분 commit은 없었다. 이 결과는 shadow/commit 경계와 안전한 실패 가능성은 뒷받침하지만, 공격 완화, 정상 적응성 보존, tenant-local 방식 대비 우월성, overhead 또는 분산 환경의 원자성을 입증하지 않는다. 따라서 CTFR은 본 논문에서 검증 완료된 방어책이 아니라 후속 실험이 필요한 설계 제안이다.

5. 논의 및 한계

본 연구가 일반화하는 것은 취약성의 존재가 아니라 검사 가능한 위험 구조다. 다른 서빙 엔진에서도 식 (1)의 공유 상태, 비신뢰 feedback, 문맥 누락, 후속 policy 연결과 지속성이 모두 확인되어야 같은 문제를 주장할 수 있다. 단순 principal별 estimator는 직접 오염을 차단하지만 principal 수만큼 상태가 증가하고 교차-principal 정상 feedback을 활용하지 못한다. 반대로 global clipping·decay는 단일 요청의 영향을 줄여도 slow-drip 누적을 허용할 수 있다. CTFR은 둘 사이의 trade-off를 명시하지만, validator가 benignness oracle이 아니며 quorum은 Sybil resistance가 아니다.

실험은 한 vLLM commit, 한 target/draft pair, 한 GPU, 단일 worker와 고정 workload에 한정된다. Principal은 gateway로 구성했으며 native vLLM tenant 격리를 시험하지 않았다. 8개 post window 이후 recovery half-life, 다른 모델·부하·엔진에서의 재현성, 공격 비용 대비 경제적 증폭도 확립하지 않았다. 특히 CTFR prototype은 quiescent barrier만 사용하므로 concurrent version pinning, stale feedback 처리, crash atomicity, multi-worker publication과 동적 principal eviction은 향후 과제다.

6. 결 론

온라인 적응형 LLM 서빙은 고정된 모델 가중치와 별개로 변경 가능한 control-state trust boundary를 만든다. 본 연구는 이 경계를 인증 주체 간 제어 상태 오염으로 정의하고, 고정된 vLLM adaptive-verification 구성에서 공격에 특이적인 후속 성능 변화가 공유 estimator 갱신을 필요로 함을 2×2 factorial 실험으로 확인하였다. 또한 비신뢰 feedback을 context-tagged shadow에 보관하고 검증 후 retire하거나 squash하는 CTFR을 설계 방향으로 제시하였다. 향후에는 두 번째 서빙 controller, 복수 모델과 부하, recovery 및 cost amplification을 평가하고, CTFR의 정상 적응성·overhead·동시성과 분산 원자성을 검증해야 한다.

참고문헌

[1] Y. Leviathan, M. Kalman, and Y. Matias, “Fast Inference from Transformers via Speculative Decoding,” Proc. ICML, pp. 19274–19286, 2023.
[2] X. Liu, L. Hu, P. Bailis, A. Cheung, Z. Deng, I. Stoica, and H. Zhang, “Online Speculative Decoding,” Proc. ICML, pp. 31131–31146, 2024.
[3] W. Kwon, Z. Li, S. Zhuang, Y. Sheng, L. Zheng, C. H. Yu, J. E. Gonzalez, H. Zhang, and I. Stoica, “Efficient Memory Management for Large Language Model Serving with PagedAttention,” Proc. SOSP, 2023.
[4] T. Wu, F. Jia, X. Qi, J. T. Wang, V. Sehwag, S. Mahloujifar, and P. Mittal, “Uncovering Adversarial Risks of Test-Time Adaptation,” Proc. ICML, pp. 37456–37495, 2023.
[5] K. N. Khasawneh, E. M. Koruyeh, C. Song, D. Evtyushkin, D. Ponomarev, and N. Abu-Ghazaleh, “SafeSpec: Banishing the Spectre of a Meltdown with Leakage-Free Speculation,” Proc. DAC, 2019.
[6] H. T. Kung and J. T. Robinson, “On Optimistic Methods for Concurrency Control,” ACM Trans. Database Syst., vol. 6, no. 2, pp. 213–226, 1981.
