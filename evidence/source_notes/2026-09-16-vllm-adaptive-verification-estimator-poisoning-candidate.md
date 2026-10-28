# INCONCLUSIVE — vLLM Adaptive Verification Estimator Poisoning 후보 연구보고서

> 상태: 미검증 취약점 후보  
> 이 문서는 보안 권고문, CVE 요청서, 공개용 글 또는 제출본이 아니다.  
> 실제 GPU 영향과 사용자 가시적 피해가 검증되기 전에는 외부 공개·제출하지 말 것.

## 1. 문서 메타데이터

| 항목 | 값 |
| --- | --- |
| 후보 ID | VLLM-AVEP-2026-09-16 |
| 가칭 | Adaptive Verification Estimator Poisoning, AVEP |
| 다른 이름 | Cross-request Serving-Policy Poisoning |
| 현재 판정 | INCONCLUSIVE |
| 연구일 | 2026-09-16 |
| 저장소 | vllm-project/vllm |
| CPU 참조 실험 SHA | 6ecd97f1b7fb13991065370f6d6be3dffe9fe1db |
| 최신 정적 재검토 SHA | 4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c |
| 예상 영향 범주 | 정확도 훼손이 아닌 성능·가용성 저하 |
| CVSS/CWE | 미할당 — 영향 검증 전 산정하지 않음 |

## 2. 한 문장 가설

adaptive verification을 켠 비-confidence-head speculative decoding 구성에서,
일반 추론 사용자가 target에만 적용되는 토큰 제약을 반복해 보내면
accept/reject label을 의도적으로 편향시킬 수 있고, 이 label이 worker 전체가
공유하는 온라인 acceptance estimator를 갱신해 같은 worker의 뒤이은 무관한
요청들의 verification budget과 성능을 바꿀 수 있다.

이 가설은 소스 수준에서는 연결되지만, 실제 HTTP→모델→GPU 경로와 피해량은
아직 검증되지 않았다. 따라서 현재 문서가 주장하는 것은 취약점의 존재가 아니라
검증할 가치가 있는 공격 원시기법 후보의 존재다.

## 3. 후보의 의미론적 지문

| 필드 | 후보 내용 |
| --- | --- |
| 공격자 진입점 | 일반 chat/completion 추론 요청의 allowed_token_ids가 가장 강한 입력이다. bad_words와 repetition/frequency/presence penalties도 같은 계열의 후보 입력이다. |
| 깨질 수 있는 불변식 | 한 요청에서 target에만 적용된 분포 변형이 다른 요청들이 공유하는 장기 serving controller의 학습 label이 되어서는 안 된다. 또는 estimator feature와 label은 같은 sampling support를 나타내야 한다. |
| 상태·sink | worker 수명 동안 공유되는 OnlineAcceptanceEstimator의 slope/intercepts와, 이를 사용해 계산되는 adaptive verification draft budget |
| 필요 조건 | adaptive verification opt-in, confidence head가 없는 draft-model speculator, 지원 attention backend와 full CUDA graph, 같은 worker/replica, 최소 한 번 이상의 refit |
| 가설상 영향 | 공격 요청이 끝난 뒤에도 무관한 victim 요청의 speculative acceleration이 줄어 output throughput 또는 TPOT가 악화 |
| 가능한 수정 형태 | target-only 변형 요청의 관측 제외, draft/target support 정렬, calibration domain 분리, 요청별 기여도 제한, 계수·회복률 경계 또는 tenant/workload 격리 |

## 4. 최신 main의 정적 데이터 흐름

최신 main은 2026-09-16 UTC에
4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c로 동기화했다. 이전 참조 실험
SHA에서 최신 SHA까지의 네 커밋은 아래 관련 경로를 변경하지 않았고, 후보의
정적 경로는 그대로다.

1. 일반 OpenAI 호환 요청이 제약을 받는다.

   ChatCompletionRequest는 penalties, allowed_token_ids, bad_words를 받고
   SamplingParams로 넘긴다.
   [요청 필드](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/entrypoints/openai/chat_completion/protocol.py#L213-L301),
   [SamplingParams 변환](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/entrypoints/openai/chat_completion/protocol.py#L672-L758)

2. target verifier의 분포가 요청별로 바뀐다.

   target sampler는 allowlist, penalties, bad words를 logits에 적용한다.
   특히 allowlist는 허용 목록 밖의 logits를 음의 무한대로 만든다.
   [sampling parameter 적용](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/sample/sampler.py#L209-L274),
   [allowlist mask](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/sample/logit_bias.py#L193-L226)

3. draft 쪽에는 같은 변형이 전달되지 않는다.

   DraftModelSpeculator의 request-input 복사는 temperature와 seed만 받으며
   다른 sampling parameter를 무시한다고 명시한다. 현재 함수 시그니처에는
   allowed_token_ids, bad_words, penalties가 없다.
   [draft 입력 복사](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/speculator.py#L475-L496)

4. 변형된 target 분포가 draft token을 채점한다.

   처리된 target logits가 rejection sampler로 들어간다. greedy 경로에서는
   target argmax와 draft token의 일치 여부가 accept/reject 결과를 만든다.
   [target 처리와 rejection 진입](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/rejection_sampler.py#L168-L208),
   [rejection 계산](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/rejection_sampler_utils.py#L551-L666)

5. 모든 활성 요청의 label이 공용 estimator를 갱신한다.

   num_sampled/num_rejected는 observe_verification을 거쳐
   OnlineAcceptanceEstimator.step으로 전달된다. estimator는 관측을 공용
   info, grad, counts에 합치며 100 step마다 공용 slope/intercepts를 다시
   적합한다.
   [model runner 전달](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/model_runner.py#L2107-L2120),
   [label 누적 커널](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py#L24-L88),
   [공용 상태와 refit](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py#L313-L448)

6. 바뀐 계수가 뒤이은 요청의 serving budget에 들어간다.

   estimator가 새 draft logits로 confidence를 예측하고, manager는 confidence의
   누적 생존확률과 시작 시 측정한 비용표로 global draft budget을 선택한다.
   [예측과 관측](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/speculator.py#L439-L466),
   [budget 계산](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/adaptive_verification.py#L280-L348),
   [scheduler 연동](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/model_runner.py#L1226-L1246)

새 요청을 추가할 때 per-request confidence는 1.0으로 초기화되지만 공용 estimator
계수는 초기화되지 않는다.
[새 요청 초기화](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/adaptive_verification.py#L179-L182)
따라서 정적 구조만 보면 cross-request persistence가 성립한다. 프로세스를
재시작하면 메모리 상태가 사라지고, replica 사이에는 공유되지 않는다.

## 5. 현재까지의 동적 근거

### 5.1 실행한 것

실제 vLLM 서버가 아닌, estimator update와 budget 선택식을 분리한 CPU/PyTorch
참조 실험을 이전 SHA 6ecd97f1b7fb13991065370f6d6be3dffe9fe1db에서
실행했다.

| 관찰 | 결과 |
| --- | --- |
| bounded estimator iterations | 600 |
| position 0 관측 수 | 6,400 |
| position 0 accepted label | 4 |
| neutral victim의 초기 p0 | 0.9214010175 |
| 편향 관측 뒤 같은 victim feature의 p0 | 1.4938946922e-08 |
| 대표 capture-boundary budget 모의 | poison arm 0/256, neutral controls 256/256; 한 고비용 control은 192/256 |
| 실행시간 | 0.437초 |
| assertion | 모두 통과 |

이 수치는 estimator 수학이 극단적으로 움직일 수 있다는 증거일 뿐, 실제 GPU
서버가 같은 값이나 피해량을 보인다는 증거가 아니다.

### 5.2 음성 대조군

- 제약이 없는 관측과 draft/target 분포가 일치하는 관측은 같은 붕괴를 만들지 않았다.
- 새 estimator를 만들면 초기 상태로 복원됐다.
- 새 request slot 또는 per-request confidence reset은 이미 학습된 공용 계수를
  지우지 않았다.
- adaptive verification을 끈 경우 budget coupling이 없었다.
- 관측 수가 0인 round는 계수를 움직이지 않았다.

### 5.3 실행하지 못한 것

- 실제 OpenAI 호환 HTTP 요청
- 실제 Qwen target/DFlash draft forward
- Triton estimator kernel과 CUDA graph
- L40S 또는 다른 GPU의 실제 startup cost table
- 공격 전·후 output throughput, TPOT, ITL, p95 latency
- 회복까지 필요한 실제 요청 수와 시간
- 여러 프로세스·replica·로드밸런서에서의 도달 확률
- 출력 동일성 및 lossless 동작의 실모델 확인

따라서 VERIFIED, exploitable, affected version, severity라는 표현을 사용하면 안 된다.

## 6. 후보를 약화시키는 반증 가능성

이 후보는 다음 이유로 실제 취약점이 아닐 수 있다.

- 이 기능은 기본값이 false인 opt-in 기능이다.
- 설계 자체가 현재 serving workload에 적응하도록 만들어졌다. 한 tenant의 합법적
  sampling regime이 공용 모델을 바꾸는 것을 maintainers가 의도된 동작으로 볼 수 있다.
- 원 PR의 자연스러운 workload-shift 실험에서는 estimator가 대략 100~200 engine
  step 안에 새 regime을 추적했다. 공격이 끝난 직후 빠르게 회복하면 victim impact가
  미미할 수 있다.
- confidence head가 있는 DSpark 구성은 이 online estimator를 사용하지 않는다.
- worker-local 상태이므로 공격자와 victim이 다른 replica로 라우팅되면 연결이 끊긴다.
- target output은 rejection sampling 때문에 정상 분포를 유지하도록 설계됐다.
  현재 가설은 성능·가용성뿐이며 무결성 또는 기밀성 침해가 아니다.
- reverse proxy가 확장 sampling parameter를 차단하거나 tenant별 worker 격리를 하면
  공격 표면이 사라진다.
- 실제 cost curve에서 draft budget 0이 최적이 아니거나, 낮아진 budget이 오히려
  해당 부하에서 더 빠를 수도 있다.

## 7. 버전과 배포 상태

핵심 estimator는
[PR #52228](https://github.com/vllm-project/vllm/pull/52228)의
[커밋 3bb0a03](https://github.com/vllm-project/vllm/commit/3bb0a03f35269185b6358753e64932bb946cc531)에서
2026-09-14에 main으로 들어왔다.

2026-09-16 기준 최신 공개 release는
[v0.29.0](https://github.com/vllm-project/vllm/releases/tag/v0.29.0)이며
2026-09-09에 공개됐다. 해당 도입 커밋을 포함하는 release tag는 없다. 따라서
현재 검토 대상은 main-only 코드이고, 공개 release가 취약하다고 주장할 근거가 없다.

## 8. 신규성 검토

### 8.1 내부 prior art

로컬 private corpus 7건을 전수 인벤토리했다.

- corpus SHA-256:
  6b3ea82322eff94bc5f556cf7cc97991181d96e4fdff51d81a5b61d3678c9dc7
- 동일 의미 지문: 없음
- 후보 ledger 상태: inconclusive

이 문서는 검증된 private reports corpus에는 넣지 않았다.

### 8.2 공개 prior art

- [PR #52228](https://github.com/vllm-project/vllm/pull/52228)은 online
  estimator, 공용 slope, mixed-client temperature, workload drift와 연속 refit을
  이미 공개했다. 따라서 “online acceptance estimator가 workload에 의해 움직인다”는
  사실 자체는 신규가 아니다.
- [PR #56724](https://github.com/vllm-project/vllm/pull/56724)는 draft와
  target의 top-k/top-p support 불일치가 online calibration에 영향을 준다고
  명시하고 draft support를 맞추는 변경을 제안한다. 이는 가장 가까운 공개 sibling이며
  이 후보가 duplicate로 판단될 위험을 높인다.
- [ADSD](https://arxiv.org/abs/2607.21804)와
  [Mistletoe](https://arxiv.org/abs/2605.14005)는 adversarial input으로
  speculative acceptance와 acceleration을 직접 무너뜨리는 선행 연구다. 다만 두
  연구는 공격자의 현재 요청을 느리게 하는 것이 중심이고, 공격 트래픽이 끝난 뒤
  공용 학습 controller를 통해 다른 요청의 budget을 바꾸는 상태 전이는 다루지 않는다.
- [GHSA-83vm-p52w-f9pw](https://github.com/vllm-project/vllm/security/advisories/GHSA-83vm-p52w-f9pw)는
  penalty 요청이 speculative proposer를 즉시 crash시키는 별도 shape bug다.
  공격 입력 일부는 겹치지만 장기 estimator 상태, 후속 요청, sink와 수정 형태가 다르다.
- 온라인 학습 poisoning 자체도
  [Wang과 Chaudhuri](https://arxiv.org/abs/1808.08994) 등에서 확립된 개념이다.
  이 후보의 잠재적 신규성은 일반 개념이 아니라 vLLM의 특정 요청→label→serving
  controller 상태 전이에만 있다.

2026-09-16 06:05 UTC 기준 공개 issue/PR 검색과 vLLM advisory 76건,
PyPI vllm 관련 GitHub Advisory Database 70건에서는 다음의 전체 지문을 직접
다루는 기록을 찾지 못했다.

target-only allowed_token_ids/bad_words/penalties
→ 고의 label 편향
→ worker-local persistent estimator
→ 뒤이은 무관한 요청의 verification budget steering

따라서 신규성 판정은 “좁은 의미에서 잠정 지원”이다. 일반 online poisoning이나
speculative acceptance collapse가 새롭다고 주장해서는 안 된다. 실GPU 영향이 확인된
뒤에도 PR #56724의 단순 sibling으로 분류될 가능성을 다시 평가해야 한다.

## 9. AWS 검증 서버 설계

### 9.1 권장 단일 노드

| 항목 | 권장값 |
| --- | --- |
| Region | ap-northeast-2, Seoul |
| 구매 방식 | On-Demand |
| Instance | g6e.2xlarge |
| GPU | NVIDIA L40S 1개, 48GB |
| CPU/RAM | 8 vCPU, 64GiB |
| Local storage | 450GB NVMe instance store |
| Root storage | 암호화 gp3 200GB, DeleteOnTermination=true |
| AMI | AWS Deep Learning Base OSS Nvidia Driver GPU AMI, Ubuntu 24.04 |
| 프로세스 구조 | 단일 instance, 단일 worker, TP=1, PP=1, replica 없음 |
| 접속 | SSM Session Manager 우선 |
| Security Group | inbound 없음; 불가피한 SSH는 연구자 IP /32의 TCP 22만 |
| API bind | 127.0.0.1:8000 |
| IAM | AmazonSSMManagedInstanceCore 수준의 최소 instance profile |
| Metadata | IMDSv2 강제 |

[AWS G6e 사양](https://aws.amazon.com/ec2/instance-types/g6e/)에 따르면
g6e.2xlarge는 L40S 48GB, 8 vCPU, 64GiB RAM, 450GB local NVMe를 제공한다.
[AWS region 표](https://docs.aws.amazon.com/ec2/latest/instancetypes/ec2-instance-regions.html)는
Seoul에서 G6e family가 제공됨을 표시하지만, 모든 Availability Zone에서 용량이
보장되지는 않는다.

### 9.2 모델 조합

| 역할 | 모델 | 고정 revision |
| --- | --- | --- |
| target | Qwen/Qwen3-4B | 1cfa9a7208912126459214e8b04321603b3df60c |
| draft | z-lab/Qwen3-4B-DFlash-b16 | b74e3a329c4d963783143b1e970d95b002be72bd |

Hugging Face는 target을 4B BF16, draft를 0.5B BF16으로 표시한다.
[target](https://huggingface.co/Qwen/Qwen3-4B),
[draft](https://huggingface.co/z-lab/Qwen3-4B-DFlash-b16)
두 저장소의 합산 weight 크기는 대략 9.1GB다. vLLM의 CPU smoke suite도 이
target/draft 쌍과 4 speculative tokens를 사용한다.
[현재 테스트](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/tests/v1/e2e/test_cpu_spec_decode.py#L109-L140)

48GB는 이 weight와 제한된 4096-token 실험, KV cache, full CUDA graph를 함께
담을 현실적인 첫 선택이다. 다만 64개 요청이 모두 4096-token context를 동시에
채우는 구성은 목표가 아니다. 짧은 prompt와 max-num-batched-tokens 4096로
실험을 제한한다. OOM이면 max-num-seqs 32, gpu-memory-utilization 0.75,
max-model-len 2048 순으로 낮추되 full CUDA graph 요구는 유지한다.

### 9.3 L40S에서 attention backend를 고정해야 하는 이유

현재 adaptive manager는 모든 target attention builder가
AttentionCGSupport.ALWAYS를 보고해야 시작한다.
[startup gate](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/worker/gpu/spec_decode/adaptive_verification.py#L448-L503)

L40S는 일반적으로 FlashAttention 2 경로이며, vLLM의 FA2 builder는
UNIFORM_BATCH만 보고한다.
[FlashAttention support](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/attention/backends/flash_attn.py#L546-L575)
반면 TRITON_ATTN은 ALWAYS와 non-causal attention을 지원한다.
[Triton CUDA-graph support](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/attention/backends/triton_attn.py#L99-L110),
[non-causal support](https://github.com/vllm-project/vllm/blob/4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c/vllm/v1/attention/backends/triton_attn.py#L306-L324)

따라서 target CLI와 draft speculative config 모두 TRITON_ATTN으로 고정한다.
자동 backend 선택을 쓰면 startup에서 실패할 수 있다.

### 9.4 네트워크 경계

이 실험은 소유한 AWS 계정의 단일 연구 instance에서만 수행한다.

- TCP 8000, 29500, 14579, gRPC 포트를 인터넷이나 다른 VPC host에 열지 않는다.
- VLLM_SERVER_DEV_MODE, profiler, gRPC, Ray, LoRA, batch-sharded sampling을
  켜지 않는다.
- public subnet을 쓰더라도 ephemeral public IPv4와 inbound 0개를 사용하고
  SSM outbound 세션만 허용한다. NAT Gateway나 Elastic IP는 만들지 않는다.
- 실제 사용자 prompt, credential 또는 production traffic을 사용하지 않는다.
- public 모델이라 HF token은 필요 없다. remote code는 아래 고정 revision을
  검토한 뒤에만 신뢰한다.

## 10. AWS 기동 절차

### 10.1 사전 조건

1. Seoul의 Running On-Demand G and VT instances quota가 최소 8 vCPU인지 확인한다.
2. 예상 비용 경보를 USD 40에 설정한다. Budget 알림은 실시간 차단 장치가 아니므로
   종료 시각도 별도로 정한다.
3. Ubuntu 24.04 GPU DLAMI를 선택하고 gp3 DeleteOnTermination을 확인한다.
4. SG inbound는 비워 두고 SSM instance profile만 연결한다.

### 10.2 vLLM 준비

저장소 정책에 따라 system python 또는 bare pip를 쓰지 않고 uv와 .venv를 쓴다.

~~~bash
git clone https://github.com/vllm-project/vllm.git
cd vllm
git fetch origin
git checkout 4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c

uv venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements/lint.txt
pre-commit install
VLLM_USE_PRECOMPILED=1 uv pip install -e . --torch-backend=auto

git rev-parse HEAD
nvidia-smi
~~~

### 10.3 첫 서버 기동안

이 명령은 검증용 실험안이다. 현재 사용자 문서와 config docstring은 아직
adaptive verification을 DSpark-only로 설명하지만, PR #52228과 현재 구현은
generic estimator 경로를 포함한다. 따라서 기동 성공 자체가 첫 번째 gate다.

~~~bash
export VLLM_USE_V2_MODEL_RUNNER=1
export VLLM_HOST_IP=127.0.0.1
export VLLM_ADAPTIVE_VERIFICATION_PROFILE_CONTEXT_LEN=4096

vllm serve Qwen/Qwen3-4B \
  --revision 1cfa9a7208912126459214e8b04321603b3df60c \
  --host 127.0.0.1 \
  --port 8000 \
  --api-key local-research-only \
  --dtype bfloat16 \
  --trust-remote-code \
  --max-model-len 4096 \
  --max-num-seqs 64 \
  --max-num-batched-tokens 4096 \
  --gpu-memory-utilization 0.80 \
  --no-enable-prefix-caching \
  --attention-backend TRITON_ATTN \
  --compilation-config '{"cudagraph_mode":"FULL_AND_PIECEWISE"}' \
  --speculative-config '{
    "method":"dflash",
    "model":"z-lab/Qwen3-4B-DFlash-b16",
    "revision":"b74e3a329c4d963783143b1e970d95b002be72bd",
    "code_revision":"b74e3a329c4d963783143b1e970d95b002be72bd",
    "attention_backend":"TRITON_ATTN",
    "num_speculative_tokens":4,
    "max_model_len":4096,
    "enable_adaptive_verification":true
  }'
~~~

기동 로그에서 다음을 확인하지 못하면 공격 실험으로 진행하지 않는다.

- V2 model runner가 실제 선택됨
- target과 draft 모두 TRITON_ATTN 사용
- adaptive verification manager 생성 성공
- acceptance estimator 생성 성공
- startup cost profiling과 CUDA graph capture 성공
- OOM, fallback, eager-mode 전환, NaN 없음

## 11. 제한된 GPU 검증 설계

### 11.1 실험 팔

| 팔 | 설명 | 목적 |
| --- | --- | --- |
| A | adaptive on, neutral traffic만 | 정상 drift와 noise floor |
| B | adaptive on, neutral baseline→bounded poison→무관한 neutral victim | 후보 메커니즘 |
| C | adaptive off, 같은 traffic | adaptive coupling 음성 대조 |
| D | fresh process 후 같은 victim | process-local persistence 대조 |
| E | target/draft support가 일치하는 제약 | mismatch가 핵심인지 확인 |

모든 팔은 같은 prompt, seed, max_tokens, concurrency 순서를 사용하고 서버 warmup
뒤 측정한다. 순서효과를 줄이기 위해 A/B 순서를 바꾼 paired run을 최소 세 번 한다.

### 11.2 bounded poison 입력

가장 단순한 후보는 한 개의 유효 vocab ID만 허용하는 allowed_token_ids다. 선택한
ID는 draft top-1과 대체로 다르되 target request 자체는 schema-valid해야 한다.
처음에는 최대 600 estimator step과 concurrency 64를 상한으로 두고, 오류율,
GPU memory 또는 latency가 사전 중단선에 닿으면 즉시 멈춘다.

요청 형태는 다음 수준으로만 고정한다. CONTROL_TOKEN_ID는 해당 checkpoint의
유효 vocab ID 중 실험자가 사전에 정한 값이다.

~~~json
{
  "model": "Qwen/Qwen3-4B",
  "messages": [{"role": "user", "content": "bounded synthetic prompt"}],
  "temperature": 0,
  "max_tokens": 32,
  "allowed_token_ids": ["CONTROL_TOKEN_ID"]
}
~~~

실제 JSON에서는 CONTROL_TOKEN_ID를 문자열이 아닌 정수로 넣는다. 이 요청을
제3자 서버나 production에 보내지 않는다.

### 11.3 수집할 값

- refit 번호와 각 refit 전후 slope/intercepts
- position별 observation/accept count
- victim의 position별 predicted confidence
- step별 chosen global draft budget
- acceptance length와 accepted/drafted
- output tokens/s, median·p95 TPOT, ITL, TTFT
- GPU memory, utilization, server error와 OOM
- 공격 종료 뒤 baseline으로 회복하는 데 걸린 step 수

계수와 budget이 기본 metric에 노출되지 않으면 별도 연구 branch의 최소 telemetry
patch 또는 debugger를 사용하되, patch hash와 전체 diff를 결과에 첨부하고 upstream
source에는 커밋하지 않는다.

### 11.4 확인 기준

메커니즘 확인에는 다음이 모두 필요하다.

1. 일반 HTTP 요청의 제약이 실제 accept/reject 분포를 바꾼다.
2. 그 관측으로 공용 estimator 계수가 바뀐다.
3. 공격 요청이 끝난 뒤 새 neutral request가 바뀐 계수를 사용한다.
4. 같은 victim feature에서 confidence와 chosen budget이 fresh-process control과
   재현 가능하게 다르다.

사용자 영향 확인에는 추가로 paired run에서 neutral victim의 output throughput
또는 TPOT/p95가 noise floor를 넘어 일관되게 악화되어야 한다. 단순히 estimator
계수가 달라진 것만으로는 보안 보고 대상이 아니다.

### 11.5 기각 기준

다음 중 하나면 현재 가설을 기각하거나 다시 좁힌다.

- Qwen3-4B/DFlash/TRITON_ATTN 조합이 현재 main에서 지원되지 않는다.
- target-only constraint가 실제 draft에도 반영되어 label 편향이 생기지 않는다.
- refit 뒤 새 request의 confidence 또는 budget이 control과 같다.
- 상태가 공격 요청이 끝나기 전에 회복해 post-attack victim 차이가 없다.
- 변화가 공격 요청 자신의 비용에만 국한된다.
- budget은 바뀌지만 victim latency/throughput은 악화되지 않거나 오히려 개선된다.
- effect가 한 run의 CUDA graph, thermal 또는 startup noise로 설명된다.

## 12. AWS 예상 비용

2026-09-16 확인값:

- Seoul g6e.2xlarge Linux/Shared On-Demand:
  시간당 USD 2.75652
- Seoul gp3:
  GB-month당 USD 0.0912
- public IPv4:
  시간당 USD 0.005
- AWS Korea VAT:
  10%

근거는 [AWS EC2 Price List](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/current/ap-northeast-2/index.json),
[EBS pricing](https://aws.amazon.com/ebs/pricing/),
[VPC pricing](https://aws.amazon.com/vpc/pricing/),
[AWS Korea 약관](https://aws.amazon.com/legal/awsk/)이다.
EC2 price file의 publication version은 20260910195514, effective date는
2026-09-01이었다. g6e.2xlarge SKU는 7Q3CFPGZCF2ZUPJQ, gp3 SKU는
MTK7D9SGKGYR3JD6였다.

아래 표는 200GB gp3를 사용 시간만큼 일할 계산하고 public IPv4와 VAT를 더한
보수적 예시다. 환산은 1 USD = KRW 1,360.66이라는 계산 가정이며 실제 카드 환율과
해외 결제 수수료는 다르다.

| 세션 | VAT 포함 USD | 원화 예시 |
| ---: | ---: | ---: |
| 2시간 | 6.13 | 약 8,300원 |
| 4시간 | 12.26 | 약 16,700원 |
| 6시간 | 18.39 | 약 25,000원 |
| 8시간 | 24.52 | 약 33,400원 |

현실적인 첫 검증은 4~6시간, 약 1.7만~2.5만원이다. 재시도와 환율 차이를 포함한
안전 상한은 4만원으로 잡는다.

이 계산에는 snapshot, Elastic IP, NAT Gateway, 장기 log storage, 큰 data egress가
포함되지 않는다. 200GB gp3를 삭제하지 않고 한 달 두면 USD 18.24와 VAT가 계속
청구될 수 있다.

## 13. 종료와 비용 누수 방지

1. revision, 명령, nvidia-smi, 측정 로그와 telemetry patch hash만 보존한다.
2. synthetic prompt 외 데이터가 로그에 없는지 확인한다.
3. vLLM 프로세스를 종료한다.
4. EC2를 stop이 아니라 terminate한다.
5. gp3 volume이 DeleteOnTermination으로 삭제됐는지 확인한다.
6. snapshot, Elastic IP, NAT Gateway, load balancer가 남지 않았는지 확인한다.
7. 450GB instance store는 terminate 시 자동 소멸함을 전제로 필요한 로그를 먼저
   내보낸다.
8. Cost Explorer에서 다음 날 실제 청구를 확인한다.

## 14. 검증 뒤 고려할 완화책

아직 코드를 수정하지 않았으며 아래는 설계 후보일 뿐이다.

- allowed_token_ids, bad_words, penalties, structured-output mask처럼 draft가 보지
  못하는 target transform이 활성화된 요청은 공용 estimator 학습에서 제외한다.
- draft prediction feature와 target label이 같은 support를 보도록 모든 관련
  sampling transform을 draft 측에도 전달한다.
- sampling/calibration signature별 estimator를 두되 상태 폭발과 sparse-data
  문제를 평가한다.
- 한 request 또는 tenant가 한 refit의 info/grad에 기여할 수 있는 양을 제한한다.
- slope/intercepts와 round별 변화량을 경계하고, 오래된 관측을 감쇠시킨다.
- coefficient shift, acceptance collapse, budget=0 비율을 metric으로 노출해
  비정상적인 serving-policy 변화를 탐지한다.
- 강한 multi-tenant 경계가 필요하면 tenant별 worker/replica를 사용한다.

PR #56724가 top-k/top-p support 정렬을 이미 제안하므로, 실제 수정 전에는 그
변경이 merge됐는지와 allowed-token/bad-word/penalty까지 확장되는지 다시 확인해야 한다.

## 15. 최종 처분

현재 후보는 다음 세 문장으로만 요약해야 한다.

1. 최신 main에서 공격자 제어 입력→공용 estimator→후속 요청 budget으로 이어지는
   정적 경로는 존재한다.
2. CPU 참조 실험에서는 극단적 coefficient와 budget steering이 재현됐다.
3. 실제 GPU·HTTP·성능 피해는 검증되지 않았고, 가까운 공개 sibling prior art가
   있으므로 보안 권고문을 만들거나 제출할 단계가 아니다.

다음 행동은 위 AWS 단일-node 실험으로 기동 가능성, cross-request persistence,
피해량을 검증하는 것이다. 그 결과가 음성이면 후보를 폐기한다. 양성이어도 공개
신규성 검색과 maintainer threat-model 적합성을 다시 통과한 뒤에만 private report
전환을 검토한다.
