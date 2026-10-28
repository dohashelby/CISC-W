#!/usr/bin/env bash
set -Eeuo pipefail

readonly WORK_DIR="${HOME}/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly VENV_DIR="${REPO_DIR}/.venv"
readonly RESULT_DIR="${WORK_DIR}/results"
readonly SERVER_LOG="${RESULT_DIR}/server.log"
readonly SERVER_PID_FILE="${RESULT_DIR}/server.pid"
readonly API_KEY="local-research-only"

mkdir -p "${RESULT_DIR}"

server_pid=""

stop_server() {
    if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
        kill "${server_pid}"
        for _ in $(seq 1 60); do
            kill -0 "${server_pid}" 2>/dev/null || break
            sleep 1
        done
        kill -9 "${server_pid}" 2>/dev/null || true
    fi
    server_pid=""
    rm -f "${SERVER_PID_FILE}"
}

trap stop_server EXIT

mark_phase() {
    local phase="$1"
    printf '%s %s\n' "$(date --iso-8601=ns)" "${phase}" \
        | tee -a "${RESULT_DIR}/phase_markers.txt"
    printf '===== AVEP_PHASE %s %s =====\n' \
        "${phase}" "$(date --iso-8601=ns)" >> "${SERVER_LOG}"
}

start_server() {
    local label="$1"
    stop_server
    mark_phase "server_start_${label}"
    cd "${REPO_DIR}"
    export HF_HUB_DISABLE_TELEMETRY=1
    export VLLM_ADAPTIVE_VERIFICATION_PROFILE_CONTEXT_LEN=4096
    export VLLM_AVEP_TELEMETRY=1
    export VLLM_AVEP_TELEMETRY_BUDGET_EVERY=10
    export VLLM_HOST_IP=127.0.0.1
    export VLLM_USE_V2_MODEL_RUNNER=1

    nohup "${VENV_DIR}/bin/vllm" serve Qwen/Qwen3-4B \
        --revision 1cfa9a7208912126459214e8b04321603b3df60c \
        --host 127.0.0.1 \
        --port 8000 \
        --api-key "${API_KEY}" \
        --dtype bfloat16 \
        --trust-remote-code \
        --max-model-len 4096 \
        --max-num-seqs 64 \
        --max-num-batched-tokens 4096 \
        --gpu-memory-utilization 0.80 \
        --no-enable-prefix-caching \
        --attention-backend TRITON_ATTN \
        --enable-per-request-metrics \
        --per-request-spec-decode-metrics detailed \
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
        }' >> "${SERVER_LOG}" 2>&1 &
    server_pid="$!"
    printf '%s\n' "${server_pid}" > "${SERVER_PID_FILE}"

    for _ in $(seq 1 120); do
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            tail -200 "${SERVER_LOG}"
            return 1
        fi
        if curl --fail --silent \
            -H "Authorization: Bearer ${API_KEY}" \
            http://127.0.0.1:8000/v1/models >/dev/null; then
            mark_phase "server_ready_${label}"
            return 0
        fi
        sleep 10
    done
    tail -200 "${SERVER_LOG}"
    return 1
}

run_probe() {
    local phase="$1"
    local requests="$2"
    local concurrency="$3"
    local max_tokens="$4"
    local allowed_token_id="${5:-}"
    local output="${RESULT_DIR}/${phase}.json"
    local cmd=(
        "${VENV_DIR}/bin/python"
        "${WORK_DIR}/avep_probe.py"
        --phase "${phase}"
        --requests "${requests}"
        --concurrency "${concurrency}"
        --max-tokens "${max_tokens}"
        --api-key "${API_KEY}"
        --output "${output}"
    )
    if [[ -n "${allowed_token_id}" ]]; then
        cmd+=(--allowed-token-id "${allowed_token_id}")
    fi
    mark_phase "${phase}_begin"
    "${cmd[@]}" | tee "${RESULT_DIR}/${phase}.summary.json"
    grep 'AVEP_ESTIMATOR' "${SERVER_LOG}" | tail -1 \
        > "${RESULT_DIR}/${phase}.last_refit.txt" || true
    mark_phase "${phase}_end"
}

{
    date --iso-8601=seconds
    cat "${WORK_DIR}/manifest.txt"
    nvidia-smi
} > "${RESULT_DIR}/environment.txt"

start_server "poison_run"
run_probe warmup 64 16 16
run_probe baseline 128 32 32
run_probe poison 1024 64 32 151646
run_probe post_poison_victim 128 32 32
run_probe recovery_1 128 32 32
run_probe recovery_2 128 32 32

stop_server
start_server "fresh_process_control"
run_probe fresh_warmup 64 16 16
run_probe fresh_process_victim 128 32 32
stop_server

"${VENV_DIR}/bin/python" "${WORK_DIR}/analyze_gate1.py" \
    --result-dir "${RESULT_DIR}" \
    --output "${RESULT_DIR}/gate1_assessment.json"

tar -C "${WORK_DIR}" -czf "${WORK_DIR}/avep-gate1-results.tgz" \
    manifest.txt results
sha256sum "${WORK_DIR}/avep-gate1-results.tgz" \
    > "${WORK_DIR}/avep-gate1-results.tgz.sha256"
touch "${WORK_DIR}/GATE1_COMPLETE"
