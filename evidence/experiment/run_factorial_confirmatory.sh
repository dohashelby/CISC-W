#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROTOCOL_VERSION="avep-factorial-confirmatory-v1"
readonly WORK_DIR="/home/ubuntu/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly VENV_DIR="${REPO_DIR}/.venv"
export PATH="${VENV_DIR}/bin:${PATH:-}"
readonly RESULT_ROOT="${WORK_DIR}/factorial_confirmatory_results_v1"
readonly CREDENTIALS_FILE="${WORK_DIR}/.avep_factorial_v1_tenant_credentials.json"
readonly PROBE="${WORK_DIR}/tenant_probe.py"
readonly GATEWAY="${WORK_DIR}/tenant_gateway.py"
readonly ANALYZER="${WORK_DIR}/analyze_factorial_confirmatory.py"
readonly RULES_SOURCE="${WORK_DIR}/FACTORIAL_CONFIRMATORY_DECISION_RULES.md"
readonly RESULT_ARCHIVE="${WORK_DIR}/avep-factorial-confirmatory-v1-results.tgz"
readonly PARTIAL_ARCHIVE="${WORK_DIR}/avep-factorial-confirmatory-v1-partial.tgz"
readonly TOKEN_ID=279
readonly PHASE_TIMEOUT_SECONDS="${PHASE_TIMEOUT_SECONDS:-1800}"

declare -ar GATE_ORDER=(
    placebo_blocked placebo_shared attack_blocked attack_shared
)
declare -ar PERFORMANCE_ORDERS=(
    "attack_shared attack_blocked placebo_blocked placebo_shared"
    "attack_blocked placebo_shared attack_shared placebo_blocked"
    "placebo_shared placebo_blocked attack_blocked attack_shared"
    "placebo_blocked attack_shared placebo_shared attack_blocked"
    "attack_shared attack_blocked placebo_blocked placebo_shared"
    "attack_blocked placebo_shared attack_shared placebo_blocked"
    "placebo_shared placebo_blocked attack_blocked attack_shared"
    "placebo_blocked attack_shared placebo_shared attack_blocked"
)

server_pid=""
server_pgid=""
server_marker=""
gateway_pid=""
gateway_pgid=""
gateway_instance_id=""
current_log=""
ATTACKER_API_KEY=""
VICTIM_API_KEY=""
UPSTREAM_API_KEY=""

secret_sha256() {
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

initialize_credentials() {
    if [[ ! -e "${CREDENTIALS_FILE}" ]]; then
        local temporary="${CREDENTIALS_FILE}.partial"
        umask 077
        jq -n \
            --arg attacker "$(openssl rand -hex 32)" \
            --arg victim "$(openssl rand -hex 32)" \
            --arg upstream "$(openssl rand -hex 32)" \
            '{attacker: $attacker, victim: $victim, upstream: $upstream}' \
            > "${temporary}"
        chmod 0600 "${temporary}"
        mv "${temporary}" "${CREDENTIALS_FILE}"
    fi
    if [[ -L "${CREDENTIALS_FILE}" ]] \
        || [[ "$(stat -c '%a' "${CREDENTIALS_FILE}")" != "600" ]]; then
        printf 'Credential file must be regular and mode 0600.\n' >&2
        return 1
    fi
    ATTACKER_API_KEY="$(jq -er '.attacker' "${CREDENTIALS_FILE}")"
    VICTIM_API_KEY="$(jq -er '.victim' "${CREDENTIALS_FILE}")"
    UPSTREAM_API_KEY="$(jq -er '.upstream' "${CREDENTIALS_FILE}")"
    if [[ "${#ATTACKER_API_KEY}" -lt 32 \
        || "${#VICTIM_API_KEY}" -lt 32 \
        || "${#UPSTREAM_API_KEY}" -lt 32 \
        || "${ATTACKER_API_KEY}" == "${VICTIM_API_KEY}" \
        || "${ATTACKER_API_KEY}" == "${UPSTREAM_API_KEY}" \
        || "${VICTIM_API_KEY}" == "${UPSTREAM_API_KEY}" ]]; then
        printf 'Credentials are missing, short, or non-distinct.\n' >&2
        return 1
    fi
}

is_managed_server_pid() {
    local pid="$1"
    local command_line
    [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/${pid}/cmdline" ]] || return 1
    command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
    [[ "${command_line}" == *"${VENV_DIR}/bin/vllm serve Qwen/Qwen3-4B"* ]]
    [[ "${command_line}" == *"--host 127.0.0.1"* ]]
    [[ "${command_line}" == *"--port 8000"* ]]
    [[ "${command_line}" == *"--api-key ${UPSTREAM_API_KEY}"* ]]
}

is_managed_gateway_pid() {
    local pid="$1"
    local command_line
    [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/${pid}/cmdline" ]] || return 1
    command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
    [[ "${command_line}" == *"${VENV_DIR}/bin/python ${GATEWAY} serve"* ]]
    [[ "${command_line}" == *"--port 8001"* ]]
}

stop_gateway() {
    if [[ -z "${gateway_pid}" ]] || ! kill -0 "${gateway_pid}" 2>/dev/null; then
        gateway_pid=""
        gateway_pgid=""
        gateway_instance_id=""
        return 0
    fi
    if ! is_managed_gateway_pid "${gateway_pid}"; then
        printf 'Refusing to stop unrecognized gateway PID %s.\n' \
            "${gateway_pid}" >&2
        return 1
    fi
    kill -TERM "${gateway_pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "${gateway_pid}" 2>/dev/null || break
        sleep 0.2
    done
    kill -KILL "${gateway_pid}" 2>/dev/null || true
    wait "${gateway_pid}" 2>/dev/null || true
    gateway_pid=""
    gateway_pgid=""
    gateway_instance_id=""
}

stop_server() {
    stop_gateway || true
    if [[ -n "${server_pid}" ]] && kill -0 "${server_pid}" 2>/dev/null; then
        if ! is_managed_server_pid "${server_pid}"; then
            printf 'Refusing to stop unrecognized server PID %s.\n' \
                "${server_pid}" >&2
            return 1
        fi
        if [[ -n "${server_pgid}" && "${server_pgid}" == "${server_pid}" ]]; then
            kill -TERM -- "-${server_pgid}" 2>/dev/null || true
            for _ in $(seq 1 60); do
                kill -0 -- "-${server_pgid}" 2>/dev/null || break
                sleep 1
            done
            kill -KILL -- "-${server_pgid}" 2>/dev/null || true
        else
            kill -TERM "${server_pid}" 2>/dev/null || true
            for _ in $(seq 1 60); do
                kill -0 "${server_pid}" 2>/dev/null || break
                sleep 1
            done
            kill -KILL "${server_pid}" 2>/dev/null || true
        fi
    fi
    server_pid=""
    server_pgid=""
    server_marker=""
}

cleanup() {
    local status="$?"
    stop_server || true
    if ((status != 0)) && [[ -d "${RESULT_ROOT}" ]]; then
        printf 'exit_status=%s\ntimestamp=%s\n' \
            "${status}" "$(date --iso-8601=ns)" \
            > "${RESULT_ROOT}/FACTORIAL_CONFIRMATORY_FAILED.txt"
        tar -czf "${PARTIAL_ARCHIVE}.partial" -C "${WORK_DIR}" \
            factorial_confirmatory_results_v1 \
            FACTORIAL_CONFIRMATORY_PROTOCOL.md \
            FACTORIAL_CONFIRMATORY_DECISION_RULES.md \
            avep_causal_ablation.patch \
            run_factorial_confirmatory.sh \
            analyze_factorial_confirmatory.py \
            test_analyze_factorial_confirmatory.py \
            tenant_probe.py \
            tenant_gateway.py \
            factorial_environment.txt 2>/dev/null || true
        if [[ -f "${PARTIAL_ARCHIVE}.partial" ]]; then
            mv "${PARTIAL_ARCHIVE}.partial" "${PARTIAL_ARCHIVE}"
            sha256sum "${PARTIAL_ARCHIVE}" \
                > "${PARTIAL_ARCHIVE}.sha256"
        fi
    fi
    return "${status}"
}
trap cleanup EXIT INT TERM

runtime_preflight() {
    local command_name
    for command_name in curl cut find jq ninja openssl ps setsid sha256sum \
        ss stat tar timeout; do
        command -v "${command_name}" >/dev/null 2>&1 || {
            printf 'Required command is unavailable: %s\n' \
                "${command_name}" >&2
            return 1
        }
    done
    local required_file
    for required_file in \
        "${VENV_DIR}/bin/ninja" \
        "${VENV_DIR}/bin/vllm" \
        "${VENV_DIR}/bin/python" \
        "${PROBE}" \
        "${GATEWAY}" \
        "${ANALYZER}" \
        "${WORK_DIR}/test_analyze_factorial_confirmatory.py" \
        "${RULES_SOURCE}" \
        "${WORK_DIR}/FACTORIAL_CONFIRMATORY_PROTOCOL.md" \
        "${WORK_DIR}/avep_causal_ablation.patch"; do
        [[ -f "${required_file}" ]] || {
            printf 'Required input is unavailable: %s\n' \
                "${required_file}" >&2
            return 1
        }
    done
    if [[ -n "$(ss -H -ltn 'sport = :8000')" \
        || -n "$(ss -H -ltn 'sport = :8001')" ]]; then
        printf 'Port 8000 or 8001 is already occupied.\n' >&2
        return 1
    fi
}

write_environment_manifest() {
    local output="${WORK_DIR}/factorial_environment.txt"
    local temporary="${output}.partial"
    {
        printf 'vllm_sha=%s\n' "$(git -C "${REPO_DIR}" rev-parse HEAD)"
        printf 'paper_patch_sha256=%s\n' \
            "$(sha256sum "${WORK_DIR}/avep_paper_instrumentation.patch" \
                | cut -d' ' -f1)"
        printf 'causal_patch_sha256=%s\n' \
            "$(sha256sum "${WORK_DIR}/avep_causal_ablation.patch" \
                | cut -d' ' -f1)"
        "${VENV_DIR}/bin/python" -c \
            'import importlib.metadata as m; print("vllm_version=" + m.version("vllm"))'
        "${VENV_DIR}/bin/python" --version
        uv --version
        nvidia-smi --query-gpu=name,driver_version,memory.total \
            --format=csv,noheader
        sha256sum \
            "${WORK_DIR}/run_factorial_confirmatory.sh" \
            "${WORK_DIR}/analyze_factorial_confirmatory.py" \
            "${WORK_DIR}/test_analyze_factorial_confirmatory.py" \
            "${WORK_DIR}/tenant_probe.py" \
            "${WORK_DIR}/tenant_gateway.py"
    } > "${temporary}"
    mv "${temporary}" "${output}"
}

run_local_self_tests() {
    (
        cd "${WORK_DIR}"
        "${VENV_DIR}/bin/python" -m unittest -v \
            test_analyze_factorial_confirmatory.py
    )
}

declare_protocol() {
    mkdir -p "${RESULT_ROOT}"
    if [[ -f "${RESULT_ROOT}/DECLARED_AT_UTC.txt" ]]; then
        (
            cd "${WORK_DIR}"
            sha256sum -c \
                "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
        )
        (
            cd "${RESULT_ROOT}"
            sha256sum -c DECLARED_SCHEDULE.json.sha256
        )
        return
    fi
    if find "${RESULT_ROOT}" -mindepth 1 -maxdepth 1 -print -quit \
        | grep -q .; then
        printf 'Refusing to declare over existing factorial data.\n' >&2
        return 1
    fi
    cp "${RULES_SOURCE}" "${RESULT_ROOT}/DECLARED_DECISION_RULES.md"
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --argjson token_id "${TOKEN_ID}" \
        '{
            protocol_version: $protocol_version,
            token_id: $token_id,
            gate_order: [
                "placebo_blocked", "placebo_shared",
                "attack_blocked", "attack_shared"
            ],
            performance_orders: [
                ["attack_shared", "attack_blocked",
                    "placebo_blocked", "placebo_shared"],
                ["attack_blocked", "placebo_shared",
                    "attack_shared", "placebo_blocked"],
                ["placebo_shared", "placebo_blocked",
                    "attack_blocked", "attack_shared"],
                ["placebo_blocked", "attack_shared",
                    "placebo_shared", "attack_blocked"],
                ["attack_shared", "attack_blocked",
                    "placebo_blocked", "placebo_shared"],
                ["attack_blocked", "placebo_shared",
                    "attack_shared", "placebo_blocked"],
                ["placebo_shared", "placebo_blocked",
                    "attack_blocked", "attack_shared"],
                ["placebo_blocked", "attack_shared",
                    "placebo_shared", "attack_blocked"]
            ],
            workload: {
                warmup: {requests: 1024, concurrency: 32, max_tokens: 32},
                pre: {windows: 4, requests: 128, concurrency: 32,
                    max_tokens: 32},
                intervention: {
                    requests: 4096, concurrency: 8, max_tokens: 2,
                    attack_allowed_token_id: $token_id,
                    placebo_allowed_token_id: null,
                    return_token_ids: true
                },
                post: {windows: 8, requests: 128, concurrency: 32,
                    max_tokens: 32}
            }
        }' > "${RESULT_ROOT}/DECLARED_SCHEDULE.json"
    (
        cd "${WORK_DIR}"
        sha256sum \
            FACTORIAL_CONFIRMATORY_PROTOCOL.md \
            FACTORIAL_CONFIRMATORY_DECISION_RULES.md \
            avep_paper_instrumentation.patch \
            avep_causal_ablation.patch \
            run_factorial_confirmatory.sh \
            analyze_factorial_confirmatory.py \
            test_analyze_factorial_confirmatory.py \
            tenant_probe.py \
            tenant_gateway.py \
            factorial_environment.txt \
            > "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
    )
    (
        cd "${RESULT_ROOT}"
        sha256sum DECLARED_SCHEDULE.json \
            > DECLARED_SCHEDULE.json.sha256
    )
    jq -n \
        --arg attacker "$(secret_sha256 "${ATTACKER_API_KEY}")" \
        --arg victim "$(secret_sha256 "${VICTIM_API_KEY}")" \
        --arg upstream "$(secret_sha256 "${UPSTREAM_API_KEY}")" \
        '{attacker: $attacker, victim: $victim, upstream: $upstream}' \
        > "${RESULT_ROOT}/DECLARED_PRINCIPALS.json"
    date --iso-8601=ns > "${RESULT_ROOT}/DECLARED_AT_UTC.txt"
}

mark_phase() {
    printf '===== AVEP_FACTORIAL_PHASE %s %s =====\n' \
        "$1" "$(date --iso-8601=ns)" >> "${current_log}"
}

start_gateway() {
    local run_dir="$1"
    local run_name
    run_name="$(basename "${run_dir}")"
    gateway_instance_id="factorial-${run_name}-$(date +%s%N)"
    : > "${run_dir}/gateway.stderr.log"
    : > "${run_dir}/gateway_audit.jsonl"
    nohup setsid "${VENV_DIR}/bin/python" "${GATEWAY}" serve \
        --host 127.0.0.1 \
        --port 8001 \
        --upstream-host 127.0.0.1 \
        --upstream-port 8000 \
        --credentials "${CREDENTIALS_FILE}" \
        --gateway-instance-id "${gateway_instance_id}" \
        --upstream-marker "${server_marker}" \
        --audit "${run_dir}/gateway_audit.jsonl" \
        >> "${run_dir}/gateway.stderr.log" 2>&1 &
    gateway_pid="$!"
    gateway_pgid="$(ps -o pgid= -p "${gateway_pid}" | tr -d '[:space:]')"
    for _ in $(seq 1 100); do
        kill -0 "${gateway_pid}" 2>/dev/null || break
        [[ -n "$(ss -H -ltn 'sport = :8001')" ]] && break
        sleep 0.1
    done
    is_managed_gateway_pid "${gateway_pid}" || return 1
    [[ -n "$(ss -H -ltn 'sport = :8001')" ]] || return 1
    printf '%s\n' "${gateway_pid}" > "${run_dir}/gateway.pid"
    printf '%s\n' "${gateway_instance_id}" > "${run_dir}/gateway.instance"
    "${VENV_DIR}/bin/python" "${GATEWAY}" self-test \
        --base-url http://127.0.0.1:8001/v1 \
        --credentials "${CREDENTIALS_FILE}" \
        --output "${run_dir}/auth_self_test.json.partial"
    mv "${run_dir}/auth_self_test.json.partial" \
        "${run_dir}/auth_self_test.json"
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --arg gateway_instance_id "${gateway_instance_id}" \
        --arg upstream_marker "${server_marker}" \
        --arg attacker "$(secret_sha256 "${ATTACKER_API_KEY}")" \
        --arg victim "$(secret_sha256 "${VICTIM_API_KEY}")" \
        --arg upstream "$(secret_sha256 "${UPSTREAM_API_KEY}")" \
        '{protocol_version: $protocol_version,
          gateway_instance_id: $gateway_instance_id,
          upstream_marker: $upstream_marker,
          key_fingerprints: {attacker: $attacker, victim: $victim,
            upstream: $upstream}}' \
        > "${run_dir}/tenant_topology.json"
}

start_server() {
    local run_dir="$1"
    local telemetry="$2"
    local detailed_metrics="$3"
    stop_server
    current_log="${run_dir}/server.log"
    export HF_HUB_DISABLE_TELEMETRY=1
    export VLLM_ADAPTIVE_VERIFICATION_PROFILE_CONTEXT_LEN=4096
    export VLLM_HOST_IP=127.0.0.1
    export VLLM_USE_V2_MODEL_RUNNER=1
    export VLLM_SERVER_DEV_MODE=1
    if [[ "${telemetry}" == "true" ]]; then
        export VLLM_AVEP_TELEMETRY=1
        export VLLM_AVEP_TELEMETRY_BUDGET_EVERY=1
    else
        unset VLLM_AVEP_TELEMETRY || true
        unset VLLM_AVEP_TELEMETRY_BUDGET_EVERY || true
    fi
    local spec_config
    spec_config="$(printf '%s' "{
        \"method\":\"dflash\",
        \"model\":\"z-lab/Qwen3-4B-DFlash-b16\",
        \"revision\":\"b74e3a329c4d963783143b1e970d95b002be72bd\",
        \"code_revision\":\"b74e3a329c4d963783143b1e970d95b002be72bd\",
        \"attention_backend\":\"TRITON_ATTN\",
        \"num_speculative_tokens\":4,
        \"max_model_len\":4096,
        \"enable_adaptive_verification\":true
    }")"
    local server_args=(
        serve Qwen/Qwen3-4B
        --revision 1cfa9a7208912126459214e8b04321603b3df60c
        --host 127.0.0.1
        --port 8000
        --api-key "${UPSTREAM_API_KEY}"
        --dtype bfloat16
        --trust-remote-code
        --max-model-len 4096
        --max-num-seqs 64
        --max-num-batched-tokens 4096
        --gpu-memory-utilization 0.80
        --no-enable-prefix-caching
        --attention-backend TRITON_ATTN
        --compilation-config '{"cudagraph_mode":"FULL_AND_PIECEWISE"}'
        --speculative-config "${spec_config}"
    )
    if [[ "${detailed_metrics}" == "true" ]]; then
        server_args+=(
            --enable-per-request-metrics
            --per-request-spec-decode-metrics detailed
        )
    fi
    cd "${REPO_DIR}"
    : > "${current_log}"
    server_marker="factorial-${BASHPID}-$(date +%s%N)"
    nohup setsid "${VENV_DIR}/bin/vllm" "${server_args[@]}" \
        >> "${current_log}" 2>&1 &
    server_pid="$!"
    server_pgid="$(ps -o pgid= -p "${server_pid}" | tr -d '[:space:]')"
    printf '%s\n' "${server_pid}" > "${run_dir}/server.pid"
    printf '%s\n' "${server_pgid}" > "${run_dir}/server.pgid"
    printf '%s\n' "${server_marker}" > "${run_dir}/server.marker"
    for _ in $(seq 1 180); do
        if ! kill -0 "${server_pid}" 2>/dev/null; then
            tail -200 "${current_log}"
            return 1
        fi
        if curl --fail --silent --show-error \
            --connect-timeout 2 --max-time 5 \
            -H "Authorization: Bearer ${UPSTREAM_API_KEY}" \
            http://127.0.0.1:8000/v1/models >/dev/null; then
            start_gateway "${run_dir}"
            mark_phase server_ready
            return 0
        fi
        sleep 10
    done
    tail -200 "${current_log}"
    return 1
}

rpc() {
    local output="$1"
    local payload="$2"
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 60 \
        -H "Authorization: Bearer ${UPSTREAM_API_KEY}" \
        -H 'Content-Type: application/json' \
        --data "${payload}" \
        http://127.0.0.1:8000/collective_rpc > "${output}.partial"
    mv "${output}.partial" "${output}"
}

snapshot_state() {
    rpc "$1/state_$2.json" \
        '{"method":"avep_get_acceptance_estimator_state"}'
}

reset_estimator() {
    rpc "$1/estimator_reset.json" \
        '{"method":"avep_reset_acceptance_estimator"}'
}

set_updates() {
    local run_dir="$1"
    local label="$2"
    local enabled="$3"
    rpc "${run_dir}/update_gate_${label}.json" \
        "{\"method\":\"avep_set_acceptance_estimator_updates\",\"args\":[\"${enabled}\"]}"
}

run_probe() {
    local run_dir="$1"
    local phase="$2"
    local principal="$3"
    local requests="$4"
    local concurrency="$5"
    local max_tokens="$6"
    local allowed_token_id="${7:-}"
    local return_token_ids="${8:-false}"
    local cmd=(
        "${VENV_DIR}/bin/python"
        "${PROBE}"
        --phase "${phase}"
        --principal "${principal}"
        --run-id "$(basename "${run_dir}")"
        --gateway-instance-id "${gateway_instance_id}"
        --upstream-marker "${server_marker}"
        --base-url http://127.0.0.1:8001/v1
        --requests "${requests}"
        --concurrency "${concurrency}"
        --max-tokens "${max_tokens}"
        --credentials "${CREDENTIALS_FILE}"
        --output "${run_dir}/${phase}.json.partial"
    )
    [[ -z "${allowed_token_id}" ]] || cmd+=(--allowed-token-id "${allowed_token_id}")
    [[ "${return_token_ids}" != "true" ]] || cmd+=(--return-token-ids)
    mark_phase "${phase}_begin"
    timeout --signal=TERM --kill-after=60s \
        "${PHASE_TIMEOUT_SECONDS}s" "${cmd[@]}" \
        | tee "${run_dir}/${phase}.summary.json.partial"
    mv "${run_dir}/${phase}.json.partial" "${run_dir}/${phase}.json"
    mv "${run_dir}/${phase}.summary.json.partial" \
        "${run_dir}/${phase}.summary.json"
    mark_phase "${phase}_end"
}

prepare_run_dir() {
    local run_dir="$1"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        return 1
    fi
    if [[ -d "${run_dir}" ]]; then
        mkdir -p "${RESULT_ROOT}/_incomplete"
        mv "${run_dir}" \
            "${RESULT_ROOT}/_incomplete/$(basename "${run_dir}").$(date +%s%N)"
    fi
    mkdir -p "${run_dir}"
}

run_arm() {
    local run_name="$1"
    local stage="$2"
    local block_id="$3"
    local arm="$4"
    local telemetry="$5"
    local detailed_metrics="$6"
    local return_token_ids="$7"
    local workload="${arm%%_*}"
    local update_mode="${arm##*_}"
    if [[ "${workload}" != "attack" && "${workload}" != "placebo" ]]; then
        printf 'Invalid workload in arm %s.\n' "${arm}" >&2
        return 1
    fi
    if [[ "${update_mode}" != "shared" \
        && "${update_mode}" != "blocked" ]]; then
        printf 'Invalid update mode in arm %s.\n' "${arm}" >&2
        return 1
    fi
    local run_dir="${RESULT_ROOT}/${run_name}"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete run %s.\n' "${run_name}"
        return
    fi
    prepare_run_dir "${run_dir}"
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --arg run_name "${run_name}" \
        --arg stage "${stage}" \
        --arg block_id "${block_id}" \
        --arg arm "${arm}" \
        --arg workload "${workload}" \
        --arg update_mode "${update_mode}" \
        --argjson token_id "${TOKEN_ID}" \
        --argjson telemetry "${telemetry}" \
        --argjson detailed_metrics "${detailed_metrics}" \
        --arg created_at "$(date --iso-8601=ns)" \
        '{protocol_version: $protocol_version, run_name: $run_name,
          stage: $stage, block_id: $block_id, arm: $arm,
          workload: $workload, update_mode: $update_mode,
          poison_token_id: $token_id, telemetry: $telemetry,
          detailed_metrics: $detailed_metrics, created_at: $created_at}' \
        > "${run_dir}/metadata.json"
    start_server "${run_dir}" "${telemetry}" "${detailed_metrics}"
    snapshot_state "${run_dir}" server_ready
    reset_estimator "${run_dir}"
    snapshot_state "${run_dir}" reset
    run_probe "${run_dir}" warmup victim 1024 32 32 "" \
        "${return_token_ids}"
    snapshot_state "${run_dir}" warmup
    local window_number
    local window
    for window_number in $(seq 1 4); do
        window="$(printf '%02d' "${window_number}")"
        run_probe "${run_dir}" "pre_${window}" victim 128 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "pre_${window}"
    done
    if [[ "${update_mode}" == "blocked" ]]; then
        set_updates "${run_dir}" before_intervention false
    else
        set_updates "${run_dir}" before_intervention true
    fi
    snapshot_state "${run_dir}" pre_intervention
    local intervention_token=""
    if [[ "${workload}" == "attack" ]]; then
        intervention_token="${TOKEN_ID}"
    fi
    run_probe "${run_dir}" intervention attacker 4096 8 2 \
        "${intervention_token}" true
    snapshot_state "${run_dir}" intervention
    set_updates "${run_dir}" after_intervention true
    snapshot_state "${run_dir}" reenabled
    for window_number in $(seq 1 8); do
        window="$(printf '%02d' "${window_number}")"
        run_probe "${run_dir}" "post_${window}" victim 128 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "post_${window}"
    done
    stop_server
    cp "${WORK_DIR}/factorial_environment.txt" "${run_dir}/environment.txt"
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

run_gate() {
    local arm
    for arm in "${GATE_ORDER[@]}"; do
        run_arm "gate_${arm}" gate gate "${arm}" true true true
    done
    "${VENV_DIR}/bin/python" "${ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --gate-only \
        --output "${RESULT_ROOT}/gate_assessment.json.partial"
    mv "${RESULT_ROOT}/gate_assessment.json.partial" \
        "${RESULT_ROOT}/gate_assessment.json"
    jq -e '.valid == true and .mechanism_gate.pass == true' \
        "${RESULT_ROOT}/gate_assessment.json" >/dev/null
}

run_performance() {
    local block_number
    local block_id
    local arm
    for block_number in $(seq 1 8); do
        block_id="$(printf '%02d' "${block_number}")"
        for arm in ${PERFORMANCE_ORDERS[$((block_number - 1))]}; do
            run_arm "perf_block_${block_id}_${arm}" performance \
                "${block_id}" "${arm}" false false false
        done
    done
}

archive_results() {
    local -a members=(
        factorial_confirmatory_results_v1
        FACTORIAL_CONFIRMATORY_PROTOCOL.md
        FACTORIAL_CONFIRMATORY_DECISION_RULES.md
        avep_paper_instrumentation.patch
        avep_causal_ablation.patch
        run_factorial_confirmatory.sh
        analyze_factorial_confirmatory.py
        test_analyze_factorial_confirmatory.py
        tenant_probe.py
        tenant_gateway.py
        factorial_environment.txt
    )
    tar -czf "${RESULT_ARCHIVE}.partial" -C "${WORK_DIR}" \
        "${members[@]}"
    mv "${RESULT_ARCHIVE}.partial" "${RESULT_ARCHIVE}"
    sha256sum "${RESULT_ARCHIVE}" > "${RESULT_ARCHIVE}.sha256"
    cat "${RESULT_ARCHIVE}.sha256"
}

mode="${1:-core}"
initialize_credentials
runtime_preflight
write_environment_manifest
run_local_self_tests
declare_protocol

case "${mode}" in
    gate)
        run_gate
        ;;
    performance)
        jq -e '.valid == true and .mechanism_gate.pass == true' \
            "${RESULT_ROOT}/gate_assessment.json" >/dev/null
        run_performance
        "${VENV_DIR}/bin/python" "${ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --require-performance \
            --output "${RESULT_ROOT}/factorial_assessment.json"
        archive_results
        ;;
    analyze)
        "${VENV_DIR}/bin/python" "${ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --require-performance \
            --output "${RESULT_ROOT}/factorial_assessment.json"
        archive_results
        ;;
    core)
        run_gate
        run_performance
        "${VENV_DIR}/bin/python" "${ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --require-performance \
            --output "${RESULT_ROOT}/factorial_assessment.json"
        archive_results
        ;;
    *)
        printf 'Usage: %s [gate|performance|analyze|core]\n' "$0" >&2
        exit 2
        ;;
esac
