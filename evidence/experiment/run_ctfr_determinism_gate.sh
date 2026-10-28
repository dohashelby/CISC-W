#!/usr/bin/env bash
set -Eeuo pipefail

readonly BASE_DRIVER="/home/ubuntu/avep/run_factorial_confirmatory.sh"
readonly BASE_DRIVER_SHA256="ea733ab7264d5c55418e2f0819da09d757deea15708885b2e495a440912ff172"
readonly EXPECTED_VLLM_SHA="4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c"
readonly EXPECTED_SOURCE_SHA256="dcc2239dd80e8e4095a76d31a09ae96b5a4de603ca16850706760b4bfe6a2387"
readonly MAX_GATE_SECONDS="${MAX_GATE_SECONDS:-6900}"

if [[ "${CTFR_DETERMINISM_GATE_CHILD:-0}" != "1" ]]; then
    export CTFR_DETERMINISM_GATE_CHILD=1
    exec timeout --signal=TERM --kill-after=120s \
        "${MAX_GATE_SECONDS}s" "$0" "$@"
fi

actual_base_driver_sha256="$(sha256sum "${BASE_DRIVER}" | cut -d' ' -f1)"
if [[ "${actual_base_driver_sha256}" != "${BASE_DRIVER_SHA256}" ]]; then
    printf 'Base driver SHA-256 does not match the commitment.\n' >&2
    exit 1
fi

# Import only the audited credential, gateway, RPC, and process-lifecycle
# functions. The experiment schedule below is intentionally independent.
# shellcheck disable=SC1090
source <(
    sed \
        -e '/^mode="${1:-core}"$/,$d' \
        -e 's#^readonly PROTOCOL_VERSION=.*#readonly PROTOCOL_VERSION="ctfr-determinism-gate-v1"#' \
        -e 's#^readonly RESULT_ROOT=.*#readonly RESULT_ROOT="${WORK_DIR}/ctfr_determinism_gate_v1"#' \
        -e 's#^readonly CREDENTIALS_FILE=.*#readonly CREDENTIALS_FILE="${WORK_DIR}/.avep_ctfr_full_v2_tenant_credentials.json"#' \
        -e 's#^readonly GATEWAY=.*#readonly GATEWAY="${WORK_DIR}/ctfr_gateway.py"#' \
        -e 's#^readonly ANALYZER=.*#readonly ANALYZER="${WORK_DIR}/analyze_ctfr_determinism_gate.py"#' \
        -e 's#^readonly RESULT_ARCHIVE=.*#readonly RESULT_ARCHIVE="${WORK_DIR}/avep-ctfr-determinism-gate-v1-results.tgz"#' \
        -e 's#^readonly PARTIAL_ARCHIVE=.*#readonly PARTIAL_ARCHIVE="${WORK_DIR}/avep-ctfr-determinism-gate-v1-partial.tgz"#' \
        "${BASE_DRIVER}"
)
trap - EXIT INT TERM

readonly DUAL_PROBE="${WORK_DIR}/ctfr_dual_probe.py"
readonly ANALYZER_TEST="${WORK_DIR}/test_analyze_ctfr_determinism_gate.py"
readonly MANIFEST_DIR="${WORK_DIR}/ctfr_manifests_v2"
readonly EVALUATION_MANIFEST="${MANIFEST_DIR}/shifted_evaluation.json"
readonly WARMUP_MANIFEST="${MANIFEST_DIR}/compile_warmup.json"
readonly BASELINE_STATE="${WORK_DIR}/ctfr_baseline_committed_state_v2.json"
readonly HYPERPARAMETERS="${WORK_DIR}/CTFR_FROZEN_HYPERPARAMETERS.json"
readonly ENVIRONMENT_FILE="${RESULT_ROOT}/environment.txt"
readonly WATCHDOG_UNIT="ctfr-determinism-shutdown-$(date +%s)"

archive_written=false

stack_digest() {
    local -a paths=(
        vllm/v1/worker/gpu/model_runner.py
        vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py
        vllm/v1/worker/gpu/spec_decode/adaptive_verification.py
        vllm/v1/worker/gpu/spec_decode/speculator.py
        vllm/v1/worker/gpu_worker.py
    )
    (
        cd "${REPO_DIR}"
        sha256sum "${paths[@]}"
    ) | sha256sum | cut -d' ' -f1
}

archive_results() {
    local destination="$1"
    local temporary="${destination}.partial"
    tar -czf "${temporary}" -C "${WORK_DIR}" \
        ctfr_determinism_gate_v1 \
        run_ctfr_determinism_gate.sh \
        analyze_ctfr_determinism_gate.py \
        test_analyze_ctfr_determinism_gate.py \
        ctfr_manifests_v2/compile_warmup.json \
        ctfr_manifests_v2/shifted_evaluation.json \
        ctfr_baseline_committed_state_v2.json \
        CTFR_FROZEN_HYPERPARAMETERS.json
    mv "${temporary}" "${destination}"
    sha256sum "${destination}" > "${destination}.sha256"
    archive_written=true
}

cleanup_gate() {
    local status="$?"
    set +e
    stop_server
    if ((status != 0)) && [[ -d "${RESULT_ROOT}" ]]; then
        printf 'exit_status=%s\ntimestamp=%s\n' \
            "${status}" "$(date --iso-8601=ns)" \
            > "${RESULT_ROOT}/DETERMINISM_GATE_FAILED.txt"
        if [[ "${archive_written}" != "true" ]]; then
            archive_results "${PARTIAL_ARCHIVE}"
        fi
    fi
    return "${status}"
}
trap cleanup_gate EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

runtime_preflight_gate() {
    local command_name
    for command_name in awk curl cut git jq nvidia-smi openssl ps sed \
        setsid sha256sum ss stat sudo systemd-run tar timeout uv; do
        command -v "${command_name}" >/dev/null 2>&1 || {
            printf 'Required command is unavailable: %s\n' \
                "${command_name}" >&2
            return 1
        }
    done
    local required_file
    for required_file in \
        "${VENV_DIR}/bin/python" \
        "${VENV_DIR}/bin/vllm" \
        "${GATEWAY}" \
        "${DUAL_PROBE}" \
        "${ANALYZER}" \
        "${ANALYZER_TEST}" \
        "${WARMUP_MANIFEST}" \
        "${EVALUATION_MANIFEST}" \
        "${BASELINE_STATE}" \
        "${HYPERPARAMETERS}"; do
        [[ -f "${required_file}" ]] || {
            printf 'Required input is unavailable: %s\n' \
                "${required_file}" >&2
            return 1
        }
    done
    [[ "$(git -C "${REPO_DIR}" rev-parse HEAD)" == \
        "${EXPECTED_VLLM_SHA}" ]] || {
        printf 'Pinned vLLM commit is not checked out.\n' >&2
        return 1
    }
    [[ "$(stack_digest)" == "${EXPECTED_SOURCE_SHA256}" ]] || {
        printf 'Runtime source stack does not match CTFR v2.\n' >&2
        return 1
    }
    if [[ -n "$(ss -H -ltn 'sport = :8000')" \
        || -n "$(ss -H -ltn 'sport = :8001')" ]]; then
        printf 'Port 8000 or 8001 is already occupied.\n' >&2
        return 1
    fi
    jq -e '
        .schema == "ctfr-baseline-v1"
        and (.coefficient_sha256 | test("^[0-9a-f]{64}$"))
        and (.slope | type) == "number"
        and (.intercepts | length) == 4
    ' "${BASELINE_STATE}" >/dev/null
    jq -e '
        .schema == "ctfr-workload-manifest-v1"
        and (.entries | length) == 256
    ' "${EVALUATION_MANIFEST}" >/dev/null
    (
        cd "${WORK_DIR}"
        "${VENV_DIR}/bin/python" -m unittest -v \
            test_analyze_ctfr_determinism_gate.py
    )
}

declare_gate() {
    if [[ -e "${RESULT_ROOT}" ]]; then
        printf 'Refusing to overwrite an existing determinism gate.\n' >&2
        return 1
    fi
    mkdir -p "${RESULT_ROOT}"
    local requests
    requests="$(jq -er '.entries | length' "${EVALUATION_MANIFEST}")"
    jq -n \
        --argjson evaluation_requests "${requests}" \
        --arg source_sha256 "${EXPECTED_SOURCE_SHA256}" \
        --arg baseline_sha256 \
            "$(jq -er '.coefficient_sha256' "${BASELINE_STATE}")" \
        '{
          schema: "ctfr-determinism-gate-v1",
          evaluation_requests: $evaluation_requests,
          source_sha256: $source_sha256,
          baseline_sha256: $baseline_sha256,
          deterministic_environment: {
            CUBLAS_WORKSPACE_CONFIG: ":4096:8",
            NVIDIA_TF32_OVERRIDE: "0",
            PYTHONHASHSEED: "0"
          },
          conditions: [
            {name: "graph_c32_a", execution_mode: "cuda-graph",
             concurrency: 32, waves_per_batch: 16, repetitions: 2},
            {name: "graph_c32_b", execution_mode: "cuda-graph",
             concurrency: 32, waves_per_batch: 16, repetitions: 1},
            {name: "graph_c2_a", execution_mode: "cuda-graph",
             concurrency: 2, waves_per_batch: 1, repetitions: 2},
            {name: "graph_c2_b", execution_mode: "cuda-graph",
             concurrency: 2, waves_per_batch: 1, repetitions: 1},
            {name: "eager_c2_a", execution_mode: "eager",
             concurrency: 2, waves_per_batch: 1, repetitions: 2},
            {name: "eager_c2_b", execution_mode: "eager",
             concurrency: 2, waves_per_batch: 1, repetitions: 1}
          ],
          inference_policy: {
            estimator_updates: false,
            estimator_state: "frozen committed baseline",
            temperature: 0,
            return_token_ids: true,
            prefix_caching: false
          }
        }' > "${RESULT_ROOT}/DECLARED_SCHEDULE.json"
    (
        cd "${WORK_DIR}"
        sha256sum \
            run_ctfr_determinism_gate.sh \
            analyze_ctfr_determinism_gate.py \
            test_analyze_ctfr_determinism_gate.py \
            ctfr_dual_probe.py \
            ctfr_gateway.py \
            ctfr_manifests_v2/compile_warmup.json \
            ctfr_manifests_v2/shifted_evaluation.json \
            ctfr_baseline_committed_state_v2.json \
            CTFR_FROZEN_HYPERPARAMETERS.json \
            > "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
    )
    date --iso-8601=ns > "${RESULT_ROOT}/DECLARED_AT_UTC.txt"
}

start_shutdown_watchdog() {
    printf '%s\n' "${WATCHDOG_UNIT}" > "${RESULT_ROOT}/WATCHDOG_UNIT.txt"
    sudo systemd-run \
        --unit="${WATCHDOG_UNIT}" \
        --on-active=2h \
        /usr/sbin/shutdown -h now \
        > "${RESULT_ROOT}/WATCHDOG_INSTALL.txt"
}

configure_ctfr_environment() {
    export VLLM_AVEP_EVAL_METRICS=1
    export VLLM_AVEP_PCFR_MODE=shared
    export VLLM_AVEP_CTFR_MIN_OBSERVATIONS
    export VLLM_AVEP_CTFR_DELTA_CLIP
    export VLLM_AVEP_CTFR_MIN_COSINE
    export VLLM_AVEP_CTFR_MAX_COMMIT_NORM
    export VLLM_AVEP_CTFR_MAX_PROBABILITY_SHIFT
    export VLLM_AVEP_CTFR_BUCKET_CAPACITY
    VLLM_AVEP_CTFR_MIN_OBSERVATIONS="$(
        jq -er '.min_observations' "${HYPERPARAMETERS}"
    )"
    VLLM_AVEP_CTFR_DELTA_CLIP="$(
        jq -er '.delta_clip' "${HYPERPARAMETERS}"
    )"
    VLLM_AVEP_CTFR_MIN_COSINE="$(
        jq -er '.min_cosine' "${HYPERPARAMETERS}"
    )"
    VLLM_AVEP_CTFR_MAX_COMMIT_NORM="$(
        jq -er '.max_commit_norm' "${HYPERPARAMETERS}"
    )"
    VLLM_AVEP_CTFR_MAX_PROBABILITY_SHIFT="$(
        jq -er '.max_probability_shift' "${HYPERPARAMETERS}"
    )"
    VLLM_AVEP_CTFR_BUCKET_CAPACITY="$(
        jq -er '.bucket_capacity' "${HYPERPARAMETERS}"
    )"
    export TRITON_ALLOW_NON_CONSTEXPR_GLOBALS=1
    export CUBLAS_WORKSPACE_CONFIG=:4096:8
    export NVIDIA_TF32_OVERRIDE=0
    export PYTHONHASHSEED=0
}

write_environment_manifest() {
    {
        printf 'vllm_sha=%s\n' "$(git -C "${REPO_DIR}" rev-parse HEAD)"
        printf 'source_stack_sha256=%s\n' "$(stack_digest)"
        printf 'cublas_workspace_config=%s\n' \
            "${CUBLAS_WORKSPACE_CONFIG}"
        printf 'nvidia_tf32_override=%s\n' "${NVIDIA_TF32_OVERRIDE}"
        printf 'pythonhashseed=%s\n' "${PYTHONHASHSEED}"
        "${VENV_DIR}/bin/python" --version
        "${VENV_DIR}/bin/python" -c \
            'import torch; print("torch=" + torch.__version__)'
        "${VENV_DIR}/bin/python" -c \
            'import importlib.metadata as m; print("vllm=" + m.version("vllm"))'
        nvidia-smi --query-gpu=name,driver_version,memory.total \
            --format=csv,noheader
    } > "${ENVIRONMENT_FILE}"
}

start_server_determinism() {
    local run_dir="$1"
    local execution_mode="$2"
    stop_server
    current_log="${run_dir}/server.log"
    export HF_HUB_DISABLE_TELEMETRY=1
    export VLLM_ADAPTIVE_VERIFICATION_PROFILE_CONTEXT_LEN=4096
    export VLLM_HOST_IP=127.0.0.1
    export VLLM_USE_V2_MODEL_RUNNER=1
    export VLLM_SERVER_DEV_MODE=1
    unset VLLM_AVEP_TELEMETRY || true
    unset VLLM_AVEP_TELEMETRY_BUDGET_EVERY || true
    local spec_config
    spec_config="$(printf '%s' '{
      "method":"dflash",
      "model":"z-lab/Qwen3-4B-DFlash-b16",
      "revision":"b74e3a329c4d963783143b1e970d95b002be72bd",
      "code_revision":"b74e3a329c4d963783143b1e970d95b002be72bd",
      "attention_backend":"TRITON_ATTN",
      "num_speculative_tokens":4,
      "max_model_len":4096,
      "enable_adaptive_verification":true
    }')"
    local -a server_args=(
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
        --enable-per-request-metrics
        --per-request-spec-decode-metrics detailed
        --speculative-config "${spec_config}"
    )
    case "${execution_mode}" in
        cuda-graph)
            server_args+=(
                --compilation-config \
                '{"cudagraph_mode":"FULL_AND_PIECEWISE"}'
            )
            ;;
        eager)
            server_args+=(--enforce-eager)
            ;;
        *)
            printf 'Unknown execution mode: %s\n' "${execution_mode}" >&2
            return 1
            ;;
    esac
    cd "${REPO_DIR}"
    : > "${current_log}"
    server_marker="determinism-${BASHPID}-$(date +%s%N)"
    nohup setsid "${VENV_DIR}/bin/vllm" "${server_args[@]}" \
        >> "${current_log}" 2>&1 &
    server_pid="$!"
    server_pgid="$(ps -o pgid= -p "${server_pid}" | tr -d '[:space:]')"
    printf '%s\n' "${server_pid}" > "${run_dir}/server.pid"
    printf '%s\n' "${server_pgid}" > "${run_dir}/server.pgid"
    printf '%s\n' "${server_marker}" > "${run_dir}/server.marker"
    local attempt
    for attempt in $(seq 1 180); do
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

wait_for_drain() {
    local run_dir="$1"
    local label="$2"
    local consecutive_zero=0
    local attempt
    local metrics_file="${run_dir}/metrics_${label}.prom"
    for attempt in $(seq 1 120); do
        curl --fail --silent --show-error \
            --connect-timeout 2 --max-time 10 \
            -H "Authorization: Bearer ${UPSTREAM_API_KEY}" \
            http://127.0.0.1:8000/metrics > "${metrics_file}.partial"
        mv "${metrics_file}.partial" "${metrics_file}"
        local running
        local waiting
        running="$(awk \
            '/^vllm:num_requests_running([{ ]|$)/ {sum += $NF}
             END {print sum + 0}' "${metrics_file}")"
        waiting="$(awk \
            '/^vllm:num_requests_waiting([{ ]|$)/ {sum += $NF}
             END {print sum + 0}' "${metrics_file}")"
        jq -cn \
            --arg sample_label "${label}" \
            --arg sampled_at "$(date --iso-8601=ns)" \
            --argjson running "${running}" \
            --argjson waiting "${waiting}" \
            '{label: $sample_label, sampled_at: $sampled_at,
              running: $running, waiting: $waiting}' \
            >> "${run_dir}/drain_evidence.jsonl"
        if [[ "${running}" == "0" && "${waiting}" == "0" ]]; then
            consecutive_zero=$((consecutive_zero + 1))
            if ((consecutive_zero == 2)); then
                return 0
            fi
        else
            consecutive_zero=0
        fi
        sleep 1
    done
    printf 'Queue did not drain for %s.\n' "${label}" >&2
    return 1
}

reset_estimator_named() {
    local run_dir="$1"
    local label="$2"
    rpc "${run_dir}/estimator_reset_${label}.json" \
        '{"method":"avep_reset_acceptance_estimator"}'
}

load_baseline_named() {
    local run_dir="$1"
    local label="$2"
    local serialized
    local payload
    serialized="$(jq -c '{slope: .slope, intercepts: .intercepts}' \
        "${BASELINE_STATE}")"
    payload="$(jq -cn --arg state "${serialized}" \
        '{method: "avep_load_acceptance_estimator_state", args: [$state]}')"
    rpc "${run_dir}/baseline_load_${label}.json" "${payload}"
}

reset_eval_metrics() {
    rpc "$1" '{"method":"avep_reset_acceptance_estimator_eval_metrics"}'
}

get_eval_metrics() {
    rpc "$1" '{"method":"avep_get_acceptance_estimator_eval_metrics"}'
}

run_manifest_probe() {
    local run_dir="$1"
    local output_name="$2"
    local phase="$3"
    local manifest="$4"
    local concurrency="$5"
    local waves_per_batch="$6"
    local -a cmd=(
        "${VENV_DIR}/bin/python"
        "${DUAL_PROBE}"
        --phase "${phase}"
        --run-id "$(basename "${run_dir}")"
        --gateway-instance-id "${gateway_instance_id}"
        --upstream-marker "${server_marker}"
        --manifest "${manifest}"
        --credentials "${CREDENTIALS_FILE}"
        --base-url http://127.0.0.1:8001/v1
        --concurrency "${concurrency}"
        --waves-per-batch "${waves_per_batch}"
        --return-token-ids
        --output "${run_dir}/${output_name}.json.partial"
    )
    mark_phase "${phase}_begin"
    timeout --signal=TERM --kill-after=60s \
        "${PHASE_TIMEOUT_SECONDS}s" "${cmd[@]}" \
        | tee "${run_dir}/${output_name}.summary.json.partial"
    mv "${run_dir}/${output_name}.json.partial" \
        "${run_dir}/${output_name}.json"
    mv "${run_dir}/${output_name}.summary.json.partial" \
        "${run_dir}/${output_name}.summary.json"
    mark_phase "${phase}_end"
}

assert_frozen_baseline() {
    local state_path="$1"
    local expected
    expected="$(jq -er '.coefficient_sha256' "${BASELINE_STATE}")"
    jq -e --arg expected "${expected}" '
        (.results | length) > 0
        and all(.results[];
          .available == true
          and .updates_enabled == false
          and .baseline_sha256 == $expected)
    ' "${state_path}" >/dev/null
}

write_condition_metadata() {
    local run_dir="$1"
    local condition="$2"
    local execution_mode="$3"
    local concurrency="$4"
    local waves_per_batch="$5"
    local repetitions="$6"
    jq -n \
        --arg condition "${condition}" \
        --arg execution_mode "${execution_mode}" \
        --arg process_uuid "${server_marker}" \
        --arg started_at "$(date --iso-8601=ns)" \
        --argjson concurrency "${concurrency}" \
        --argjson waves_per_batch "${waves_per_batch}" \
        --argjson repetitions "${repetitions}" \
        '{condition: $condition, execution_mode: $execution_mode,
          process_uuid: $process_uuid, started_at: $started_at,
          concurrency: $concurrency,
          waves_per_batch: $waves_per_batch,
          repetitions: $repetitions,
          estimator_updates: false}' > "${run_dir}/metadata.json"
}

run_condition() {
    local condition="$1"
    local execution_mode="$2"
    local concurrency="$3"
    local waves_per_batch="$4"
    local repetitions="$5"
    local run_dir="${RESULT_ROOT}/${condition}"
    mkdir "${run_dir}"
    : > "${run_dir}/drain_evidence.jsonl"
    start_server_determinism "${run_dir}" "${execution_mode}"
    write_condition_metadata \
        "${run_dir}" "${condition}" "${execution_mode}" \
        "${concurrency}" "${waves_per_batch}" "${repetitions}"

    reset_estimator_named "${run_dir}" warmup
    load_baseline_named "${run_dir}" warmup
    set_updates "${run_dir}" warmup false
    run_manifest_probe \
        "${run_dir}" warmup compile_warmup "${WARMUP_MANIFEST}" \
        "${concurrency}" "${waves_per_batch}"
    wait_for_drain "${run_dir}" warmup

    local repetition
    local label
    for repetition in $(seq 1 "${repetitions}"); do
        label="$(printf '%02d' "${repetition}")"
        reset_estimator_named "${run_dir}" "evaluation_${label}"
        load_baseline_named "${run_dir}" "evaluation_${label}"
        set_updates "${run_dir}" "evaluation_${label}" false
        reset_eval_metrics \
            "${run_dir}/eval_reset_${label}.json"
        snapshot_state "${run_dir}" "before_${label}"
        assert_frozen_baseline "${run_dir}/state_before_${label}.json"
        run_manifest_probe \
            "${run_dir}" "evaluation_${label}" \
            determinism_evaluation "${EVALUATION_MANIFEST}" \
            "${concurrency}" "${waves_per_batch}"
        wait_for_drain "${run_dir}" "evaluation_${label}"
        get_eval_metrics "${run_dir}/eval_metrics_${label}.json"
        snapshot_state "${run_dir}" "after_${label}"
        assert_frozen_baseline "${run_dir}/state_after_${label}.json"
    done
    stop_server
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

initialize_credentials
runtime_preflight_gate
declare_gate
start_shutdown_watchdog
configure_ctfr_environment
write_environment_manifest

run_condition graph_c32_a cuda-graph 32 16 2
run_condition graph_c32_b cuda-graph 32 16 1
run_condition graph_c2_a cuda-graph 2 1 2
run_condition graph_c2_b cuda-graph 2 1 1
run_condition eager_c2_a eager 2 1 2
run_condition eager_c2_b eager 2 1 1

"${VENV_DIR}/bin/python" "${ANALYZER}" \
    "${RESULT_ROOT}" \
    --output "${RESULT_ROOT}/assessment.json"
date --iso-8601=ns > "${RESULT_ROOT}/COMPLETE"
archive_results "${RESULT_ARCHIVE}"
cat "${RESULT_ARCHIVE}.sha256"
