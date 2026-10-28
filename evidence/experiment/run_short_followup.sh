#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROTOCOL_VERSION="avep-short-followup-v1"
readonly WORK_DIR="/home/ubuntu/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly VENV_DIR="${REPO_DIR}/.venv"
readonly RESULT_ROOT="${WORK_DIR}/followup_results"
readonly API_KEY="local-research-only"
readonly RULES_SOURCE="${WORK_DIR}/SHORT_FOLLOWUP_DECISION_RULES.md"
readonly ANALYZER="${WORK_DIR}/analyze_short_followup.py"
readonly PROBE="${WORK_DIR}/paper_probe.py"
readonly RESULT_ARCHIVE="${WORK_DIR}/avep-short-followup-results.tgz"
readonly PARTIAL_ARCHIVE="${WORK_DIR}/avep-short-followup-results-partial.tgz"
readonly PHASE_TIMEOUT_SECONDS="${PHASE_TIMEOUT_SECONDS:-1800}"
# One prefill-sampled token plus at most one speculative verification round.
readonly INTERVENTION_MAX_TOKENS=2

declare -ar SCREEN_TOKEN_IDS=(
    279 323 6303 8251 23811 3015 8094 12095 13 11 0 30
)
declare -ar GATE_ORDER=(placebo attack)
declare -ar PERFORMANCE_ORDERS=(
    "placebo attack"
    "attack placebo"
    "attack placebo"
    "placebo attack"
)

server_pid=""
server_pgid=""
server_marker=""
current_log=""

is_managed_server_pid() {
    local pid="$1"
    local command_line
    [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/${pid}/cmdline" ]] || return 1
    command_line="$(tr '\0' ' ' < "/proc/${pid}/cmdline")"
    [[ "${command_line}" == *"${VENV_DIR}/bin/vllm serve Qwen/Qwen3-4B"* ]]
    [[ "${command_line}" == *"--host 127.0.0.1"* ]]
    [[ "${command_line}" == *"--port 8000"* ]]
    [[ "${command_line}" == *"--api-key ${API_KEY}"* ]]
}

group_has_marker() {
    local pgid="$1"
    local marker="$2"
    local member_pid
    local member_pgid
    [[ "${pgid}" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -n "${marker}" ]] || return 1
    while read -r member_pid member_pgid; do
        [[ "${member_pgid}" == "${pgid}" ]] || continue
        [[ -r "/proc/${member_pid}/environ" ]] || continue
        if tr '\0' '\n' < "/proc/${member_pid}/environ" \
            | grep -Fqx -- "VLLM_AVEP_PROCESS_GROUP_MARKER=${marker}"; then
            return 0
        fi
    done < <(ps -eo pid=,pgid=)
    return 1
}

terminate_managed_server() {
    local pid="$1"
    local pgid
    kill -0 "${pid}" 2>/dev/null || return 0
    if ! is_managed_server_pid "${pid}"; then
        printf 'Refusing to stop unrecognized process with PID %s.\n' \
            "${pid}" >&2
        return 1
    fi
    pgid="$(ps -o pgid= -p "${pid}" | tr -d '[:space:]')"
    if [[ "${pgid}" == "${pid}" ]]; then
        kill -TERM -- "-${pgid}" 2>/dev/null || true
        for _ in $(seq 1 60); do
            kill -0 -- "-${pgid}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL -- "-${pgid}" 2>/dev/null || true
    else
        kill -TERM "${pid}" 2>/dev/null || true
        for _ in $(seq 1 60); do
            kill -0 "${pid}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "${pid}" 2>/dev/null || true
    fi
}

terminate_managed_group() {
    local pgid="$1"
    local marker="$2"
    kill -0 -- "-${pgid}" 2>/dev/null || return 0
    if ! group_has_marker "${pgid}" "${marker}"; then
        printf 'Refusing to stop unrecognized process group %s.\n' \
            "${pgid}" >&2
        return 1
    fi
    kill -TERM -- "-${pgid}" 2>/dev/null || true
    for _ in $(seq 1 60); do
        kill -0 -- "-${pgid}" 2>/dev/null || break
        sleep 1
    done
    kill -KILL -- "-${pgid}" 2>/dev/null || true
}

stop_server() {
    if [[ -n "${server_pgid}" && -n "${server_marker}" ]]; then
        terminate_managed_group "${server_pgid}" "${server_marker}" || true
    elif [[ -n "${server_pid}" ]]; then
        terminate_managed_server "${server_pid}" || true
    fi
    server_pid=""
    server_pgid=""
    server_marker=""
    unset VLLM_AVEP_PROCESS_GROUP_MARKER || true
}

cleanup_stale_servers() {
    local pgid_file
    local marker_file
    local stale_pgid
    local stale_marker
    local pid_file
    local stale_pid
    while IFS= read -r pgid_file; do
        marker_file="${pgid_file%.pgid}.marker"
        stale_pgid="$(tr -d '[:space:]' < "${pgid_file}")"
        stale_marker=""
        if [[ -f "${marker_file}" ]]; then
            stale_marker="$(tr -d '[:space:]' < "${marker_file}")"
        fi
        if [[ -n "${stale_pgid}" && -n "${stale_marker}" ]] \
            && kill -0 -- "-${stale_pgid}" 2>/dev/null; then
            terminate_managed_group "${stale_pgid}" "${stale_marker}"
        fi
    done < <(find "${RESULT_ROOT}" -type f -name server.pgid -print | sort)

    while IFS= read -r pid_file; do
        stale_pid="$(tr -d '[:space:]' < "${pid_file}")"
        if [[ -n "${stale_pid}" ]] && kill -0 "${stale_pid}" 2>/dev/null; then
            terminate_managed_server "${stale_pid}"
        fi
    done < <(find "${RESULT_ROOT}" -type f -name server.pid -print | sort)

    if [[ -n "$(ss -H -ltn 'sport = :8000')" ]]; then
        printf 'TCP port 8000 is occupied by an unmanaged listener.\n' >&2
        return 1
    fi
}

runtime_preflight() {
    local command_name
    for command_name in curl find grep jq ps setsid sha256sum ss tar timeout; do
        if ! command -v "${command_name}" >/dev/null 2>&1; then
            printf 'Required command is unavailable: %s\n' \
                "${command_name}" >&2
            return 1
        fi
    done
    if ! [[ "${PHASE_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]]; then
        printf 'PHASE_TIMEOUT_SECONDS must be a positive integer.\n' >&2
        return 1
    fi
    if ((INTERVENTION_MAX_TOKENS < 2)) \
        || ((INTERVENTION_MAX_TOKENS != 2)); then
        printf 'INTERVENTION_MAX_TOKENS must remain exactly 2.\n' >&2
        return 1
    fi
    local required_file
    for required_file in \
        "${VENV_DIR}/bin/vllm" \
        "${VENV_DIR}/bin/python" \
        "${PROBE}" \
        "${ANALYZER}" \
        "${WORK_DIR}/test_analyze_short_followup.py" \
        "${RULES_SOURCE}" \
        "${WORK_DIR}/SHORT_FOLLOWUP_PROTOCOL.md" \
        "${WORK_DIR}/ordinary_tokens.json" \
        "${WORK_DIR}/manifest.txt"; do
        if [[ ! -f "${required_file}" ]]; then
            printf 'Required input is unavailable: %s\n' \
                "${required_file}" >&2
            return 1
        fi
    done
    jq -e '
        . as $document
        | [.ordinary_single_tokens[].token_id]
            == [279,323,6303,8251,23811,3015,8094,12095,13,11,0,30]
        and ([.ordinary_single_tokens[].token_id]
            | all(.[]; . as $id
                | ($document.special_token_ids | index($id) | not)))
    ' "${WORK_DIR}/ordinary_tokens.json" >/dev/null
}

declare_protocol() {
    mkdir -p "${RESULT_ROOT}"
    local declared_rules="${RESULT_ROOT}/DECLARED_DECISION_RULES.md"
    local schedule="${RESULT_ROOT}/DECLARED_SCHEDULE.json"
    if [[ ! -f "${RESULT_ROOT}/DECLARED_AT_UTC.txt" ]]; then
        if find "${RESULT_ROOT}" -mindepth 1 -maxdepth 1 \
            ! -name '_incomplete' -print -quit | grep -q .; then
            printf 'Refusing to declare rules over pre-existing follow-up data.\n' \
                >&2
            return 1
        fi
        cp "${RULES_SOURCE}" "${declared_rules}.partial"
        mv "${declared_rules}.partial" "${declared_rules}"
        jq -n \
            --arg protocol_version "${PROTOCOL_VERSION}" \
            '{
                schema_version: 1,
                protocol_version: $protocol_version,
                screen: {
                    token_ids: [
                        279, 323, 6303, 8251, 23811, 3015,
                        8094, 12095, 13, 11, 0, 30
                    ],
                    warmup: {
                        requests: 512,
                        concurrency: 32,
                        max_tokens: 32
                    },
                    candidate: {
                        requests: 256,
                        concurrency: 8,
                        max_tokens: 2
                    }
                },
                gate_order: ["placebo", "attack"],
                performance_orders: [
                    ["placebo", "attack"],
                    ["attack", "placebo"],
                    ["attack", "placebo"],
                    ["placebo", "attack"]
                ],
                adaptive_workload: {
                    reset_after_server_ready: true,
                    warmup: {
                        requests: 1024,
                        concurrency: 32,
                        max_tokens: 32
                    },
                    pre: {
                        windows: 4,
                        requests_per_window: 128,
                        concurrency: 32,
                        max_tokens: 32
                    },
                    intervention: {
                        requests: 4096,
                        concurrency: 8,
                        max_tokens: 2
                    },
                    post: {
                        windows: 8,
                        requests_per_window: 128,
                        concurrency: 32,
                        max_tokens: 32
                    }
                }
            }' > "${schedule}.partial"
        mv "${schedule}.partial" "${schedule}"
        (
            cd "${RESULT_ROOT}"
            sha256sum DECLARED_DECISION_RULES.md \
                > DECLARED_DECISION_RULES.md.sha256
            sha256sum DECLARED_SCHEDULE.json \
                > DECLARED_SCHEDULE.json.sha256
        )
        (
            cd "${WORK_DIR}"
            sha256sum \
                run_short_followup.sh \
                analyze_short_followup.py \
                test_analyze_short_followup.py \
                paper_probe.py \
                SHORT_FOLLOWUP_DECISION_RULES.md \
                SHORT_FOLLOWUP_PROTOCOL.md \
                avep_paper_instrumentation.patch \
                > "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
        )
        date --iso-8601=ns > "${RESULT_ROOT}/DECLARED_AT_UTC.txt"
    fi
    (
        cd "${RESULT_ROOT}"
        sha256sum -c DECLARED_DECISION_RULES.md.sha256
        sha256sum -c DECLARED_SCHEDULE.json.sha256
    )
    (
        cd "${WORK_DIR}"
        sha256sum -c "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
    )
}

mark_phase() {
    local phase="$1"
    printf '===== AVEP_PHASE %s %s =====\n' \
        "${phase}" "$(date --iso-8601=ns)" >> "${current_log}"
}

start_server() {
    local run_dir="$1"
    local adaptive="$2"
    local telemetry="$3"
    local detailed_metrics="$4"
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
        \"enable_adaptive_verification\":${adaptive}
    }")"

    local server_args=(
        serve Qwen/Qwen3-4B
        --revision 1cfa9a7208912126459214e8b04321603b3df60c
        --host 127.0.0.1
        --port 8000
        --api-key "${API_KEY}"
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
    server_marker="short-followup-${BASHPID}-$(date +%s%N)"
    export VLLM_AVEP_PROCESS_GROUP_MARKER="${server_marker}"
    nohup setsid "${VENV_DIR}/bin/vllm" "${server_args[@]}" \
        >> "${current_log}" 2>&1 &
    server_pid="$!"
    for _ in $(seq 1 50); do
        if is_managed_server_pid "${server_pid}"; then
            break
        fi
        kill -0 "${server_pid}" 2>/dev/null || break
        sleep 0.1
    done
    if ! is_managed_server_pid "${server_pid}"; then
        printf 'The launched process did not become the expected server.\n' >&2
        kill -TERM "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
        server_pid=""
        return 1
    fi
    server_pgid="$(ps -o pgid= -p "${server_pid}" | tr -d '[:space:]')"
    if [[ "${server_pgid}" != "${server_pid}" ]]; then
        printf 'The server was not isolated in its own process group.\n' >&2
        terminate_managed_server "${server_pid}" || true
        server_pid=""
        server_pgid=""
        return 1
    fi
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
            -H "Authorization: Bearer ${API_KEY}" \
            http://127.0.0.1:8000/v1/models >/dev/null; then
            mark_phase server_ready
            return 0
        fi
        sleep 10
    done
    tail -200 "${current_log}"
    return 1
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
    local output_partial="${run_dir}/${phase}.json.partial"
    local summary_partial="${run_dir}/${phase}.summary.json.partial"
    local cmd=(
        "${VENV_DIR}/bin/python"
        "${PROBE}"
        --phase "${phase}"
        --principal "${principal}"
        --requests "${requests}"
        --concurrency "${concurrency}"
        --max-tokens "${max_tokens}"
        --api-key "${API_KEY}"
        --output "${output_partial}"
    )
    if [[ -n "${allowed_token_id}" ]]; then
        cmd+=(--allowed-token-id "${allowed_token_id}")
    fi
    if [[ "${return_token_ids}" == "true" ]]; then
        cmd+=(--return-token-ids)
    fi
    mark_phase "${phase}_begin"
    if timeout --signal=TERM --kill-after=60s \
        "${PHASE_TIMEOUT_SECONDS}s" "${cmd[@]}" \
        | tee "${summary_partial}"; then
        mv "${output_partial}" "${run_dir}/${phase}.json"
        mv "${summary_partial}" "${run_dir}/${phase}.summary.json"
        mark_phase "${phase}_end"
    else
        local status="$?"
        mark_phase "${phase}_failed_status_${status}"
        printf 'Phase %s failed or exceeded its %ss deadline.\n' \
            "${phase}" "${PHASE_TIMEOUT_SECONDS}" >&2
        return "${status}"
    fi
}

snapshot_state() {
    local run_dir="$1"
    local phase="$2"
    local output="${run_dir}/state_${phase}.json"
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 60 \
        -H 'Content-Type: application/json' \
        --data '{"method":"avep_get_acceptance_estimator_state"}' \
        http://127.0.0.1:8000/collective_rpc > "${output}.partial"
    mv "${output}.partial" "${output}"
}

reset_estimator() {
    local run_dir="$1"
    local output="${run_dir}/estimator_reset.json"
    mark_phase startup_reset_begin
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 60 \
        -H 'Content-Type: application/json' \
        --data '{"method":"avep_reset_acceptance_estimator"}' \
        http://127.0.0.1:8000/collective_rpc > "${output}.partial"
    mv "${output}.partial" "${output}"
    mark_phase startup_reset_end
}

prepare_run_dir() {
    local run_dir="$1"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        return 1
    fi
    if [[ -d "${run_dir}" ]]; then
        local incomplete_dir="${RESULT_ROOT}/_incomplete"
        local suffix
        suffix="$(date --utc +%Y%m%dT%H%M%S%N)"
        mkdir -p "${incomplete_dir}"
        mv "${run_dir}" "${incomplete_dir}/$(basename "${run_dir}").${suffix}"
    fi
    mkdir -p "${run_dir}"
    return 0
}

write_metadata() {
    local run_dir="$1"
    local run_name="$2"
    local stage="$3"
    local pair_id="$4"
    local arm="$5"
    local adaptive="$6"
    local telemetry="$7"
    local detailed_metrics="$8"
    local token_id="$9"
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --arg run_name "${run_name}" \
        --arg stage "${stage}" \
        --arg pair_id "${pair_id}" \
        --arg arm "${arm}" \
        --argjson adaptive "${adaptive}" \
        --argjson telemetry "${telemetry}" \
        --argjson detailed_metrics "${detailed_metrics}" \
        --argjson poison_token_id "${token_id}" \
        --arg created_at "$(date --iso-8601=ns)" \
        '{
            protocol_version: $protocol_version,
            run_name: $run_name,
            stage: $stage,
            pair_id: ($pair_id | if . == "" then null else . end),
            arm: $arm,
            adaptive: $adaptive,
            telemetry: $telemetry,
            detailed_metrics: $detailed_metrics,
            poison_token_id: $poison_token_id,
            created_at: $created_at
        }' > "${run_dir}/metadata.json.partial"
    mv "${run_dir}/metadata.json.partial" "${run_dir}/metadata.json"
}

run_screen() {
    local run_dir="${RESULT_ROOT}/screen"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete screen.\n'
        return
    fi
    prepare_run_dir "${run_dir}" || return
    write_metadata \
        "${run_dir}" screen screen "" screen false false true null
    start_server "${run_dir}" false false true
    run_probe "${run_dir}" warmup victim 512 32 32 "" false

    local token_id
    local -a candidate_files=()
    for token_id in "${SCREEN_TOKEN_IDS[@]}"; do
        run_probe \
            "${run_dir}" "token_${token_id}" attacker 256 8 \
            "${INTERVENTION_MAX_TOKENS}" \
            "${token_id}" true
        candidate_files+=("${run_dir}/token_${token_id}.json")
    done
    stop_server

    jq -s '
        if length != 12 then error("screen did not produce 12 candidates") else . end
        | if all(.[];
            .config.requests == 256
            and .config.concurrency == 8
            and .config.max_tokens == 2
            and .config.return_token_ids == true
            and (.config.allowed_token_id | type) == "number"
            and .summary.requests == 256
            and .summary.successful == 256
            and .summary.failed == 0
            and .summary.spec_requests == 256
            and (.summary.spec_steps > 0)
            and (.summary.draft_tokens > 0)
            and (.summary.draft_acceptance_rate | type) == "number"
            and .summary.control_token_fraction == 1
        ) then . else error("invalid screen candidate") end
        | to_entries
        | min_by([.value.summary.draft_acceptance_rate, .key])
        | {
            selected_token_id: .value.config.allowed_token_id,
            selected_acceptance_rate:
                .value.summary.draft_acceptance_rate,
            tie_break_position: .key
        }
    ' "${candidate_files[@]}" > "${run_dir}/selected_token.json.partial"
    mv "${run_dir}/selected_token.json.partial" \
        "${run_dir}/selected_token.json"
    jq -er '.selected_token_id' "${run_dir}/selected_token.json" \
        > "${run_dir}/selected_token_id.txt"
    cp "${WORK_DIR}/manifest.txt" "${run_dir}/environment.txt"
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

selected_token_id() {
    local path="${RESULT_ROOT}/screen/selected_token_id.txt"
    if [[ ! -f "${path}" ]]; then
        printf 'The screen must complete before adaptive-on runs.\n' >&2
        return 1
    fi
    local token_id
    token_id="$(tr -d '[:space:]' < "${path}")"
    if ! [[ "${token_id}" =~ ^[0-9]+$ ]]; then
        printf 'The selected ordinary token is invalid: %s\n' \
            "${token_id:-<empty>}" >&2
        return 1
    fi
    printf '%s\n' "${token_id}"
}

run_adaptive_arm() {
    local run_name="$1"
    local stage="$2"
    local pair_id="$3"
    local arm="$4"
    local telemetry="$5"
    local detailed_metrics="$6"
    local return_token_ids="$7"
    local token_id
    token_id="$(selected_token_id)"
    local run_dir="${RESULT_ROOT}/${run_name}"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete run %s.\n' "${run_name}"
        return
    fi
    prepare_run_dir "${run_dir}" || return
    write_metadata \
        "${run_dir}" "${run_name}" "${stage}" "${pair_id}" "${arm}" \
        true "${telemetry}" "${detailed_metrics}" "${token_id}"

    start_server "${run_dir}" true "${telemetry}" "${detailed_metrics}"
    snapshot_state "${run_dir}" server_ready
    reset_estimator "${run_dir}"
    snapshot_state "${run_dir}" reset

    run_probe \
        "${run_dir}" warmup victim 1024 32 32 "" \
        "${return_token_ids}"
    snapshot_state "${run_dir}" warmup

    local window_number
    local window
    for window_number in $(seq 1 4); do
        window="$(printf '%02d' "${window_number}")"
        run_probe \
            "${run_dir}" "pre_${window}" victim 128 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "pre_${window}"
    done

    local intervention_token=""
    if [[ "${arm}" == "attack" ]]; then
        intervention_token="${token_id}"
    fi
    run_probe \
        "${run_dir}" intervention attacker 4096 8 \
        "${INTERVENTION_MAX_TOKENS}" \
        "${intervention_token}" "${return_token_ids}"
    snapshot_state "${run_dir}" intervention

    for window_number in $(seq 1 8); do
        window="$(printf '%02d' "${window_number}")"
        run_probe \
            "${run_dir}" "post_${window}" victim 128 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "post_${window}"
    done
    stop_server
    cp "${WORK_DIR}/manifest.txt" "${run_dir}/environment.txt"
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

run_gate_pair() {
    local arm
    for arm in "${GATE_ORDER[@]}"; do
        run_adaptive_arm \
            "gate_${arm}" gate gate "${arm}" true true true
    done
}

run_performance_pairs() {
    local pair_number
    local pair_id
    local arm
    for pair_number in $(seq 1 4); do
        pair_id="$(printf '%02d' "${pair_number}")"
        for arm in ${PERFORMANCE_ORDERS[$((pair_number - 1))]}; do
            run_adaptive_arm \
                "perf_pair_${pair_id}_${arm}" performance "${pair_id}" \
                "${arm}" false false false
        done
    done
}

analyze_gate() {
    "${VENV_DIR}/bin/python" "${ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --rules "${RULES_SOURCE}" \
        --gate-only \
        --output "${RESULT_ROOT}/gate_assessment.json.partial"
    mv "${RESULT_ROOT}/gate_assessment.json.partial" \
        "${RESULT_ROOT}/gate_assessment.json"
}

analyze_complete_followup() {
    "${VENV_DIR}/bin/python" "${ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --rules "${RULES_SOURCE}" \
        --require-performance \
        --output "${RESULT_ROOT}/followup_assessment.json.partial"
    mv "${RESULT_ROOT}/followup_assessment.json.partial" \
        "${RESULT_ROOT}/followup_assessment.json"
}

potency_gate_passes() {
    jq -e '.potency.pass == true' \
        "${RESULT_ROOT}/gate_assessment.json" >/dev/null
}

performance_artifacts_exist() {
    find "${RESULT_ROOT}" -mindepth 1 -maxdepth 1 -type d \
        -name 'perf_pair_*' -print -quit | grep -q .
}

refuse_failed_gate_with_performance() {
    if performance_artifacts_exist; then
        printf '%s\n' \
            'The potency gate failed while performance artifacts exist.' \
            'Refusing to ignore or relabel those artifacts.' >&2
        return 1
    fi
}

archive_results() {
    local completion="$1"
    local archive_partial="${RESULT_ARCHIVE}.partial"
    local -a members=(
        followup_results
        manifest.txt
        ordinary_tokens.json
        avep_paper_instrumentation.patch
        paper_probe.py
        analyze_short_followup.py
        test_analyze_short_followup.py
        run_short_followup.sh
        SHORT_FOLLOWUP_DECISION_RULES.md
        SHORT_FOLLOWUP_PROTOCOL.md
    )
    local member
    for member in "${members[@]}"; do
        if [[ ! -e "${WORK_DIR}/${member}" ]]; then
            printf 'Cannot archive missing follow-up input: %s\n' \
                "${WORK_DIR}/${member}" >&2
            return 1
        fi
    done
    printf '%s\n' "${completion}" \
        > "${RESULT_ROOT}/FOLLOWUP_COMPLETION_STATUS.txt"
    date --iso-8601=ns > "${RESULT_ROOT}/FOLLOWUP_ARCHIVED_AT_UTC.txt"
    tar -czf "${archive_partial}" -C "${WORK_DIR}" "${members[@]}"
    mv "${archive_partial}" "${RESULT_ARCHIVE}"
    sha256sum "${RESULT_ARCHIVE}" > "${RESULT_ARCHIVE}.sha256"
    cat "${RESULT_ARCHIVE}.sha256"
}

archive_partial_results() {
    local exit_status="$1"
    local archive_partial="${PARTIAL_ARCHIVE}.partial"
    printf 'exit_status=%s\ntimestamp=%s\n' \
        "${exit_status}" "$(date --iso-8601=ns)" \
        > "${RESULT_ROOT}/FOLLOWUP_FAILED.txt"
    tar -czf "${archive_partial}" -C "${WORK_DIR}" \
        followup_results \
        manifest.txt \
        ordinary_tokens.json \
        avep_paper_instrumentation.patch \
        paper_probe.py \
        analyze_short_followup.py \
        test_analyze_short_followup.py \
        run_short_followup.sh \
        SHORT_FOLLOWUP_DECISION_RULES.md \
        SHORT_FOLLOWUP_PROTOCOL.md
    mv "${archive_partial}" "${PARTIAL_ARCHIVE}"
    sha256sum "${PARTIAL_ARCHIVE}" > "${PARTIAL_ARCHIVE}.sha256"
}

on_exit() {
    local status="$?"
    trap - EXIT
    stop_server
    if ((status != 0)); then
        set +e
        archive_partial_results "${status}"
    fi
    exit "${status}"
}

trap on_exit EXIT

runtime_preflight
declare_protocol
cleanup_stale_servers

mode="${1:-core}"
case "${mode}" in
    gate)
        run_screen
        run_gate_pair
        if performance_artifacts_exist; then
            printf '%s\n' \
                'Gate-only collection refuses existing performance artifacts.' \
                'Use core, performance, or analyze mode instead.' >&2
            exit 4
        fi
        analyze_gate
        if potency_gate_passes; then
            date --iso-8601=ns > "${RESULT_ROOT}/GATE_PASSED"
            archive_results GATE_PASSED
        else
            date --iso-8601=ns > "${RESULT_ROOT}/FOLLOWUP_STOPPED_AT_GATE"
            archive_results STOPPED_AT_GATE
        fi
        ;;
    performance)
        analyze_gate
        if ! potency_gate_passes; then
            if ! refuse_failed_gate_with_performance; then
                exit 4
            fi
            printf 'The fixed potency gate did not pass; refusing performance.\n' \
                >&2
            exit 3
        fi
        run_performance_pairs
        analyze_complete_followup
        archive_results PERFORMANCE_COMPLETE
        ;;
    analyze)
        analyze_gate
        if performance_artifacts_exist; then
            if ! potency_gate_passes; then
                if ! refuse_failed_gate_with_performance; then
                    exit 4
                fi
                exit 4
            fi
            analyze_complete_followup
            archive_results PERFORMANCE_COMPLETE
        elif potency_gate_passes; then
            archive_results GATE_PASSED
        else
            archive_results STOPPED_AT_GATE
        fi
        ;;
    core)
        run_screen
        run_gate_pair
        analyze_gate
        if potency_gate_passes; then
            date --iso-8601=ns > "${RESULT_ROOT}/GATE_PASSED"
            run_performance_pairs
            analyze_complete_followup
            archive_results PERFORMANCE_COMPLETE
        else
            if ! refuse_failed_gate_with_performance; then
                exit 4
            fi
            date --iso-8601=ns > "${RESULT_ROOT}/FOLLOWUP_STOPPED_AT_GATE"
            archive_results STOPPED_AT_GATE
        fi
        ;;
    *)
        printf 'Unknown mode: %s\n' "${mode}" >&2
        exit 2
        ;;
esac
