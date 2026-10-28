#!/usr/bin/env bash
set -Eeuo pipefail

readonly WORK_DIR="${HOME}/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly VENV_DIR="${REPO_DIR}/.venv"
readonly RESULT_ROOT="${WORK_DIR}/paper_results"
readonly API_KEY="local-research-only"
readonly POST_WINDOWS="${POST_WINDOWS:-6}"
readonly PAIR_COUNT="${PAIR_COUNT:-6}"
readonly RESET_REPS="${RESET_REPS:-3}"
readonly ADAPTIVE_OFF_REPS="${ADAPTIVE_OFF_REPS:-3}"
readonly PHASE_TIMEOUT_SECONDS="${PHASE_TIMEOUT_SECONDS:-1800}"
readonly RESULT_ARCHIVE="${WORK_DIR}/avep-paper-results.tgz"
readonly PARTIAL_RESULT_ARCHIVE="${WORK_DIR}/avep-paper-results-partial.tgz"

mkdir -p "${RESULT_ROOT}"
export PATH="${VENV_DIR}/bin:${PATH}"

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

terminate_managed_server() {
    local pid="$1"
    local pgid
    if ! kill -0 "${pid}" 2>/dev/null; then
        return 0
    fi
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
            | grep -Fqx -- \
                "VLLM_AVEP_PROCESS_GROUP_MARKER=${marker}"; then
            return 0
        fi
    done < <(ps -eo pid=,pgid=)
    return 1
}

terminate_managed_group() {
    local pgid="$1"
    local marker="$2"
    if ! kill -0 -- "-${pgid}" 2>/dev/null; then
        return 0
    fi
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
    local stale_pgid
    local marker_file
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
            printf 'Stopping stale AVEP process group %s from %s.\n' \
                "${stale_pgid}" "${pgid_file}"
            terminate_managed_group "${stale_pgid}" "${stale_marker}"
        fi
        rm -f "${pgid_file}" "${marker_file}"
    done < <(
        find "${RESULT_ROOT}" -type f -name server.pgid -print | sort
    )

    while IFS= read -r pid_file; do
        stale_pid="$(tr -d '[:space:]' < "${pid_file}")"
        if [[ -n "${stale_pid}" ]] && kill -0 "${stale_pid}" 2>/dev/null; then
            printf 'Stopping stale AVEP server PID %s from %s.\n' \
                "${stale_pid}" "${pid_file}"
            terminate_managed_server "${stale_pid}"
        fi
        rm -f "${pid_file}"
    done < <(
        find "${RESULT_ROOT}" -type f -name server.pid -print | sort
    )

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
    server_marker="avep-${BASHPID}-$(date +%s%N)"
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
        printf 'The launched process did not become the expected AVEP server.\n' \
            >&2
        kill -TERM "${server_pid}" 2>/dev/null || true
        wait "${server_pid}" 2>/dev/null || true
        server_pid=""
        return 1
    fi
    server_pgid="$(ps -o pgid= -p "${server_pid}" | tr -d '[:space:]')"
    if [[ "${server_pgid}" != "${server_pid}" ]]; then
        printf 'The AVEP server was not isolated in its own process group.\n' >&2
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
    local cmd=(
        "${VENV_DIR}/bin/python"
        "${WORK_DIR}/paper_probe.py"
        --phase "${phase}"
        --principal "${principal}"
        --requests "${requests}"
        --concurrency "${concurrency}"
        --max-tokens "${max_tokens}"
        --api-key "${API_KEY}"
        --output "${run_dir}/${phase}.json"
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
        | tee "${run_dir}/${phase}.summary.json"; then
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
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 60 \
        -H 'Content-Type: application/json' \
        --data '{"method":"avep_get_acceptance_estimator_state"}' \
        http://127.0.0.1:8000/collective_rpc \
        > "${run_dir}/state_${phase}.json"
}

reset_estimator() {
    local run_dir="$1"
    curl --fail --silent --show-error \
        --connect-timeout 5 --max-time 60 \
        -H 'Content-Type: application/json' \
        --data '{"method":"avep_reset_acceptance_estimator"}' \
        http://127.0.0.1:8000/collective_rpc \
        > "${run_dir}/estimator_reset.json"
}

write_metadata() {
    local run_dir="$1"
    local run_name="$2"
    local pair_id="$3"
    local arm="$4"
    local adaptive="$5"
    local telemetry="$6"
    local token_id="$7"
    jq -n \
        --arg run_name "${run_name}" \
        --arg pair_id "${pair_id}" \
        --arg arm "${arm}" \
        --argjson adaptive "${adaptive}" \
        --argjson telemetry "${telemetry}" \
        --argjson poison_token_id "${token_id}" \
        '{
            run_name: $run_name,
            pair_id: ($pair_id | if . == "" then null else . end),
            arm: $arm,
            adaptive: $adaptive,
            telemetry: $telemetry,
            poison_token_id: $poison_token_id
        }' > "${run_dir}/metadata.json"
}

run_arm() {
    local run_name="$1"
    local pair_id="$2"
    local arm="$3"
    local adaptive="$4"
    local telemetry="$5"
    local detailed_metrics="$6"
    local token_id="$7"
    local return_token_ids="${8:-false}"
    local run_dir="${RESULT_ROOT}/${run_name}"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete run %s\n' "${run_name}"
        return
    fi
    mkdir -p "${run_dir}"
    write_metadata \
        "${run_dir}" "${run_name}" "${pair_id}" "${arm}" \
        "${adaptive}" "${telemetry}" "${token_id}"

    start_server "${run_dir}" "${adaptive}" "${telemetry}" "${detailed_metrics}"
    snapshot_state "${run_dir}" initial
    run_probe "${run_dir}" warmup victim 1024 32 32 "" "${return_token_ids}"
    snapshot_state "${run_dir}" warmup
    run_probe "${run_dir}" baseline victim 2048 32 32 "" "${return_token_ids}"
    snapshot_state "${run_dir}" baseline

    local intervention_token=""
    if [[ "${arm}" != "placebo" ]]; then
        intervention_token="${token_id}"
    fi
    run_probe \
        "${run_dir}" intervention attacker 1024 64 32 \
        "${intervention_token}" "${return_token_ids}"
    snapshot_state "${run_dir}" intervention

    if [[ "${arm}" == "reset" ]]; then
        reset_estimator "${run_dir}"
        snapshot_state "${run_dir}" reset
    fi

    for window_number in $(seq 1 "${POST_WINDOWS}"); do
        local window
        window="$(printf '%02d' "${window_number}")"
        run_probe \
            "${run_dir}" "post_${window}" victim 1024 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "post_${window}"
    done
    stop_server
    cp "${WORK_DIR}/manifest.txt" "${run_dir}/environment.txt"
    touch "${run_dir}/COMPLETE"
}

run_token_preflight() {
    local run_dir="${RESULT_ROOT}/token_preflight"
    local token_json
    local token_id
    local -a token_ids
    local -a candidate_files
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete token preflight.\n'
        return
    fi
    mkdir -p "${run_dir}"
    start_server "${run_dir}" true true true
    run_probe "${run_dir}" warmup victim 256 32 16 "" true
    if ! token_json="$(
        jq -er '
            [.ordinary_single_tokens[:6][]?.token_id
             | select(type == "number" and floor == . and . >= 0)]
            | if length == 0
              then error("no valid ordinary single-token candidates")
              else .[]
              end
        ' "${WORK_DIR}/ordinary_tokens.json"
    )"; then
        printf 'Token preflight has no valid token candidates.\n' >&2
        return 1
    fi
    mapfile -t token_ids <<< "${token_json}"
    for token_id in "${token_ids[@]}"; do
        if ! [[ "${token_id}" =~ ^[0-9]+$ ]]; then
            printf 'Invalid token candidate: %s\n' "${token_id}" >&2
            return 1
        fi
        run_probe \
            "${run_dir}" "token_${token_id}" attacker 64 64 16 \
            "${token_id}" true
    done
    stop_server

    mapfile -t candidate_files < <(
        find "${run_dir}" -maxdepth 1 -type f -name 'token_*.json' \
            -print | sort
    )
    if ((${#candidate_files[@]} == 0)); then
        printf 'Token preflight produced no candidate results.\n' >&2
        return 1
    fi
    if ! jq -ser '
        map(select(
            (.summary.draft_tokens | type) == "number"
            and .summary.draft_tokens > 0
            and (.summary.draft_acceptance_rate | type) == "number"
            and (.config.allowed_token_id | type) == "number"
        ))
        | if length == 0
          then error("no candidate produced usable speculative metrics")
          else min_by(.summary.draft_acceptance_rate)
               | .config.allowed_token_id
          end
    ' "${candidate_files[@]}" \
        | tee "${run_dir}/selected_token_id.txt.tmp"; then
        rm -f "${run_dir}/selected_token_id.txt.tmp"
        printf 'Token preflight could not select a poisoning token.\n' >&2
        return 1
    fi
    token_id="$(
        tr -d '[:space:]' < "${run_dir}/selected_token_id.txt.tmp"
    )"
    if ! [[ "${token_id}" =~ ^[0-9]+$ ]]; then
        rm -f "${run_dir}/selected_token_id.txt.tmp"
        printf 'Token preflight selected an invalid token ID: %s\n' \
            "${token_id}" >&2
        return 1
    fi
    mv "${run_dir}/selected_token_id.txt.tmp" \
        "${run_dir}/selected_token_id.txt"
    touch "${run_dir}/COMPLETE"
}

selected_token_id() {
    local selected="${RESULT_ROOT}/token_preflight/selected_token_id.txt"
    if [[ ! -f "${selected}" ]]; then
        printf 'Token preflight must run first.\n' >&2
        return 1
    fi
    local token_id
    token_id="$(tr -d '[:space:]' < "${selected}")"
    if ! [[ "${token_id}" =~ ^[0-9]+$ ]]; then
        printf 'Selected token ID is missing or invalid: %s\n' \
            "${token_id:-<empty>}" >&2
        return 1
    fi
    printf '%s\n' "${token_id}"
}

run_performance_pairs() {
    local token_id
    token_id="$(selected_token_id)"
    local orders=(
        'placebo attack'
        'attack placebo'
        'attack placebo'
        'placebo attack'
        'attack placebo'
        'placebo attack'
        'placebo attack'
        'attack placebo'
        'placebo attack'
        'attack placebo'
    )
    if ((PAIR_COUNT > ${#orders[@]})); then
        printf 'PAIR_COUNT is capped at %s.\n' "${#orders[@]}" >&2
        return 1
    fi
    for pair_number in $(seq 1 "${PAIR_COUNT}"); do
        local pair_id
        pair_id="$(printf '%02d' "${pair_number}")"
        for arm in ${orders[$((pair_number - 1))]}; do
            run_arm \
                "pair_${pair_id}_${arm}" "${pair_id}" "${arm}" \
                true false false "${token_id}" false
        done
    done
}

run_reset_controls() {
    local token_id
    token_id="$(selected_token_id)"
    for repetition in $(seq 1 "${RESET_REPS}"); do
        run_arm \
            "reset_$(printf '%02d' "${repetition}")" "" reset \
            true false false "${token_id}" false
    done
}

run_adaptive_off_controls() {
    local token_id
    token_id="$(selected_token_id)"
    for repetition in $(seq 1 "${ADAPTIVE_OFF_REPS}"); do
        run_arm \
            "adaptive_off_$(printf '%02d' "${repetition}")" "" adaptive_off \
            false false false "${token_id}" false
    done
}

run_mechanism_controls() {
    local token_id
    token_id="$(selected_token_id)"
    run_arm mechanism_attack "" attack true true true "${token_id}" true
    run_arm mechanism_placebo "" placebo true true true "${token_id}" true
}

analyze_results() {
    "${VENV_DIR}/bin/python" "${WORK_DIR}/analyze_paper_trials.py" \
        --result-root "${RESULT_ROOT}" \
        --output "${RESULT_ROOT}/paper_assessment.json" \
        --csv-output "${RESULT_ROOT}/paper_trials.csv" \
        | tee "${RESULT_ROOT}/paper_assessment.stdout.json"
}

archive_results() {
    local partial_archive="${RESULT_ARCHIVE}.partial"
    local -a archive_members=(
        paper_results
        manifest.txt
        ordinary_tokens.json
        paper_setup.log
        PAPER_SETUP_COMPLETE
        avep_paper_instrumentation.patch
        paper_probe.py
        find_ordinary_tokens.py
        analyze_paper_trials.py
        run_paper_trials.sh
        setup_paper_instance.sh
    )
    local member
    for member in "${archive_members[@]}"; do
        if [[ ! -e "${WORK_DIR}/${member}" ]]; then
            printf 'Cannot archive missing result input: %s\n' \
                "${WORK_DIR}/${member}" >&2
            return 1
        fi
    done

    date --iso-8601=seconds > "${RESULT_ROOT}/EXPERIMENT_COMPLETE"
    rm -f "${RESULT_ROOT}/EXPERIMENT_FAILED"
    tar -czf "${partial_archive}" -C "${WORK_DIR}" \
        "${archive_members[@]}"
    mv "${partial_archive}" "${RESULT_ARCHIVE}"
    sha256sum "${RESULT_ARCHIVE}" \
        > "${RESULT_ARCHIVE}.sha256"
    rm -f "${PARTIAL_RESULT_ARCHIVE}" \
        "${PARTIAL_RESULT_ARCHIVE}.sha256"
    cat "${RESULT_ARCHIVE}.sha256"
}

archive_partial_results() {
    local exit_status="$1"
    local partial_archive="${PARTIAL_RESULT_ARCHIVE}.partial"
    local -a possible_members=(
        paper_results
        manifest.txt
        ordinary_tokens.json
        paper_setup.log
        PAPER_SETUP_COMPLETE
        avep_paper_instrumentation.patch
        paper_probe.py
        find_ordinary_tokens.py
        analyze_paper_trials.py
        run_paper_trials.sh
        setup_paper_instance.sh
    )
    local -a archive_members=()
    local member
    command -v tar >/dev/null 2>&1 || return 0
    command -v sha256sum >/dev/null 2>&1 || return 0

    printf 'exit_status=%s\ntimestamp=%s\n' \
        "${exit_status}" "$(date --iso-8601=seconds)" \
        > "${RESULT_ROOT}/EXPERIMENT_FAILED"
    rm -f "${RESULT_ROOT}/EXPERIMENT_COMPLETE"
    for member in "${possible_members[@]}"; do
        if [[ -e "${WORK_DIR}/${member}" ]]; then
            archive_members+=("${member}")
        fi
    done
    ((${#archive_members[@]} > 0)) || return 0
    tar -czf "${partial_archive}" -C "${WORK_DIR}" \
        "${archive_members[@]}"
    mv "${partial_archive}" "${PARTIAL_RESULT_ARCHIVE}"
    sha256sum "${PARTIAL_RESULT_ARCHIVE}" \
        > "${PARTIAL_RESULT_ARCHIVE}.sha256"
    cat "${PARTIAL_RESULT_ARCHIVE}.sha256"
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
cleanup_stale_servers

mode="${1:-core}"
case "${mode}" in
    token-preflight)
        run_token_preflight
        ;;
    pairs)
        run_performance_pairs
        ;;
    controls)
        run_reset_controls
        run_adaptive_off_controls
        ;;
    mechanism)
        run_mechanism_controls
        ;;
    analyze)
        analyze_results
        archive_results
        ;;
    core)
        run_token_preflight
        run_performance_pairs
        run_reset_controls
        run_adaptive_off_controls
        run_mechanism_controls
        analyze_results
        archive_results
        ;;
    *)
        printf 'Unknown mode: %s\n' "${mode}" >&2
        exit 2
        ;;
esac
