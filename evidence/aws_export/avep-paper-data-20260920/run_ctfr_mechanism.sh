#!/usr/bin/env bash
set -Eeuo pipefail

readonly BASE_DRIVER="/home/ubuntu/avep/run_factorial_confirmatory.sh"
readonly BASE_DRIVER_SHA256="ea733ab7264d5c55418e2f0819da09d757deea15708885b2e495a440912ff172"

actual_base_driver_sha256="$(sha256sum "${BASE_DRIVER}" | cut -d' ' -f1)"
if [[ "${actual_base_driver_sha256}" != "${BASE_DRIVER_SHA256}" ]]; then
    printf 'Base driver SHA-256 does not match the CTFR commitment.\n' >&2
    exit 1
fi

# Reuse the audited lifecycle, authenticated gateway, workload generator, and
# process controls. Everything treatment-specific is overridden below.
# shellcheck disable=SC1090
source <(
    sed \
        -e '/^mode="${1:-core}"$/,$d' \
        -e 's/avep-factorial-confirmatory-v1/avep-ctfr-mechanism-v1/g' \
        -e 's/factorial_confirmatory_results_v1/ctfr_mechanism_results_v1/g' \
        -e 's/\.avep_factorial_v1_tenant_credentials/\.avep_ctfr_mechanism_v1_tenant_credentials/g' \
        -e 's/FACTORIAL_CONFIRMATORY_PROTOCOL\.md/CTFR_EXPERIMENT_PROTOCOL.md/g' \
        -e 's/FACTORIAL_CONFIRMATORY_DECISION_RULES\.md/CTFR_DECISION_RULES.md/g' \
        -e 's/run_factorial_confirmatory\.sh/run_ctfr_mechanism.sh/g' \
        -e 's/analyze_factorial_confirmatory\.py/analyze_ctfr_mechanism.py/g' \
        -e 's/test_analyze_factorial_confirmatory\.py/test_analyze_ctfr_mechanism.py/g' \
        -e 's/tenant_gateway\.py/ctfr_gateway.py/g' \
        -e 's/factorial_environment\.txt/ctfr_environment.txt/g' \
        "${BASE_DRIVER}"
)

readonly PCFR_PATCH="${WORK_DIR}/avep_pcfr_mitigation.patch"
readonly CTFR_PATCH="${WORK_DIR}/avep_ctfr_mitigation.patch"
readonly CTFR_DESIGN="${WORK_DIR}/CTFR_DESIGN.md"

cleanup() {
    local status="$?"
    stop_server || true
    if ((status != 0)) && [[ -d "${RESULT_ROOT}" ]]; then
        printf 'exit_status=%s\ntimestamp=%s\n' \
            "${status}" "$(date --iso-8601=ns)" \
            > "${RESULT_ROOT}/CTFR_MECHANISM_FAILED.txt"
        tar -czf "${PARTIAL_ARCHIVE}.partial" -C "${WORK_DIR}" \
            ctfr_mechanism_results_v1 \
            CTFR_DESIGN.md \
            CTFR_THREAT_MODEL.md \
            CTFR_EXPERIMENT_PROTOCOL.md \
            CTFR_DECISION_RULES.md \
            CTFR_RELATED_WORK_BOUNDARY.md \
            CTFR_PAPER_PLAN.md \
            CTFR_DEPLOYMENT_CONTENTS.md \
            avep_paper_instrumentation.patch \
            avep_causal_ablation.patch \
            avep_pcfr_mitigation.patch \
            avep_ctfr_mitigation.patch \
            prepare_ctfr_source.sh \
            run_factorial_confirmatory.sh \
            run_ctfr_mechanism.sh \
            analyze_factorial_confirmatory.py \
            analyze_ctfr_mechanism.py \
            test_analyze_ctfr_mechanism.py \
            tenant_probe.py \
            ctfr_gateway.py \
            ctfr_environment.txt 2>/dev/null || true
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
    for command_name in curl cut find git jq ninja nvidia-smi openssl ps \
        setsid sha256sum ss stat tar timeout uv; do
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
        "${WORK_DIR}/analyze_factorial_confirmatory.py" \
        "${WORK_DIR}/test_analyze_ctfr_mechanism.py" \
        "${RULES_SOURCE}" \
        "${WORK_DIR}/CTFR_EXPERIMENT_PROTOCOL.md" \
        "${WORK_DIR}/CTFR_THREAT_MODEL.md" \
        "${WORK_DIR}/CTFR_RELATED_WORK_BOUNDARY.md" \
        "${WORK_DIR}/CTFR_PAPER_PLAN.md" \
        "${WORK_DIR}/CTFR_DEPLOYMENT_CONTENTS.md" \
        "${CTFR_DESIGN}" \
        "${WORK_DIR}/avep_paper_instrumentation.patch" \
        "${WORK_DIR}/avep_causal_ablation.patch" \
        "${PCFR_PATCH}" \
        "${CTFR_PATCH}" \
        "${WORK_DIR}/prepare_ctfr_source.sh"; do
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
    local output="${WORK_DIR}/ctfr_environment.txt"
    local temporary="${output}.partial"
    {
        printf 'vllm_sha=%s\n' "$(git -C "${REPO_DIR}" rev-parse HEAD)"
        printf 'paper_patch_sha256=%s\n' \
            "$(sha256sum "${WORK_DIR}/avep_paper_instrumentation.patch" \
                | cut -d' ' -f1)"
        printf 'causal_patch_sha256=%s\n' \
            "$(sha256sum "${WORK_DIR}/avep_causal_ablation.patch" \
                | cut -d' ' -f1)"
        printf 'pcfr_patch_sha256=%s\n' \
            "$(sha256sum "${PCFR_PATCH}" | cut -d' ' -f1)"
        printf 'ctfr_patch_sha256=%s\n' \
            "$(sha256sum "${CTFR_PATCH}" | cut -d' ' -f1)"
        printf 'base_driver_sha256=%s\n' "${BASE_DRIVER_SHA256}"
        "${VENV_DIR}/bin/python" -c \
            'import importlib.metadata as m; print("vllm_version=" + m.version("vllm"))'
        "${VENV_DIR}/bin/python" --version
        uv --version
        nvidia-smi --query-gpu=name,driver_version,memory.total \
            --format=csv,noheader
        sha256sum \
            "${WORK_DIR}/CTFR_DESIGN.md" \
            "${WORK_DIR}/CTFR_THREAT_MODEL.md" \
            "${WORK_DIR}/CTFR_EXPERIMENT_PROTOCOL.md" \
            "${WORK_DIR}/CTFR_DECISION_RULES.md" \
            "${WORK_DIR}/CTFR_RELATED_WORK_BOUNDARY.md" \
            "${WORK_DIR}/CTFR_PAPER_PLAN.md" \
            "${WORK_DIR}/CTFR_DEPLOYMENT_CONTENTS.md" \
            "${WORK_DIR}/avep_pcfr_mitigation.patch" \
            "${WORK_DIR}/avep_ctfr_mitigation.patch" \
            "${WORK_DIR}/prepare_ctfr_source.sh" \
            "${WORK_DIR}/run_factorial_confirmatory.sh" \
            "${WORK_DIR}/run_ctfr_mechanism.sh" \
            "${WORK_DIR}/analyze_factorial_confirmatory.py" \
            "${WORK_DIR}/analyze_ctfr_mechanism.py" \
            "${WORK_DIR}/test_analyze_ctfr_mechanism.py" \
            "${WORK_DIR}/tenant_probe.py" \
            "${WORK_DIR}/ctfr_gateway.py"
    } > "${temporary}"
    mv "${temporary}" "${output}"
}

run_local_self_tests() {
    (
        cd "${WORK_DIR}"
        "${VENV_DIR}/bin/python" -m unittest -v \
            test_analyze_ctfr_mechanism.py
    )
}

declare_protocol() {
    mkdir -p "${RESULT_ROOT}"
    if [[ -f "${RESULT_ROOT}/DECLARED_AT_UTC.txt" ]]; then
        (
            cd "${WORK_DIR}"
            sha256sum -c "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
        )
        (
            cd "${RESULT_ROOT}"
            sha256sum -c DECLARED_SCHEDULE.json.sha256
        )
        return
    fi
    if find "${RESULT_ROOT}" -mindepth 1 -maxdepth 1 -print -quit \
        | grep -q .; then
        printf 'Refusing to declare over existing CTFR data.\n' >&2
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
                "placebo_shared", "attack_shared", "attack_route",
                "placebo_ctfr-shadow", "attack_ctfr-shadow"
            ],
            performance_orders: [
                ["attack_shared", "attack_ctfr-shadow",
                    "placebo_ctfr-shadow", "placebo_shared"],
                ["attack_ctfr-shadow", "placebo_shared",
                    "attack_shared", "placebo_ctfr-shadow"],
                ["placebo_shared", "placebo_ctfr-shadow",
                    "attack_ctfr-shadow", "attack_shared"],
                ["placebo_ctfr-shadow", "attack_shared",
                    "placebo_shared", "attack_ctfr-shadow"],
                ["attack_shared", "attack_ctfr-shadow",
                    "placebo_ctfr-shadow", "placebo_shared"],
                ["attack_ctfr-shadow", "placebo_shared",
                    "attack_shared", "placebo_ctfr-shadow"],
                ["placebo_shared", "placebo_ctfr-shadow",
                    "attack_ctfr-shadow", "attack_shared"],
                ["placebo_ctfr-shadow", "attack_shared",
                    "placebo_shared", "attack_ctfr-shadow"]
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
            CTFR_DESIGN.md \
            CTFR_THREAT_MODEL.md \
            CTFR_EXPERIMENT_PROTOCOL.md \
            CTFR_DECISION_RULES.md \
            CTFR_RELATED_WORK_BOUNDARY.md \
            CTFR_PAPER_PLAN.md \
            CTFR_DEPLOYMENT_CONTENTS.md \
            avep_paper_instrumentation.patch \
            avep_causal_ablation.patch \
            avep_pcfr_mitigation.patch \
            avep_ctfr_mitigation.patch \
            prepare_ctfr_source.sh \
            run_factorial_confirmatory.sh \
            run_ctfr_mechanism.sh \
            analyze_factorial_confirmatory.py \
            analyze_ctfr_mechanism.py \
            test_analyze_ctfr_mechanism.py \
            tenant_probe.py \
            ctfr_gateway.py \
            ctfr_environment.txt \
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

run_arm() {
    local run_name="$1"
    local stage="$2"
    local block_id="$3"
    local arm="$4"
    local telemetry="$5"
    local detailed_metrics="$6"
    local return_token_ids="$7"
    local workload="${arm%%_*}"
    local mitigation_mode="${arm##*_}"
    if [[ "${workload}" != "attack" && "${workload}" != "placebo" ]]; then
        printf 'Invalid workload in arm %s.\n' "${arm}" >&2
        return 1
    fi
    if [[ "${mitigation_mode}" != "shared" \
        && "${mitigation_mode}" != "route" \
        && "${mitigation_mode}" != "ctfr-shadow" ]]; then
        printf 'Invalid feedback mode in arm %s.\n' "${arm}" >&2
        return 1
    fi
    local run_dir="${RESULT_ROOT}/${run_name}"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete run %s.\n' "${run_name}"
        return
    fi
    prepare_run_dir "${run_dir}"
    : > "${run_dir}/retirement_calls.jsonl"
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --arg run_name "${run_name}" \
        --arg stage "${stage}" \
        --arg block_id "${block_id}" \
        --arg arm "${arm}" \
        --arg workload "${workload}" \
        --arg mitigation_mode "${mitigation_mode}" \
        --argjson token_id "${TOKEN_ID}" \
        --argjson telemetry "${telemetry}" \
        --argjson detailed_metrics "${detailed_metrics}" \
        --arg created_at "$(date --iso-8601=ns)" \
        '{protocol_version: $protocol_version, run_name: $run_name,
          stage: $stage, block_id: $block_id, arm: $arm,
          workload: $workload, mitigation_mode: $mitigation_mode,
          poison_token_id: $token_id, telemetry: $telemetry,
          detailed_metrics: $detailed_metrics, created_at: $created_at}' \
        > "${run_dir}/metadata.json"
    export VLLM_AVEP_PCFR_MODE="${mitigation_mode}"
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
    snapshot_state "${run_dir}" pre_intervention
    local intervention_token=""
    if [[ "${workload}" == "attack" ]]; then
        intervention_token="${TOKEN_ID}"
    fi
    run_probe "${run_dir}" intervention attacker 4096 8 2 \
        "${intervention_token}" true
    snapshot_state "${run_dir}" intervention
    for window_number in $(seq 1 8); do
        window="$(printf '%02d' "${window_number}")"
        run_probe "${run_dir}" "post_${window}" victim 128 32 32 "" \
            "${return_token_ids}"
        snapshot_state "${run_dir}" "post_${window}"
    done
    stop_server
    cp "${WORK_DIR}/ctfr_environment.txt" "${run_dir}/environment.txt"
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

run_gate() {
    local arm
    for arm in placebo_shared attack_shared attack_route \
        placebo_ctfr-shadow attack_ctfr-shadow; do
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
    local -a orders=(
        "attack_shared attack_ctfr-shadow placebo_ctfr-shadow placebo_shared"
        "attack_ctfr-shadow placebo_shared attack_shared placebo_ctfr-shadow"
        "placebo_shared placebo_ctfr-shadow attack_ctfr-shadow attack_shared"
        "placebo_ctfr-shadow attack_shared placebo_shared attack_ctfr-shadow"
        "attack_shared attack_ctfr-shadow placebo_ctfr-shadow placebo_shared"
        "attack_ctfr-shadow placebo_shared attack_shared placebo_ctfr-shadow"
        "placebo_shared placebo_ctfr-shadow attack_ctfr-shadow attack_shared"
        "placebo_ctfr-shadow attack_shared placebo_shared attack_ctfr-shadow"
    )
    local block_number
    local block_id
    local arm
    for block_number in $(seq 1 8); do
        block_id="$(printf '%02d' "${block_number}")"
        for arm in ${orders[$((block_number - 1))]}; do
            run_arm "perf_block_${block_id}_${arm}" performance \
                "${block_id}" "${arm}" false false false
        done
    done
}

archive_results() {
    local -a members=(
        ctfr_mechanism_results_v1
        CTFR_DESIGN.md
        CTFR_THREAT_MODEL.md
        CTFR_EXPERIMENT_PROTOCOL.md
        CTFR_DECISION_RULES.md
        CTFR_RELATED_WORK_BOUNDARY.md
        CTFR_PAPER_PLAN.md
        CTFR_DEPLOYMENT_CONTENTS.md
        avep_paper_instrumentation.patch
        avep_causal_ablation.patch
        avep_pcfr_mitigation.patch
        avep_ctfr_mitigation.patch
        prepare_ctfr_source.sh
        run_factorial_confirmatory.sh
        run_ctfr_mechanism.sh
        analyze_factorial_confirmatory.py
        analyze_ctfr_mechanism.py
        test_analyze_ctfr_mechanism.py
        tenant_probe.py
        ctfr_gateway.py
        ctfr_environment.txt
    )
    tar -czf "${RESULT_ARCHIVE}.partial" -C "${WORK_DIR}" \
        "${members[@]}"
    mv "${RESULT_ARCHIVE}.partial" "${RESULT_ARCHIVE}"
    sha256sum "${RESULT_ARCHIVE}" > "${RESULT_ARCHIVE}.sha256"
    cat "${RESULT_ARCHIVE}.sha256"
}

mode="${1:-core}"
initialize_credentials
"${WORK_DIR}/prepare_ctfr_source.sh"
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
            --output "${RESULT_ROOT}/ctfr_assessment.json"
        archive_results
        ;;
    analyze)
        "${VENV_DIR}/bin/python" "${ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --require-performance \
            --output "${RESULT_ROOT}/ctfr_assessment.json"
        archive_results
        ;;
    core)
        run_gate
        run_performance
        "${VENV_DIR}/bin/python" "${ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --require-performance \
            --output "${RESULT_ROOT}/ctfr_assessment.json"
        archive_results
        ;;
    *)
        printf 'Usage: %s [gate|performance|analyze|core]\n' "$0" >&2
        exit 2
        ;;
esac
