#!/usr/bin/env bash
set -Eeuo pipefail

readonly BASE_DRIVER="/home/ubuntu/avep/run_factorial_confirmatory.sh"
readonly BASE_DRIVER_SHA256="ea733ab7264d5c55418e2f0819da09d757deea15708885b2e495a440912ff172"

actual_base_driver_sha256="$(sha256sum "${BASE_DRIVER}" | cut -d' ' -f1)"
if [[ "${actual_base_driver_sha256}" != "${BASE_DRIVER_SHA256}" ]]; then
    printf 'Base driver SHA-256 does not match the CTFR commitment.\n' >&2
    exit 1
fi

# Import the audited server, gateway, RPC, credential, and process lifecycle.
# shellcheck disable=SC1090
source <(
    sed \
        -e '/^mode="${1:-core}"$/,$d' \
        -e 's/avep-factorial-confirmatory-v1/avep-ctfr-full-study-v2/g' \
        -e 's/factorial_confirmatory_results_v1/ctfr_full_study_results_v2/g' \
        -e 's/\.avep_factorial_v1_tenant_credentials/\.avep_ctfr_full_v2_tenant_credentials/g' \
        -e 's/FACTORIAL_CONFIRMATORY_PROTOCOL\.md/CTFR_EXPERIMENT_PROTOCOL.md/g' \
        -e 's/FACTORIAL_CONFIRMATORY_DECISION_RULES\.md/CTFR_DECISION_RULES.md/g' \
        -e 's/run_factorial_confirmatory\.sh/run_ctfr_full_study.sh/g' \
        -e 's/analyze_factorial_confirmatory\.py/analyze_ctfr_full_study.py/g' \
        -e 's/test_analyze_factorial_confirmatory\.py/test_analyze_ctfr_full_study.py/g' \
        -e 's/tenant_gateway\.py/ctfr_gateway.py/g' \
        -e 's/factorial_environment\.txt/ctfr_full_environment_v2.txt/g' \
        -e 's/factorial-/ctfr-full-/g' \
        "${BASE_DRIVER}"
)

readonly SOURCE_SHA256="dcc2239dd80e8e4095a76d31a09ae96b5a4de603ca16850706760b4bfe6a2387"
readonly TARGET_MODEL_REVISION="1cfa9a7208912126459214e8b04321603b3df60c"
readonly DRAFT_MODEL_REVISION="b74e3a329c4d963783143b1e970d95b002be72bd"
readonly FEATURE_CONTRACT_VERSION="logit-max-draft-probability-v1"
readonly DUAL_PROBE="${WORK_DIR}/ctfr_dual_probe.py"
readonly RESOURCE_SAMPLER="${WORK_DIR}/ctfr_resource_sampler.sh"
readonly CORPUS="${WORK_DIR}/ctfr_frozen_corpus.json"
readonly MANIFEST_GENERATOR="${WORK_DIR}/generate_ctfr_manifests.py"
readonly HYPERPARAMETERS="${WORK_DIR}/CTFR_FROZEN_HYPERPARAMETERS.json"
readonly SAMPLING_POLICY="${WORK_DIR}/CTFR_SAMPLING_POLICY.json"
readonly MANIFEST_DIR="${WORK_DIR}/ctfr_manifests_v2"
readonly BASELINE_STATE="${WORK_DIR}/ctfr_baseline_committed_state_v2.json"
readonly BASELINE_PILOT_DIR="${WORK_DIR}/ctfr_baseline_pilot_v2"
readonly FULL_ANALYZER="${WORK_DIR}/analyze_ctfr_full_study.py"
readonly FULL_TEST="${WORK_DIR}/test_analyze_ctfr_full_study.py"
readonly DEPLOYMENT_FILELIST="${WORK_DIR}/CTFR_DEPLOYMENT_FILELIST.txt"
readonly MAX_STUDY_SECONDS="${MAX_STUDY_SECONDS:-21600}"
readonly STUDY_STARTED_SECONDS="$(date +%s)"

# The frozen PCFR/CTFR Triton kernels dispatch on module-level integer constants.
export TRITON_ALLOW_NON_CONSTEXPR_GLOBALS=1

if [[ "${CTFR_STUDY_WATCHDOG_CHILD:-0}" != "1" ]]; then
    export CTFR_STUDY_WATCHDOG_CHILD=1
    exec timeout --signal=TERM --kill-after=120s \
        "${MAX_STUDY_SECONDS}s" "$0" "$@"
fi

resource_sampler_pid=""
resource_sampler_sentinel=""

study_budget_check() {
    local elapsed=$(( $(date +%s) - STUDY_STARTED_SECONDS ))
    if ((elapsed > MAX_STUDY_SECONDS)); then
        printf 'Study wall-time budget exceeded: %s > %s seconds.\n' \
            "${elapsed}" "${MAX_STUDY_SECONDS}" >&2
        return 1
    fi
}

require_empty_or_complete_block() {
    local present=0
    local complete=0
    local run_name
    for run_name in "$@"; do
        if [[ -e "${RESULT_ROOT}/${run_name}" ]]; then
            present=$((present + 1))
            if [[ -f "${RESULT_ROOT}/${run_name}/COMPLETE" ]]; then
                complete=$((complete + 1))
            fi
        fi
    done
    if ((present == 0)); then
        return 0
    fi
    if ((present == $# && complete == $#)); then
        return 10
    fi
    printf '%s\n' \
        'Refusing to resume a partially recorded temporal block.' \
        'Quarantine this result root and redeclare the full study.' >&2
    return 1
}

stop_resource_sampler() {
    if [[ -n "${resource_sampler_sentinel}" ]]; then
        rm -f -- "${resource_sampler_sentinel}"
    fi
    if [[ -n "${resource_sampler_pid}" ]]; then
        for _ in $(seq 1 20); do
            kill -0 "${resource_sampler_pid}" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "${resource_sampler_pid}" 2>/dev/null; then
            kill -TERM "${resource_sampler_pid}" 2>/dev/null || true
        fi
        wait "${resource_sampler_pid}" 2>/dev/null || true
    fi
    resource_sampler_pid=""
    resource_sampler_sentinel=""
}

cleanup() {
    local status="$?"
    stop_resource_sampler || true
    stop_server || true
    if ((status != 0)) && [[ -d "${RESULT_ROOT}" ]]; then
        printf 'exit_status=%s\ntimestamp=%s\n' \
            "${status}" "$(date --iso-8601=ns)" \
            > "${RESULT_ROOT}/CTFR_FULL_STUDY_FAILED.txt"
        local -a members=(ctfr_full_study_results_v2)
        local member
        while IFS= read -r member; do
            [[ -e "${WORK_DIR}/${member}" ]] && members+=("${member}")
        done < "${DEPLOYMENT_FILELIST}"
        for member in \
            ctfr_manifests_v2 \
            ctfr_baseline_pilot_v2 \
            ctfr_baseline_committed_state_v2.json \
            ctfr_full_environment_v2.txt; do
            [[ -e "${WORK_DIR}/${member}" ]] && members+=("${member}")
        done
        tar -czf "${PARTIAL_ARCHIVE}.partial" -C "${WORK_DIR}" \
            "${members[@]}" 2>/dev/null || true
        if [[ -f "${PARTIAL_ARCHIVE}.partial" ]]; then
            mv "${PARTIAL_ARCHIVE}.partial" "${PARTIAL_ARCHIVE}"
            sha256sum "${PARTIAL_ARCHIVE}" \
                > "${PARTIAL_ARCHIVE}.sha256"
        fi
    fi
    return "${status}"
}
trap cleanup EXIT INT TERM

manifest_sha256() {
    "${VENV_DIR}/bin/python" -c '
import hashlib
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    value = json.load(source)
encoded = json.dumps(
    value,
    allow_nan=False,
    ensure_ascii=False,
    separators=(",", ":"),
    sort_keys=True,
).encode()
print(hashlib.sha256(encoded).hexdigest())
' "$1"
}

manifest_principal_counts() {
    jq -c '
        reduce .entries[] as $entry
            ({attacker: 0, victim: 0};
             .[$entry.principal] += 1)
    ' "$1"
}

emit_baseline_pilot_provenance() {
    (
        cd "${BASELINE_PILOT_DIR}"
        while IFS= read -r -d '' path; do
            sha256sum "${path}"
        done < <(
            find . -type f ! -name PROVENANCE.sha256 -print0 | sort -z
        )
    )
}

verify_baseline_pilot_provenance() {
    local temporary="${WORK_DIR}/ctfr_baseline_provenance_verify.partial"
    [[ -f "${BASELINE_PILOT_DIR}/COMPLETE" ]] || {
        printf 'Baseline pilot has no COMPLETE marker.\n' >&2
        return 1
    }
    [[ -f "${BASELINE_PILOT_DIR}/PROVENANCE.sha256" ]] || {
        printf 'Baseline pilot has no provenance manifest.\n' >&2
        return 1
    }
    emit_baseline_pilot_provenance > "${temporary}"
    if ! cmp -s "${temporary}" \
        "${BASELINE_PILOT_DIR}/PROVENANCE.sha256"; then
        rm -f -- "${temporary}"
        printf 'Baseline pilot provenance does not match every file.\n' >&2
        return 1
    fi
    rm -f -- "${temporary}"
}

write_baseline_pilot_provenance() {
    local temporary="${WORK_DIR}/ctfr_baseline_pilot_provenance.partial"
    date --iso-8601=ns > "${BASELINE_PILOT_DIR}/COMPLETE"
    emit_baseline_pilot_provenance > "${temporary}"
    mv "${temporary}" "${BASELINE_PILOT_DIR}/PROVENANCE.sha256"
    verify_baseline_pilot_provenance
}

configure_ctfr_environment() {
    export VLLM_AVEP_EVAL_METRICS=1
    export VLLM_AVEP_CTFR_MIN_OBSERVATIONS
    export VLLM_AVEP_CTFR_DELTA_CLIP
    export VLLM_AVEP_CTFR_MIN_COSINE
    export VLLM_AVEP_CTFR_MAX_COMMIT_NORM
    export VLLM_AVEP_CTFR_MAX_PROBABILITY_SHIFT
    export VLLM_AVEP_CTFR_BUCKET_CAPACITY
    VLLM_AVEP_CTFR_MIN_OBSERVATIONS="$(jq -er '.min_observations' "${HYPERPARAMETERS}")"
    VLLM_AVEP_CTFR_DELTA_CLIP="$(jq -er '.delta_clip' "${HYPERPARAMETERS}")"
    VLLM_AVEP_CTFR_MIN_COSINE="$(jq -er '.min_cosine' "${HYPERPARAMETERS}")"
    VLLM_AVEP_CTFR_MAX_COMMIT_NORM="$(jq -er '.max_commit_norm' "${HYPERPARAMETERS}")"
    VLLM_AVEP_CTFR_MAX_PROBABILITY_SHIFT="$(jq -er '.max_probability_shift' "${HYPERPARAMETERS}")"
    VLLM_AVEP_CTFR_BUCKET_CAPACITY="$(jq -er '.bucket_capacity' "${HYPERPARAMETERS}")"
}

runtime_preflight() {
    local command_name
    for command_name in awk cmp curl cut find getconf git jq ninja nvidia-smi \
        openssl ps setsid sha256sum sort ss stat tar timeout uv; do
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
        "${GATEWAY}" \
        "${DUAL_PROBE}" \
        "${WORK_DIR}/test_ctfr_dual_probe.py" \
        "${RESOURCE_SAMPLER}" \
        "${CORPUS}" \
        "${MANIFEST_GENERATOR}" \
        "${WORK_DIR}/CTFR_MANIFEST_SCHEMA.md" \
        "${WORK_DIR}/test_generate_ctfr_manifests.py" \
        "${WORK_DIR}/extract_ctfr_baseline.py" \
        "${WORK_DIR}/test_extract_ctfr_baseline.py" \
        "${FULL_ANALYZER}" \
        "${FULL_TEST}" \
        "${DEPLOYMENT_FILELIST}" \
        "${HYPERPARAMETERS}" \
        "${SAMPLING_POLICY}" \
        "${RULES_SOURCE}" \
        "${WORK_DIR}/CTFR_EXPERIMENT_PROTOCOL.md" \
        "${WORK_DIR}/prepare_ctfr_source.sh" \
        "${WORK_DIR}/avep_ctfr_experiment_support.patch" \
        "${WORK_DIR}/avep_ctfr_triton_compat.patch"; do
        [[ -f "${required_file}" ]] || {
            printf 'Required input is unavailable: %s\n' \
                "${required_file}" >&2
            return 1
        }
    done
    "${VENV_DIR}/bin/python" -c \
        'from triton import knobs; assert knobs.compilation.allow_non_constexpr_globals is True' \
        || {
            printf '%s\n' \
                'Triton non-constexpr global compatibility is unavailable.' >&2
            return 1
        }
    jq -n --arg sample_label preflight \
        '{label: $sample_label}' >/dev/null
    jq -e '
        .schema == "ctfr-hyperparameters-v1"
        and (.min_observations | type) == "number"
        and (.min_observations > 0)
        and (.min_cosine >= -1 and .min_cosine <= 1)
        and (.delta_clip > 0)
        and (.max_commit_norm > 0)
        and (.max_probability_shift > 0)
        and (.bucket_capacity > 0)
        and (.fixed_shadow_tensor_bound_bytes > 0)
        and .fixed_shadow_tensor_scope ==
          "Persistent shadow-state tensors only; excludes transient retirement and validation workspace."
    ' "${HYPERPARAMETERS}" >/dev/null
    jq -e '
        .schema == "ctfr-sampling-policy-v1"
        and .api == "v1/completions"
        and .feature_contract_version == "logit-max-draft-probability-v1"
        and .ignore_eos == true
        and .return_token_ids == true
        and .stream == false
        and .temperature == 0
    ' "${SAMPLING_POLICY}" >/dev/null
    ps -e -o pgid=,rss=,%cpu= >/dev/null || {
        printf 'ps cannot expose the process-group resource columns.\n' >&2
        return 1
    }
    if [[ -n "$(ss -H -ltn 'sport = :8000')" \
        || -n "$(ss -H -ltn 'sport = :8001')" ]]; then
        printf 'Port 8000 or 8001 is already occupied.\n' >&2
        return 1
    fi
}

require_manifests() {
    local manifest
    for manifest in \
        compile_warmup.json \
        baseline_adaptation.json \
        baseline_evaluation.json \
        shifted_adaptation.json \
        shifted_evaluation.json \
        stationary_adaptation.json \
        e1_one_identity.json \
        e2_disagreement.json \
        e3_two_credentials.json; do
        [[ -f "${MANIFEST_DIR}/${manifest}" ]] || {
            printf 'Missing frozen workload manifest: %s\n' "${manifest}" >&2
            return 1
        }
        jq -e '.schema == "ctfr-workload-manifest-v1"' \
            "${MANIFEST_DIR}/${manifest}" >/dev/null
    done
}

write_environment_manifest() {
    local output="${WORK_DIR}/ctfr_full_environment_v2.txt"
    local temporary="${output}.partial"
    {
        printf 'vllm_sha=%s\n' "$(git -C "${REPO_DIR}" rev-parse HEAD)"
        printf 'source_stack_sha256=%s\n' "${SOURCE_SHA256}"
        printf 'base_driver_sha256=%s\n' "${BASE_DRIVER_SHA256}"
        printf 'target_model_revision=%s\n' "${TARGET_MODEL_REVISION}"
        printf 'draft_model_revision=%s\n' "${DRAFT_MODEL_REVISION}"
        printf 'triton_allow_non_constexpr_globals=%s\n' \
            "${TRITON_ALLOW_NON_CONSTEXPR_GLOBALS}"
        "${VENV_DIR}/bin/python" -c \
            'import importlib.metadata as m; print("vllm_version=" + m.version("vllm"))'
        "${VENV_DIR}/bin/python" -c \
            'import triton; print("triton_version=" + triton.__version__)'
        "${VENV_DIR}/bin/python" --version
        uv --version
        nvidia-smi --query-gpu=name,driver_version,memory.total \
            --format=csv,noheader
        sha256sum \
            "${HYPERPARAMETERS}" \
            "${SAMPLING_POLICY}" \
            "${WORK_DIR}/avep_ctfr_experiment_support.patch" \
            "${WORK_DIR}/avep_ctfr_triton_compat.patch" \
            "${WORK_DIR}/prepare_ctfr_source.sh" \
            "${WORK_DIR}/run_ctfr_full_study.sh" \
            "${GATEWAY}" \
            "${DUAL_PROBE}" \
            "${RESOURCE_SAMPLER}"
    } > "${temporary}"
    mv "${temporary}" "${output}"
}

run_full_self_tests() {
    local -a tests=(
        test_analyze_ctfr_mechanism.py
        test_extract_ctfr_baseline.py
        test_ctfr_dual_probe.py
    )
    [[ ! -f "${FULL_TEST}" ]] || tests+=(test_analyze_ctfr_full_study.py)
    [[ ! -f "${WORK_DIR}/test_generate_ctfr_manifests.py" ]] \
        || tests+=(test_generate_ctfr_manifests.py)
    (
        cd "${WORK_DIR}"
        "${VENV_DIR}/bin/python" -m unittest -v "${tests[@]}"
    )
}

start_resource_sampler() {
    local run_dir="$1"
    resource_sampler_sentinel="${run_dir}/.resource_sampler_active"
    : > "${resource_sampler_sentinel}"
    bash "${RESOURCE_SAMPLER}" \
        "${server_pgid}" \
        "${gateway_pgid}" \
        "${resource_sampler_sentinel}" \
        "${run_dir}/resource_samples.jsonl" \
        1.0 &
    resource_sampler_pid="$!"
}

run_dual_probe() {
    local run_dir="$1"
    local output_name="$2"
    local phase="$3"
    local manifest="$4"
    local spoof_identity="${5:-false}"
    local cmd=(
        "${VENV_DIR}/bin/python"
        "${DUAL_PROBE}"
        --phase "${phase}"
        --run-id "$(basename "${run_dir}")"
        --gateway-instance-id "${gateway_instance_id}"
        --upstream-marker "${server_marker}"
        --manifest "${manifest}"
        --credentials "${CREDENTIALS_FILE}"
        --base-url http://127.0.0.1:8001/v1
        --concurrency 32
        --return-token-ids
        --output "${run_dir}/${output_name}.json.partial"
    )
    [[ "${spoof_identity}" != "true" ]] || cmd+=(--spoof-identity-headers)
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
        local running_series
        local waiting
        local waiting_series
        read -r running running_series <<< "$(
            awk '/^vllm:num_requests_running([{ ]|$)/ {sum += $NF}
                 /^vllm:num_requests_running([{ ]|$)/ {matches += 1}
                 END {print sum + 0, matches + 0}' "${metrics_file}"
        )"
        read -r waiting waiting_series <<< "$(
            awk '/^vllm:num_requests_waiting([{ ]|$)/ {sum += $NF}
                 /^vllm:num_requests_waiting([{ ]|$)/ {matches += 1}
                 END {print sum + 0, matches + 0}' "${metrics_file}"
        )"
        if ((running_series < 1 || waiting_series < 1)); then
            printf 'Required queue gauges are absent from /metrics.\n' >&2
            return 1
        fi
        jq -cn \
            --arg sample_label "${label}" \
            --arg sampled_at "$(date --iso-8601=ns)" \
            --argjson running "${running}" \
            --argjson waiting "${waiting}" \
            --argjson running_series "${running_series}" \
            --argjson waiting_series "${waiting_series}" \
            '{label: $sample_label, sampled_at: $sampled_at,
              running: $running, waiting: $waiting,
              running_series: $running_series,
              waiting_series: $waiting_series}' \
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
    printf 'Queue did not reach two consecutive zero samples.\n' >&2
    return 1
}

reset_eval_metrics() {
    rpc "$1" '{"method":"avep_reset_acceptance_estimator_eval_metrics"}'
}

get_eval_metrics() {
    rpc "$1" '{"method":"avep_get_acceptance_estimator_eval_metrics"}'
}

reset_estimator_named() {
    local run_dir="$1"
    local label="$2"
    rpc "${run_dir}/estimator_reset_${label}.json" \
        '{"method":"avep_reset_acceptance_estimator"}'
}

load_baseline() {
    local output="$1"
    local serialized
    local payload
    serialized="$(jq -c '{slope: .slope, intercepts: .intercepts}' \
        "${BASELINE_STATE}")"
    payload="$(jq -cn --arg state "${serialized}" \
        '{method: "avep_load_acceptance_estimator_state", args: [$state]}')"
    rpc "${output}" "${payload}"
}

invoke_barrier() {
    local run_dir="$1"
    local arm="$2"
    local raw="${run_dir}/barrier_raw.json"
    local method=""
    case "${arm}" in
        ctfr-full)
            method="avep_retire_ctfr"
            ;;
        tenant-local)
            method="avep_refit_tenant_local"
            ;;
    esac
    if [[ -z "${method}" ]]; then
        jq -n \
            '{called: false, method: null, response: null}' \
            > "${run_dir}/barrier_response.json"
        return
    fi
    rpc "${raw}" "$(jq -cn --arg method "${method}" '{method: $method}')"
    jq -n \
        --arg method "${method}" \
        --slurpfile response "${raw}" \
        '{called: true, method: $method, response: $response[0]}' \
        > "${run_dir}/barrier_response.json"
}

write_run_metadata() {
    local run_dir="$1"
    local stage="$2"
    local block_id="$3"
    local arm="$4"
    local confirmatory="$5"
    local adaptation_manifest="$6"
    local evaluation_manifest="$7"
    local ownership="$8"
    local telemetry_enabled="$9"
    local baseline_sha
    local credential_control
    local scenario
    local run_id
    local measurement_window="whole-run"
    local adaptation_updates_enabled=true
    local evaluation_metrics_enabled=true
    run_id="$(basename "${run_dir}")"
    case "${stage}" in
        stage-d|stage-d-gate)
            scenario="benign-adaptation"
            ;;
        stage-e1)
            scenario="sybil-single"
            ;;
        stage-e2)
            scenario="sybil-disagree"
            ;;
        stage-e3)
            scenario="sybil-quorum-capture"
            ;;
        overhead)
            scenario="stationary-overhead"
            measurement_window="adaptation-only"
            evaluation_metrics_enabled=false
            ;;
        *)
            printf 'Unknown CTFR study stage: %s\n' "${stage}" >&2
            return 1
            ;;
    esac
    baseline_sha="$(jq -er '.coefficient_sha256' "${BASELINE_STATE}")"
    if [[ "${arm}" == "frozen" \
        || ("${stage}" == "overhead" && "${arm}" == "shared") ]]; then
        adaptation_updates_enabled=false
    fi
    case "${ownership}" in
        independent)
            credential_control='{"attacker":"experiment-benign","victim":"experiment-benign"}'
            ;;
        attacker-only)
            credential_control='{"attacker":"attacker","victim":"absent"}'
            ;;
        attacker-plus-benign)
            credential_control='{"attacker":"attacker","victim":"experiment-benign"}'
            ;;
        attacker-controls-both)
            credential_control='{"attacker":"attacker","victim":"attacker"}'
            ;;
        *)
            printf 'Unknown principal ownership declaration: %s\n' \
                "${ownership}" >&2
            return 1
            ;;
    esac
    jq -n \
        --arg protocol_version "${PROTOCOL_VERSION}" \
        --arg run_id "${run_id}" \
        --arg stage "${stage}" \
        --arg scenario "${scenario}" \
        --arg block_id "${block_id}" \
        --arg arm "${arm}" \
        --arg source_sha256 "${SOURCE_SHA256}" \
        --arg target_model_revision "${TARGET_MODEL_REVISION}" \
        --arg draft_model_revision "${DRAFT_MODEL_REVISION}" \
        --arg sampling_policy_sha256 "$(manifest_sha256 "${SAMPLING_POLICY}")" \
        --arg feature_contract_version "${FEATURE_CONTRACT_VERSION}" \
        --arg process_uuid "${server_marker}" \
        --arg created_at "$(date --iso-8601=ns)" \
        --arg baseline_sha256 "${baseline_sha}" \
        --argjson shadow_memory_bound_bytes \
            "$(jq -er '.fixed_shadow_tensor_bound_bytes' "${HYPERPARAMETERS}")" \
        --arg shadow_memory_bound_scope \
            "$(jq -er '.fixed_shadow_tensor_scope' "${HYPERPARAMETERS}")" \
        --arg adaptation_manifest_sha256 "$(manifest_sha256 "${adaptation_manifest}")" \
        --arg evaluation_manifest_sha256 "$(manifest_sha256 "${evaluation_manifest}")" \
        --argjson confirmatory "${confirmatory}" \
        --argjson observation_budget_by_principal \
            "$(manifest_principal_counts "${adaptation_manifest}")" \
        --argjson evaluation_budget_by_principal \
            "$(manifest_principal_counts "${evaluation_manifest}")" \
        --arg principal_ownership "${ownership}" \
        --arg measurement_window "${measurement_window}" \
        --argjson adaptation_updates_enabled \
            "${adaptation_updates_enabled}" \
        --argjson evaluation_metrics_enabled \
            "${evaluation_metrics_enabled}" \
        --argjson telemetry_enabled "${telemetry_enabled}" \
        --argjson credential_control_by_principal "${credential_control}" \
        '{protocol_version: $protocol_version, run_id: $run_id,
          stage: $stage, scenario: $scenario,
          block_id: $block_id, arm: $arm,
          source_sha256: $source_sha256,
          target_model_revision: $target_model_revision,
          draft_model_revision: $draft_model_revision,
          sampling_policy_sha256: $sampling_policy_sha256,
          feature_contract_version: $feature_contract_version,
          process_uuid: $process_uuid, created_at: $created_at,
          confirmatory: $confirmatory, fresh_process: true,
          baseline_sha256: $baseline_sha256,
          shadow_memory_bound_bytes: $shadow_memory_bound_bytes,
          shadow_memory_bound_scope: $shadow_memory_bound_scope,
          adaptation_manifest_sha256: $adaptation_manifest_sha256,
          evaluation_manifest_sha256: $evaluation_manifest_sha256,
          observation_budget_by_principal: $observation_budget_by_principal,
          evaluation_budget_by_principal: $evaluation_budget_by_principal,
          resource_measurement_window: $measurement_window,
          adaptation_updates_enabled: $adaptation_updates_enabled,
          evaluation_metrics_enabled: $evaluation_metrics_enabled,
          binding_telemetry_enabled: $telemetry_enabled,
          principal_ownership: $principal_ownership,
          credential_control_by_principal:
            $credential_control_by_principal}' \
        > "${run_dir}/metadata.json"
    jq \
        --arg run_id "${run_id}" \
        --arg process_uuid "${server_marker}" \
        '. + {run_id: $run_id, process_uuid: $process_uuid}' \
        "${run_dir}/tenant_topology.json" \
        > "${run_dir}/tenant_topology.json.partial"
    mv "${run_dir}/tenant_topology.json.partial" \
        "${run_dir}/tenant_topology.json"
}

record_barrier_evidence() {
    local run_dir="$1"
    local called_after_ns="$2"
    local completed_ns="$3"
    local admitted
    local completed
    admitted="$(jq -er '.summary.requests' "${run_dir}/adaptation.json")"
    completed="$(jq -er '.summary.successful' "${run_dir}/adaptation.json")"
    jq \
        --argjson called_after_ns "${called_after_ns}" \
        --argjson completed_ns "${completed_ns}" \
        --argjson admitted_requests "${admitted}" \
        --argjson completed_requests "${completed}" \
        '.barrier_evidence = {
            queue_drained: true,
            admitted_requests: $admitted_requests,
            completed_requests: $completed_requests,
            active_requests: 0,
            called_after_ns: $called_after_ns,
            completed_ns: $completed_ns
        }' "${run_dir}/metadata.json" \
        > "${run_dir}/metadata.json.partial"
    mv "${run_dir}/metadata.json.partial" "${run_dir}/metadata.json"
}

run_compile_warmup() {
    local run_dir="$1"
    reset_estimator_named "${run_dir}" compile
    set_updates "${run_dir}" compile_warmup true
    reset_eval_metrics "${run_dir}/eval_reset_compile.json"
    run_dual_probe \
        "${run_dir}" \
        compile_warmup \
        compile_warmup \
        "${MANIFEST_DIR}/compile_warmup.json" \
        true
    wait_for_drain "${run_dir}" compile_warmup
    snapshot_state "${run_dir}" compile_warmup
}

run_adaptation_arm() {
    local run_name="$1"
    local stage="$2"
    local block_id="$3"
    local arm="$4"
    local confirmatory="$5"
    local adaptation_manifest="$6"
    local evaluation_manifest="$7"
    local ownership="$8"
    local telemetry="${9:-false}"
    local mode="${arm}"
    [[ "${arm}" != "frozen" ]] || mode="shared"
    [[ "${arm}" != "ctfr-full-no-retire" ]] || mode="ctfr-full"
    case "${mode}" in
        shared|ctfr-shadow|ctfr-full|tenant-local) ;;
        *)
            printf 'Unsupported CTFR arm: %s\n' "${arm}" >&2
            return 1
            ;;
    esac
    study_budget_check
    local run_dir="${RESULT_ROOT}/${run_name}"
    if [[ -f "${run_dir}/COMPLETE" ]]; then
        printf 'Skipping complete run %s.\n' "${run_name}"
        return
    fi
    prepare_run_dir "${run_dir}"
    : > "${run_dir}/drain_evidence.jsonl"
    export VLLM_AVEP_PCFR_MODE="${mode}"
    configure_ctfr_environment
    if [[ "${stage}" == "overhead" ]]; then
        export VLLM_AVEP_EVAL_METRICS=0
    fi
    start_server "${run_dir}" "${telemetry}" true
    if [[ "${stage}" != "overhead" ]]; then
        start_resource_sampler "${run_dir}"
    fi
    write_run_metadata \
        "${run_dir}" "${stage}" "${block_id}" "${arm}" \
        "${confirmatory}" "${adaptation_manifest}" \
        "${evaluation_manifest}" "${ownership}" "${telemetry}"
    snapshot_state "${run_dir}" server_ready
    run_compile_warmup "${run_dir}"

    reset_estimator_named "${run_dir}" experiment
    load_baseline "${run_dir}/baseline_load.json"
    set_updates "${run_dir}" baseline_evaluation false
    reset_eval_metrics "${run_dir}/eval_reset_baseline.json"
    run_dual_probe \
        "${run_dir}" \
        baseline_evaluation \
        baseline_evaluation \
        "${MANIFEST_DIR}/baseline_evaluation.json"
    wait_for_drain "${run_dir}" baseline_evaluation
    get_eval_metrics "${run_dir}/baseline_eval_metrics.json"
    snapshot_state "${run_dir}" before

    reset_eval_metrics "${run_dir}/eval_reset_adaptation.json"
    if [[ "${arm}" == "frozen" \
        || ("${stage}" == "overhead" && "${arm}" == "shared") ]]; then
        set_updates "${run_dir}" adaptation false
    else
        set_updates "${run_dir}" adaptation true
    fi
    if [[ "${stage}" == "overhead" ]]; then
        start_resource_sampler "${run_dir}"
    fi
    run_dual_probe \
        "${run_dir}" adaptation adaptation "${adaptation_manifest}"
    if [[ "${stage}" == "overhead" ]]; then
        stop_resource_sampler
    fi
    wait_for_drain "${run_dir}" adaptation
    snapshot_state "${run_dir}" accumulated
    local called_after_ns
    local completed_ns
    called_after_ns="$(date +%s%N)"
    invoke_barrier "${run_dir}" "${arm}"
    completed_ns="$(date +%s%N)"
    record_barrier_evidence \
        "${run_dir}" "${called_after_ns}" "${completed_ns}"

    set_updates "${run_dir}" evaluation false
    snapshot_state "${run_dir}" after_barrier
    reset_eval_metrics "${run_dir}/eval_reset_evaluation.json"
    run_dual_probe \
        "${run_dir}" evaluation evaluation "${evaluation_manifest}"
    wait_for_drain "${run_dir}" evaluation
    get_eval_metrics "${run_dir}/eval_metrics.json"
    snapshot_state "${run_dir}" post_evaluation
    stop_resource_sampler
    stop_server
    cp "${WORK_DIR}/ctfr_full_environment_v2.txt" \
        "${run_dir}/environment.txt"
    date --iso-8601=ns > "${run_dir}/COMPLETE"
}

run_baseline_pilot() {
    require_manifests
    if [[ -f "${BASELINE_STATE}" ]]; then
        verify_baseline_pilot_provenance
        printf 'Baseline already exists: %s\n' "${BASELINE_STATE}"
        return
    fi
    if [[ -d "${BASELINE_PILOT_DIR}" ]]; then
        printf 'Refusing to overwrite an incomplete baseline pilot.\n' >&2
        return 1
    fi
    mkdir -p "${BASELINE_PILOT_DIR}"
    : > "${BASELINE_PILOT_DIR}/drain_evidence.jsonl"
    export VLLM_AVEP_PCFR_MODE=shared
    configure_ctfr_environment
    start_server "${BASELINE_PILOT_DIR}" true true
    start_resource_sampler "${BASELINE_PILOT_DIR}"
    run_compile_warmup "${BASELINE_PILOT_DIR}"
    reset_estimator_named "${BASELINE_PILOT_DIR}" baseline_training
    set_updates "${BASELINE_PILOT_DIR}" baseline_training true
    run_dual_probe \
        "${BASELINE_PILOT_DIR}" \
        baseline_adaptation \
        baseline_adaptation \
        "${MANIFEST_DIR}/baseline_adaptation.json"
    wait_for_drain "${BASELINE_PILOT_DIR}" baseline_training
    snapshot_state "${BASELINE_PILOT_DIR}" learned
    "${VENV_DIR}/bin/python" "${WORK_DIR}/extract_ctfr_baseline.py" \
        --state "${BASELINE_PILOT_DIR}/state_learned.json" \
        --output "${BASELINE_STATE}.partial"
    mv "${BASELINE_STATE}.partial" "${BASELINE_STATE}"
    stop_resource_sampler
    stop_server
    write_baseline_pilot_provenance
    sha256sum "${BASELINE_STATE}"
}

generate_manifests() {
    if [[ -e "${MANIFEST_DIR}" ]]; then
        "${VENV_DIR}/bin/python" "${MANIFEST_GENERATOR}" \
            --corpus "${CORPUS}" \
            --output-dir "${MANIFEST_DIR}" \
            --check
        return
    fi
    "${VENV_DIR}/bin/python" "${MANIFEST_GENERATOR}" \
        --corpus "${CORPUS}" \
        --output-dir "${MANIFEST_DIR}"
    "${VENV_DIR}/bin/python" "${MANIFEST_GENERATOR}" \
        --corpus "${CORPUS}" \
        --output-dir "${MANIFEST_DIR}" \
        --check
}

declare_protocol() {
    require_manifests
    [[ -f "${BASELINE_STATE}" ]] || {
        printf 'Run baseline mode before declaring confirmation.\n' >&2
        return 1
    }
    verify_baseline_pilot_provenance
    mkdir -p "${RESULT_ROOT}"
    if [[ -f "${RESULT_ROOT}/DECLARED_AT_UTC.txt" ]]; then
        (
            cd "${WORK_DIR}"
            sha256sum -c "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
        )
        (
            cd "${RESULT_ROOT}"
            sha256sum -c \
                DECLARED_SCHEDULE.json.sha256 \
                DECLARED_DECISION_RULES.md.sha256 \
                DECLARED_PRINCIPALS.json.sha256
        )
        jq -e \
            --arg attacker "$(secret_sha256 "${ATTACKER_API_KEY}")" \
            --arg victim "$(secret_sha256 "${VICTIM_API_KEY}")" \
            --arg upstream "$(secret_sha256 "${UPSTREAM_API_KEY}")" \
            '. == {attacker: $attacker, victim: $victim,
                   upstream: $upstream}' \
            "${RESULT_ROOT}/DECLARED_PRINCIPALS.json" >/dev/null
        return
    fi
    if find "${RESULT_ROOT}" -mindepth 1 -maxdepth 1 -print -quit \
        | grep -q .; then
        printf 'Refusing to declare over existing CTFR full-study data.\n' >&2
        return 1
    fi
    cp "${RULES_SOURCE}" "${RESULT_ROOT}/DECLARED_DECISION_RULES.md"
    jq -n \
        '{stage_d_blocks: 8,
          stage_d_arms: ["shared", "frozen", "tenant-local",
            "ctfr-shadow", "ctfr-full"],
          stage_d_order_by_block: {
            "01": ["shared", "frozen", "tenant-local", "ctfr-shadow",
              "ctfr-full"],
            "02": ["frozen", "tenant-local", "ctfr-shadow", "ctfr-full",
              "shared"],
            "03": ["tenant-local", "ctfr-shadow", "ctfr-full", "shared",
              "frozen"],
            "04": ["ctfr-shadow", "ctfr-full", "shared", "frozen",
              "tenant-local"],
            "05": ["ctfr-full", "shared", "frozen", "tenant-local",
              "ctfr-shadow"],
            "06": ["ctfr-full", "ctfr-shadow", "tenant-local", "frozen",
              "shared"],
            "07": ["shared", "ctfr-full", "ctfr-shadow", "tenant-local",
              "frozen"],
            "08": ["frozen", "shared", "ctfr-full", "ctfr-shadow",
              "tenant-local"]},
          stage_e: ["e1-one-identity", "e2-disagreement",
            "e3-two-credentials"],
          stage_e_initial: "e1-one-identity",
          stage_e_order_by_block: {
            "01": ["e2-disagreement", "e3-two-credentials"],
            "02": ["e2-disagreement", "e3-two-credentials"],
            "03": ["e2-disagreement", "e3-two-credentials"],
            "04": ["e2-disagreement", "e3-two-credentials"],
            "05": ["e2-disagreement", "e3-two-credentials"],
            "06": ["e2-disagreement", "e3-two-credentials"],
            "07": ["e2-disagreement", "e3-two-credentials"],
            "08": ["e2-disagreement", "e3-two-credentials"]},
          overhead_blocks: 8,
          overhead_arms: ["shared", "ctfr-full-no-retire"],
          overhead_order_by_block: {
            "01": ["shared", "ctfr-full-no-retire"],
            "02": ["ctfr-full-no-retire", "shared"],
            "03": ["shared", "ctfr-full-no-retire"],
            "04": ["ctfr-full-no-retire", "shared"],
            "05": ["shared", "ctfr-full-no-retire"],
            "06": ["ctfr-full-no-retire", "shared"],
            "07": ["shared", "ctfr-full-no-retire"],
            "08": ["ctfr-full-no-retire", "shared"]},
          fixed_shadow_tensor_bound_bytes: 1024,
          fresh_process_per_arm: true,
          barrier_attempts_per_run: 1,
          bootstrap_seed: 20260920}' \
        > "${RESULT_ROOT}/DECLARED_SCHEDULE.json"
    (
        cd "${WORK_DIR}"
        sha256sum \
            CTFR_EXPERIMENT_PROTOCOL.md \
            CTFR_DECISION_RULES.md \
            CTFR_FROZEN_HYPERPARAMETERS.json \
            CTFR_SAMPLING_POLICY.json \
            ctfr_frozen_corpus.json \
            generate_ctfr_manifests.py \
            CTFR_MANIFEST_SCHEMA.md \
            CTFR_DEPLOYMENT_FILELIST.txt \
            CTFR_V1_GATE_DIAGNOSTIC.md \
            avep_paper_instrumentation.patch \
            avep_causal_ablation.patch \
            avep_pcfr_mitigation.patch \
            avep_ctfr_mitigation.patch \
            avep_ctfr_experiment_support.patch \
            avep_ctfr_triton_compat.patch \
            avep_ctfr_telemetry_v2.patch \
            prepare_ctfr_source.sh \
            run_factorial_confirmatory.sh \
            run_ctfr_full_study.sh \
            ctfr_gateway.py \
            ctfr_dual_probe.py \
            test_ctfr_dual_probe.py \
            ctfr_resource_sampler.sh \
            extract_ctfr_baseline.py \
            test_extract_ctfr_baseline.py \
            analyze_ctfr_mechanism.py \
            test_analyze_ctfr_mechanism.py \
            test_generate_ctfr_manifests.py \
            analyze_ctfr_full_study.py \
            test_analyze_ctfr_full_study.py \
            ctfr_baseline_committed_state_v2.json \
            ctfr_baseline_pilot_v2/COMPLETE \
            ctfr_baseline_pilot_v2/PROVENANCE.sha256 \
            ctfr_manifests_v2/*.json \
            ctfr_full_environment_v2.txt \
            > "${RESULT_ROOT}/DECLARED_INPUTS.sha256"
    )
    (
        cd "${RESULT_ROOT}"
        sha256sum DECLARED_SCHEDULE.json > DECLARED_SCHEDULE.json.sha256
        sha256sum DECLARED_DECISION_RULES.md \
            > DECLARED_DECISION_RULES.md.sha256
    )
    jq -n \
        --arg attacker "$(secret_sha256 "${ATTACKER_API_KEY}")" \
        --arg victim "$(secret_sha256 "${VICTIM_API_KEY}")" \
        --arg upstream "$(secret_sha256 "${UPSTREAM_API_KEY}")" \
        '{attacker: $attacker, victim: $victim, upstream: $upstream}' \
        > "${RESULT_ROOT}/DECLARED_PRINCIPALS.json"
    (
        cd "${RESULT_ROOT}"
        sha256sum DECLARED_PRINCIPALS.json \
            > DECLARED_PRINCIPALS.json.sha256
    )
    date --iso-8601=ns > "${RESULT_ROOT}/DECLARED_AT_UTC.txt"
}

run_stage_d_gate() {
    local -a gate_runs=(
        gate_stage_d_shared
        gate_stage_d_frozen
        gate_stage_d_tenant-local
        gate_stage_d_ctfr-shadow
        gate_stage_d_ctfr-full
    )
    if require_empty_or_complete_block "${gate_runs[@]}"; then
        :
    else
        local resume_status="$?"
        if ((resume_status != 10)); then
            return "${resume_status}"
        fi
    fi
    local arm
    for arm in shared frozen tenant-local ctfr-shadow ctfr-full; do
        run_adaptation_arm \
            "gate_stage_d_${arm}" \
            stage-d-gate \
            gate \
            "${arm}" \
            false \
            "${MANIFEST_DIR}/shifted_adaptation.json" \
            "${MANIFEST_DIR}/shifted_evaluation.json" \
            independent \
            true
    done
    "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --stage stage-d-gate \
        --output "${RESULT_ROOT}/stage_d_gate_assessment.json"
}

require_stage_d_gate_pass() {
    local assessment="${RESULT_ROOT}/stage_d_gate_assessment.json"
    local partial="${assessment}.recheck.partial"
    "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --stage stage-d-gate \
        --output "${partial}"
    jq -e '
        .valid == true
        and .analysis_stage == "stage-d-gate"
        and .classification == "CTFR_MECHANISM_GATE_PASSED"
        and .stage_d_gate.valid == true
        and .stage_d_gate.arm_count == 5
        and .stage_d_gate.mixed_principal_binding_verified == true
        and .stage_d_gate.pre_retirement_committed_state_invariance == true
        and .stage_d_gate.shared_over_frozen_adaptation_opportunity == true
        and .stage_d_gate.ctfr_retirement_geometry_valid == true
        and .stage_d_gate.tenant_local_refit_valid == true
    ' "${partial}" >/dev/null || {
        printf 'Stage D mechanism gate did not satisfy every frozen gate.\n' \
            >&2
        return 1
    }
    mv "${partial}" "${assessment}"
}

run_stage_d() {
    local -a orders=(
        "shared frozen tenant-local ctfr-shadow ctfr-full"
        "frozen tenant-local ctfr-shadow ctfr-full shared"
        "tenant-local ctfr-shadow ctfr-full shared frozen"
        "ctfr-shadow ctfr-full shared frozen tenant-local"
        "ctfr-full shared frozen tenant-local ctfr-shadow"
        "ctfr-full ctfr-shadow tenant-local frozen shared"
        "shared ctfr-full ctfr-shadow tenant-local frozen"
        "frozen shared ctfr-full ctfr-shadow tenant-local"
    )
    local block_number
    local block_id
    local arm
    for block_number in $(seq 1 8); do
        block_id="$(printf '%02d' "${block_number}")"
        local -a block_runs=()
        for arm in ${orders[$((block_number - 1))]}; do
            block_runs+=("stage_d_block_${block_id}_${arm}")
        done
        if require_empty_or_complete_block "${block_runs[@]}"; then
            :
        else
            local resume_status="$?"
            if ((resume_status == 10)); then
                continue
            fi
            return "${resume_status}"
        fi
        for arm in ${orders[$((block_number - 1))]}; do
            run_adaptation_arm \
                "stage_d_block_${block_id}_${arm}" \
                stage-d \
                "${block_id}" \
                "${arm}" \
                true \
                "${MANIFEST_DIR}/shifted_adaptation.json" \
                "${MANIFEST_DIR}/shifted_evaluation.json" \
                independent
        done
    done
    "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --stage stage-d \
        --require-complete \
        --output "${RESULT_ROOT}/stage_d_assessment.json"
}

run_stage_e() {
    if require_empty_or_complete_block stage_e_e1_one_identity; then
        :
    else
        local resume_status="$?"
        if ((resume_status != 10)); then
            return "${resume_status}"
        fi
    fi
    run_adaptation_arm \
        stage_e_e1_one_identity \
        stage-e1 \
        e1 \
        ctfr-full \
        true \
        "${MANIFEST_DIR}/e1_one_identity.json" \
        "${MANIFEST_DIR}/shifted_evaluation.json" \
        attacker-only \
        true
    local block_number
    local block_id
    for block_number in $(seq 1 8); do
        block_id="$(printf '%02d' "${block_number}")"
        local -a block_runs=(
            "stage_e2_block_${block_id}_disagreement"
            "stage_e3_block_${block_id}_two_credentials"
        )
        if require_empty_or_complete_block "${block_runs[@]}"; then
            :
        else
            local resume_status="$?"
            if ((resume_status == 10)); then
                continue
            fi
            return "${resume_status}"
        fi
        run_adaptation_arm \
            "stage_e2_block_${block_id}_disagreement" \
            stage-e2 \
            "${block_id}" \
            ctfr-full \
            true \
            "${MANIFEST_DIR}/e2_disagreement.json" \
            "${MANIFEST_DIR}/shifted_evaluation.json" \
            attacker-plus-benign
        run_adaptation_arm \
            "stage_e3_block_${block_id}_two_credentials" \
            stage-e3 \
            "${block_id}" \
            ctfr-full \
            true \
            "${MANIFEST_DIR}/e3_two_credentials.json" \
            "${MANIFEST_DIR}/shifted_evaluation.json" \
            attacker-controls-both
    done
    "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --stage stage-e \
        --output "${RESULT_ROOT}/stage_e_assessment.json"
}

run_overhead() {
    local block_number
    local block_id
    local arm
    local order
    for block_number in $(seq 1 8); do
        block_id="$(printf '%02d' "${block_number}")"
        if ((block_number % 2 == 1)); then
            order="shared ctfr-full-no-retire"
        else
            order="ctfr-full-no-retire shared"
        fi
        local -a block_runs=()
        for arm in ${order}; do
            block_runs+=("overhead_block_${block_id}_${arm}")
        done
        if require_empty_or_complete_block "${block_runs[@]}"; then
            :
        else
            local resume_status="$?"
            if ((resume_status == 10)); then
                continue
            fi
            return "${resume_status}"
        fi
        for arm in ${order}; do
            run_adaptation_arm \
                "overhead_block_${block_id}_${arm}" \
                overhead \
                "${block_id}" \
                "${arm}" \
                true \
                "${MANIFEST_DIR}/stationary_adaptation.json" \
                "${MANIFEST_DIR}/baseline_evaluation.json" \
                independent
        done
    done
    "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
        --result-root "${RESULT_ROOT}" \
        --stage overhead \
        --require-complete \
        --output "${RESULT_ROOT}/overhead_assessment.json"
}

archive_results() {
    verify_baseline_pilot_provenance
    local -a members=(ctfr_full_study_results_v2)
    local member
    while IFS= read -r member; do
        members+=("${member}")
    done < "${DEPLOYMENT_FILELIST}"
    members+=(
        ctfr_manifests_v2
        ctfr_baseline_pilot_v2
        ctfr_baseline_committed_state_v2.json
        ctfr_full_environment_v2.txt
    )
    tar -czf "${RESULT_ARCHIVE}.partial" -C "${WORK_DIR}" \
        "${members[@]}"
    mv "${RESULT_ARCHIVE}.partial" "${RESULT_ARCHIVE}"
    sha256sum "${RESULT_ARCHIVE}" > "${RESULT_ARCHIVE}.sha256"
    cat "${RESULT_ARCHIVE}.sha256"
}

mode="${1:-preflight}"
initialize_credentials
"${WORK_DIR}/prepare_ctfr_source.sh"
runtime_preflight
write_environment_manifest
run_full_self_tests

case "${mode}" in
    preflight)
        ;;
    manifests)
        generate_manifests
        ;;
    baseline)
        run_baseline_pilot
        ;;
    declare)
        declare_protocol
        ;;
    gate)
        declare_protocol
        run_stage_d_gate
        archive_results
        ;;
    stage-d)
        declare_protocol
        require_stage_d_gate_pass
        run_stage_d
        archive_results
        ;;
    stage-e)
        declare_protocol
        require_stage_d_gate_pass
        run_stage_e
        archive_results
        ;;
    overhead)
        declare_protocol
        require_stage_d_gate_pass
        run_overhead
        archive_results
        ;;
    analyze)
        "${VENV_DIR}/bin/python" "${FULL_ANALYZER}" \
            --result-root "${RESULT_ROOT}" \
            --stage all \
            --require-complete \
            --output "${RESULT_ROOT}/ctfr_full_assessment.json"
        archive_results
        ;;
    archive)
        archive_results
        ;;
    *)
        printf '%s\n' \
            "Usage: $0 [preflight|manifests|baseline|declare|gate|stage-d|"\
"stage-e|overhead|analyze|archive]" >&2
        exit 2
        ;;
esac
