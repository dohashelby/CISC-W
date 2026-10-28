#!/usr/bin/env bash
set -Eeuo pipefail

readonly WORK_DIR="/home/ubuntu/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly VENV_DIR="${REPO_DIR}/.venv"
readonly PINNED_SHA="4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c"

apply_once() {
    local patch_path="$1"
    if git -C "${REPO_DIR}" apply --check "${patch_path}"; then
        git -C "${REPO_DIR}" apply "${patch_path}"
        printf 'applied=%s\n' "$(basename "${patch_path}")"
        return
    fi
    if git -C "${REPO_DIR}" apply --reverse --check "${patch_path}"; then
        printf 'already_applied=%s\n' "$(basename "${patch_path}")"
        return
    fi
    printf 'Patch is neither cleanly applicable nor already applied: %s\n' \
        "${patch_path}" >&2
    return 1
}

[[ "$(git -C "${REPO_DIR}" rev-parse HEAD)" == "${PINNED_SHA}" ]] || {
    printf 'Pinned vLLM commit is not checked out.\n' >&2
    exit 1
}
[[ -x "${VENV_DIR}/bin/python" ]] || {
    printf 'Pinned virtual-environment Python is unavailable.\n' >&2
    exit 1
}

readonly -a STACK_FILES=(
    vllm/v1/worker/gpu/model_runner.py
    vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py
    vllm/v1/worker/gpu/spec_decode/adaptive_verification.py
    vllm/v1/worker/gpu/spec_decode/speculator.py
    vllm/v1/worker/gpu_worker.py
)
readonly BASE_STACK="b5a4a8f1e333ec15b89300edfb3f70bcfd12b3d323af529b4a5dc9457b3ddf81"
readonly PAPER_STACK="372bc567370ef76ffc1b7de1b79beb66201c27b7a17ffc83b9b894132c14e25a"
readonly CAUSAL_STACK="58c3bfd627ab23c744e2431d9ca0a1826cb88ca2dd53eca274913c0de729b24c"
readonly PCFR_STACK="9f9d14d52f82cc79d47c32b95a46bf083217325a1bc8f14167d23621dd76f234"
readonly CTFR_STACK="ab8cdc3b94f22702215341971b231f088e86adf835be9a173467f26e0e920c88"
readonly LEGACY_EXPERIMENT_STACK="f941b56ee6a628aeb47a8191820189bfb8a1c5d72d87b401a304b8663177d5c4"
readonly V1_EXPERIMENT_STACK="673abce3bbad23c8c760fef0620ed49ba403ede89c1c4952b8262ad33fe8da61"
readonly EXPERIMENT_STACK="dcc2239dd80e8e4095a76d31a09ae96b5a4de603ca16850706760b4bfe6a2387"

stack_digest() {
    (
        cd "${REPO_DIR}"
        sha256sum "${STACK_FILES[@]}"
    ) | sha256sum | cut -d' ' -f1
}

current_stack="$(stack_digest)"
case "${current_stack}" in
    "${BASE_STACK}")
        apply_once "${WORK_DIR}/avep_paper_instrumentation.patch"
        apply_once "${WORK_DIR}/avep_causal_ablation.patch"
        apply_once "${WORK_DIR}/avep_pcfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_experiment_support.patch"
        ;;
    "${PAPER_STACK}")
        apply_once "${WORK_DIR}/avep_causal_ablation.patch"
        apply_once "${WORK_DIR}/avep_pcfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_experiment_support.patch"
        ;;
    "${CAUSAL_STACK}")
        apply_once "${WORK_DIR}/avep_pcfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_experiment_support.patch"
        ;;
    "${PCFR_STACK}")
        apply_once "${WORK_DIR}/avep_ctfr_mitigation.patch"
        apply_once "${WORK_DIR}/avep_ctfr_experiment_support.patch"
        ;;
    "${CTFR_STACK}")
        apply_once "${WORK_DIR}/avep_ctfr_experiment_support.patch"
        ;;
    "${LEGACY_EXPERIMENT_STACK}")
        printf 'migrating=ctfr_triton_static_range_compatibility\n'
        ;;
    "${V1_EXPERIMENT_STACK}")
        printf 'migrating=ctfr_direct_verification_telemetry_v2\n'
        ;;
    "${EXPERIMENT_STACK}")
        printf 'already_applied=complete_ctfr_experiment_stack\n'
        ;;
    *)
        printf 'Refusing an unknown or partially modified patch stack: %s\n' \
            "${current_stack}" >&2
        exit 1
        ;;
esac
apply_once "${WORK_DIR}/avep_ctfr_triton_compat.patch"
apply_once "${WORK_DIR}/avep_ctfr_telemetry_v2.patch"

[[ "$(stack_digest)" == "${EXPERIMENT_STACK}" ]] || {
    printf 'Final CTFR experiment source digest does not match the frozen stack.\n' >&2
    exit 1
}

while IFS= read -r changed_path; do
    case "${changed_path}" in
        vllm/v1/worker/gpu/model_runner.py|\
        vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py|\
        vllm/v1/worker/gpu/spec_decode/adaptive_verification.py|\
        vllm/v1/worker/gpu/spec_decode/speculator.py|\
        vllm/v1/worker/gpu_worker.py)
            ;;
        *)
            printf 'Refusing unrelated tracked modification: %s\n' \
                "${changed_path}" >&2
            exit 1
            ;;
    esac
done < <(git -C "${REPO_DIR}" diff --name-only HEAD --)

git -C "${REPO_DIR}" diff --check
"${VENV_DIR}/bin/python" -m py_compile \
    "${REPO_DIR}/vllm/v1/worker/gpu/model_runner.py" \
    "${REPO_DIR}/vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py" \
    "${REPO_DIR}/vllm/v1/worker/gpu/spec_decode/adaptive_verification.py" \
    "${REPO_DIR}/vllm/v1/worker/gpu/spec_decode/speculator.py" \
    "${REPO_DIR}/vllm/v1/worker/gpu_worker.py" \
    "${WORK_DIR}/ctfr_gateway.py" \
    "${WORK_DIR}/ctfr_dual_probe.py" \
    "${WORK_DIR}/test_ctfr_dual_probe.py" \
    "${WORK_DIR}/extract_ctfr_baseline.py" \
    "${WORK_DIR}/generate_ctfr_manifests.py" \
    "${WORK_DIR}/analyze_ctfr_mechanism.py" \
    "${WORK_DIR}/test_analyze_ctfr_mechanism.py" \
    "${WORK_DIR}/test_extract_ctfr_baseline.py" \
    "${WORK_DIR}/test_generate_ctfr_manifests.py" \
    "${WORK_DIR}/analyze_ctfr_full_study.py" \
    "${WORK_DIR}/test_analyze_ctfr_full_study.py"
(
    cd "${WORK_DIR}"
    "${VENV_DIR}/bin/python" -m unittest -v \
        test_analyze_ctfr_mechanism.py \
        test_extract_ctfr_baseline.py \
        test_ctfr_dual_probe.py \
        test_generate_ctfr_manifests.py \
        test_analyze_ctfr_full_study.py
)

sha256sum \
    "${WORK_DIR}/avep_paper_instrumentation.patch" \
    "${WORK_DIR}/avep_causal_ablation.patch" \
    "${WORK_DIR}/avep_pcfr_mitigation.patch" \
    "${WORK_DIR}/avep_ctfr_mitigation.patch" \
    "${WORK_DIR}/avep_ctfr_experiment_support.patch" \
    "${WORK_DIR}/avep_ctfr_triton_compat.patch" \
    "${WORK_DIR}/avep_ctfr_telemetry_v2.patch" \
    "${WORK_DIR}/ctfr_gateway.py" \
    "${WORK_DIR}/ctfr_dual_probe.py" \
    "${WORK_DIR}/test_ctfr_dual_probe.py" \
    "${WORK_DIR}/extract_ctfr_baseline.py" \
    "${WORK_DIR}/generate_ctfr_manifests.py" \
    "${WORK_DIR}/analyze_ctfr_mechanism.py" \
    "${WORK_DIR}/test_analyze_ctfr_mechanism.py" \
    "${WORK_DIR}/test_extract_ctfr_baseline.py" \
    "${WORK_DIR}/test_generate_ctfr_manifests.py" \
    "${WORK_DIR}/analyze_ctfr_full_study.py" \
    "${WORK_DIR}/test_analyze_ctfr_full_study.py" \
    "${WORK_DIR}/run_ctfr_mechanism.sh" \
    "${WORK_DIR}/run_ctfr_full_study.sh"
