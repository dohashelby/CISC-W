#!/usr/bin/env bash
set -Eeuo pipefail

readonly WORK_DIR="${HOME}/avep"
readonly REPO_DIR="${WORK_DIR}/vllm"
readonly TARGET_SHA="4fe9e6f6e5647a159c9e65e4f3bf33dec5d12e1c"
readonly SETUP_LOG="${WORK_DIR}/paper_setup.log"

mkdir -p "${WORK_DIR}"
exec > >(tee -a "${SETUP_LOG}") 2>&1

date --iso-8601=seconds
nvidia-smi

if ! command -v jq >/dev/null 2>&1; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y jq
fi

for command_name in \
    curl find git grep jq nvidia-smi ps setsid sha256sum ss tar timeout; do
    if ! command -v "${command_name}" >/dev/null 2>&1; then
        printf 'Required setup command is unavailable: %s\n' \
            "${command_name}" >&2
        exit 1
    fi
done

if ! command -v uv >/dev/null 2>&1; then
    curl --fail --show-error --silent --location \
        --retry 3 --retry-all-errors --connect-timeout 10 --max-time 300 \
        https://astral.sh/uv/install.sh | sh
fi
export PATH="${HOME}/.local/bin:${PATH}"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
    git clone https://github.com/vllm-project/vllm.git "${REPO_DIR}"
fi

cd "${REPO_DIR}"
git fetch origin "${TARGET_SHA}"
git checkout --detach "${TARGET_SHA}"
test "$(git rev-parse HEAD)" = "${TARGET_SHA}"

if git apply --check "${WORK_DIR}/avep_paper_instrumentation.patch"; then
    git apply "${WORK_DIR}/avep_paper_instrumentation.patch"
elif git apply --reverse --check "${WORK_DIR}/avep_paper_instrumentation.patch"; then
    printf 'Paper instrumentation patch is already applied.\n'
else
    printf 'Paper instrumentation patch does not apply cleanly.\n' >&2
    exit 1
fi
git diff --check

uv venv --python 3.12
source .venv/bin/activate
uv pip install -r requirements/lint.txt
pre-commit install
VLLM_USE_PRECOMPILED=1 uv pip install -e . --torch-backend=auto

.venv/bin/python -m py_compile \
    vllm/v1/worker/gpu/spec_decode/acceptance_estimator.py \
    vllm/v1/worker/gpu/spec_decode/adaptive_verification.py \
    vllm/v1/worker/gpu_worker.py \
    "${WORK_DIR}/paper_probe.py" \
    "${WORK_DIR}/find_ordinary_tokens.py" \
    "${WORK_DIR}/analyze_paper_trials.py"

.venv/bin/python "${WORK_DIR}/find_ordinary_tokens.py" \
    --output "${WORK_DIR}/ordinary_tokens.json"

{
    printf 'vllm_sha=%s\n' "$(git rev-parse HEAD)"
    printf 'paper_patch_sha256=%s\n' \
        "$(sha256sum "${WORK_DIR}/avep_paper_instrumentation.patch" | cut -d' ' -f1)"
    printf 'probe_sha256=%s\n' \
        "$(sha256sum "${WORK_DIR}/paper_probe.py" | cut -d' ' -f1)"
    printf 'analyzer_sha256=%s\n' \
        "$(sha256sum "${WORK_DIR}/analyze_paper_trials.py" | cut -d' ' -f1)"
    uv --version
    .venv/bin/python --version
    .venv/bin/vllm --version
    nvidia-smi --query-gpu=name,driver_version,memory.total \
        --format=csv,noheader
} | tee "${WORK_DIR}/manifest.txt"

date --iso-8601=seconds
touch "${WORK_DIR}/PAPER_SETUP_COMPLETE"
