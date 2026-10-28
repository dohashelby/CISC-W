#!/usr/bin/env bash
set -Eeuo pipefail

readonly work_dir="/home/ubuntu/avep"
readonly runner="${work_dir}/run_ctfr_determinism_gate.sh"
readonly manifest="${work_dir}/CTFR_DETERMINISM_DEPLOYMENT_SHA256SUMS"
readonly failed_suffix="failed-preflight-vllm-version-1789901378"

sed -i \
    's#import vllm; print("vllm=" + vllm.__version__)#import importlib.metadata as m; print("vllm=" + m.version("vllm"))#' \
    "${runner}"
sed -i \
    's#1e81697e29b60972cce751ef9187c20a5abd498d53e4a902542fb5eb441ef247#cbd4f85d11b757e1df5c8d177ceb37c1139ff3fd34321c106d9ef446d5a4439f#' \
    "${manifest}"
chown ubuntu:ubuntu "${runner}" "${manifest}"

(
    cd "${work_dir}"
    sha256sum -c CTFR_DETERMINISM_DEPLOYMENT_SHA256SUMS
)

test -d "${work_dir}/ctfr_determinism_gate_v1"
test ! -e "${work_dir}/ctfr_determinism_gate_v1.${failed_suffix}"
mv \
    "${work_dir}/ctfr_determinism_gate_v1" \
    "${work_dir}/ctfr_determinism_gate_v1.${failed_suffix}"

for path in \
    "${work_dir}/avep-ctfr-determinism-gate-v1-partial.tgz" \
    "${work_dir}/avep-ctfr-determinism-gate-v1-partial.tgz.sha256"; do
    if [[ -e "${path}" ]]; then
        mv "${path}" "${path}.${failed_suffix}"
    fi
done

printf 'hotfix=complete\nfailed_result=%s\n' \
    "${work_dir}/ctfr_determinism_gate_v1.${failed_suffix}"
