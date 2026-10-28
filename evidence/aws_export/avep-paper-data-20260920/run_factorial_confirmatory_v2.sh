#!/usr/bin/env bash
set -Eeuo pipefail

# v2 intentionally reuses the audited v1 lifecycle and workload implementation.
# These deterministic substitutions create a separate protocol namespace while
# the v2 analyzer and decision rules change only the prespecified endpoints.
readonly BASE_DRIVER="/home/ubuntu/avep/run_factorial_confirmatory.sh"
readonly BASE_DRIVER_SHA256="ea733ab7264d5c55418e2f0819da09d757deea15708885b2e495a440912ff172"

actual_base_driver_sha256="$(sha256sum "${BASE_DRIVER}" | cut -d' ' -f1)"
if [[ "${actual_base_driver_sha256}" != "${BASE_DRIVER_SHA256}" ]]; then
    printf 'Base driver SHA-256 does not match the v2 commitment.\n' >&2
    exit 1
fi

if [[ -f /home/ubuntu/avep/factorial_environment.txt \
    && -d /home/ubuntu/avep/factorial_confirmatory_results_v1 \
    && ! -e /home/ubuntu/avep/factorial_environment_v1_before_v2.txt ]]; then
    cp -p /home/ubuntu/avep/factorial_environment.txt \
        /home/ubuntu/avep/factorial_environment_v1_before_v2.txt
    sha256sum /home/ubuntu/avep/factorial_environment_v1_before_v2.txt \
        > /home/ubuntu/avep/factorial_environment_v1_before_v2.txt.sha256
fi

# shellcheck disable=SC1090
source <(
    sed \
        -e '/^mode="${1:-core}"$/,$d' \
        -e 's/avep-factorial-confirmatory-v1/avep-factorial-confirmatory-v2/g' \
        -e 's/factorial_confirmatory_results_v1/factorial_confirmatory_results_v2/g' \
        -e 's/\.avep_factorial_v1_tenant_credentials/\.avep_factorial_v2_tenant_credentials/g' \
        -e 's/FACTORIAL_CONFIRMATORY_PROTOCOL\.md/FACTORIAL_CONFIRMATORY_V2_PROTOCOL.md/g' \
        -e 's/FACTORIAL_CONFIRMATORY_DECISION_RULES\.md/FACTORIAL_CONFIRMATORY_V2_DECISION_RULES.md/g' \
        -e 's/run_factorial_confirmatory\.sh/run_factorial_confirmatory_v2.sh/g' \
        -e 's/analyze_factorial_confirmatory\.py/analyze_factorial_confirmatory_v2.py/g' \
        -e 's/test_analyze_factorial_confirmatory\.py/test_analyze_factorial_confirmatory_v2.py/g' \
        "${BASE_DRIVER}"
)

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
