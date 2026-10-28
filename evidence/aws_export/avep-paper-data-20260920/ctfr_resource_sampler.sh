#!/usr/bin/env bash
set -Eeuo pipefail

if (($# != 5)); then
    printf 'Usage: %s SERVER_PGID GATEWAY_PGID SENTINEL OUTPUT INTERVAL\n' \
        "$0" >&2
    exit 2
fi

readonly SERVER_PGID="$1"
readonly GATEWAY_PGID="$2"
readonly SENTINEL="$3"
readonly OUTPUT="$4"
readonly INTERVAL="$5"
readonly CLOCK_TICKS_PER_SECOND="$(getconf CLK_TCK)"

[[ "${SERVER_PGID}" =~ ^[0-9]+$ ]] || exit 2
[[ "${GATEWAY_PGID}" =~ ^[0-9]+$ ]] || exit 2
[[ "${INTERVAL}" =~ ^[0-9]+([.][0-9]+)?$ ]] || exit 2
[[ "${CLOCK_TICKS_PER_SECOND}" =~ ^[0-9]+$ ]] || exit 2
: > "${OUTPUT}"

sample_group() {
    local pgid="$1"
    local pid
    local process_pgid
    local rss
    local stat_line
    local stat_tail
    local -a stat_fields
    local total_rss=0
    local total_ticks=0
    local processes=0
    while read -r pid process_pgid rss; do
        [[ "${process_pgid}" == "${pgid}" ]] || continue
        [[ -r "/proc/${pid}/stat" ]] || continue
        stat_line="$(< "/proc/${pid}/stat")"
        stat_tail="${stat_line##*) }"
        read -r -a stat_fields <<< "${stat_tail}"
        ((${#stat_fields[@]} >= 13)) || continue
        total_rss=$((total_rss + rss))
        total_ticks=$((
            total_ticks + stat_fields[11] + stat_fields[12]
        ))
        processes=$((processes + 1))
    done < <(ps -e -o pid=,pgid=,rss= 2>/dev/null)
    printf '%d %d %d' "${total_rss}" "${total_ticks}" "${processes}"
}

read -r previous_server_rss previous_server_ticks previous_server_processes \
    <<< "$(sample_group "${SERVER_PGID}")"
read -r previous_gateway_rss previous_gateway_ticks \
    previous_gateway_processes <<< "$(sample_group "${GATEWAY_PGID}")"
previous_sample_ns="$(date +%s%N)"
sleep "${INTERVAL}"

while [[ -e "${SENTINEL}" ]]; do
    read -r server_rss server_ticks server_processes \
        <<< "$(sample_group "${SERVER_PGID}")"
    read -r gateway_rss gateway_ticks gateway_processes \
        <<< "$(sample_group "${GATEWAY_PGID}")"
    sampled_at_ns="$(date +%s%N)"
    wall_delta_ns=$((sampled_at_ns - previous_sample_ns))
    server_ticks_delta=$((server_ticks - previous_server_ticks))
    gateway_ticks_delta=$((gateway_ticks - previous_gateway_ticks))
    if ((
        wall_delta_ns <= 0
        || server_ticks_delta < 0
        || gateway_ticks_delta < 0
        || server_processes < 1
        || gateway_processes < 1
    )); then
        printf 'Invalid interval resource sample.\n' >&2
        exit 1
    fi
    server_cpu="$(awk \
        -v ticks="${server_ticks_delta}" \
        -v hz="${CLOCK_TICKS_PER_SECOND}" \
        -v wall_ns="${wall_delta_ns}" \
        'BEGIN {printf "%.6f", 100.0 * ticks * 1e9 / hz / wall_ns}'
    )"
    gateway_cpu="$(awk \
        -v ticks="${gateway_ticks_delta}" \
        -v hz="${CLOCK_TICKS_PER_SECOND}" \
        -v wall_ns="${wall_delta_ns}" \
        'BEGIN {printf "%.6f", 100.0 * ticks * 1e9 / hz / wall_ns}'
    )"
    gpu_sample="$(
        nvidia-smi \
            --query-gpu=memory.used,utilization.gpu,power.draw \
            --format=csv,noheader,nounits \
            | head -1
    )"
    IFS=',' read -r gpu_memory gpu_utilization gpu_power \
        <<< "${gpu_sample}"
    jq -cn \
        --arg sampled_at "$(date --iso-8601=ns)" \
        --argjson server_rss_kib "${server_rss}" \
        --argjson server_cpu_percent "${server_cpu}" \
        --argjson server_cpu_ticks_delta "${server_ticks_delta}" \
        --argjson server_processes "${server_processes}" \
        --argjson gateway_rss_kib "${gateway_rss}" \
        --argjson gateway_cpu_percent "${gateway_cpu}" \
        --argjson gateway_cpu_ticks_delta "${gateway_ticks_delta}" \
        --argjson gateway_processes "${gateway_processes}" \
        --argjson cpu_window_ns "${wall_delta_ns}" \
        --argjson clock_ticks_per_second "${CLOCK_TICKS_PER_SECOND}" \
        --arg gpu_memory_mib "${gpu_memory//[[:space:]]/}" \
        --arg gpu_utilization_percent "${gpu_utilization//[[:space:]]/}" \
        --arg gpu_power_watts "${gpu_power//[[:space:]]/}" \
        '{sampled_at: $sampled_at,
          server: {rss_kib: $server_rss_kib,
            cpu_percent: $server_cpu_percent,
            cpu_ticks_delta: $server_cpu_ticks_delta,
            processes: $server_processes},
          gateway: {rss_kib: $gateway_rss_kib,
            cpu_percent: $gateway_cpu_percent,
            cpu_ticks_delta: $gateway_cpu_ticks_delta,
            processes: $gateway_processes},
          cpu_measurement: {source: "proc-stat-interval-delta",
            window_ns: $cpu_window_ns,
            clock_ticks_per_second: $clock_ticks_per_second},
          gpu: {memory_mib: ($gpu_memory_mib | tonumber),
            utilization_percent: ($gpu_utilization_percent | tonumber),
            power_watts: ($gpu_power_watts | tonumber)}}' \
        >> "${OUTPUT}"
    previous_server_rss="${server_rss}"
    previous_server_ticks="${server_ticks}"
    previous_server_processes="${server_processes}"
    previous_gateway_rss="${gateway_rss}"
    previous_gateway_ticks="${gateway_ticks}"
    previous_gateway_processes="${gateway_processes}"
    previous_sample_ns="${sampled_at_ns}"
    sleep "${INTERVAL}"
done
