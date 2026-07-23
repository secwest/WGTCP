#!/usr/bin/env bash
set -euo pipefail

if (( $# != 4 )); then
	echo "usage: $0 PEER_PHYS EXPECTED_CARRIERS DURATION_S INTERVAL_S" >&2
	exit 2
fi

peer_phys=$1
expected_carriers=$2
duration_s=$3
interval_s=$4

if ! [[ $peer_phys =~ ^[[:xdigit:].]+$ ]] ||
	! [[ $expected_carriers =~ ^[1-9][0-9]*$ ]] ||
	! [[ $duration_s =~ ^[1-9][0-9]*$ ]] ||
	! [[ $interval_s =~ ^(0|[1-9][0-9]*)(\.[0-9]+)?$ ]]; then
	echo "invalid diagnostic arguments" >&2
	exit 2
fi

max_samples=$(awk -v duration="$duration_s" -v interval="$interval_s" \
	'BEGIN { print int(duration / interval + 0.5) }')
if (( max_samples < 2 )); then
	echo "duration produces fewer than two samples" >&2
	exit 2
fi

carrier_tuples() {
	ss -Htn state established |
		awk -v peer="$peer_phys" \
			'($3 ~ /:51821$/ || $4 ~ /:51821$/) &&
			 (index($3, peer ":") || index($4, peer ":")) {
				print $3, $4
			}' |
		sort
}

snapshot() {
	local reason=$1

	printf '%s\n' "--- snapshot reason=$reason timestamp=$(date +%s.%N) ---"
	ss -tin state established '( sport = :51821 or dport = :51821 )' || true
	printf '%s\n' "--- kernel-tail ---"
	dmesg --color=never | tail -n 80 || true
}

baseline=
tuple_changes=0
wrong_count_samples=0

printf 'carrier_diagnostic=started peer=%s expected_carriers=%s duration_s=%s interval_s=%s max_samples=%s\n' \
	"$peer_phys" "$expected_carriers" "$duration_s" "$interval_s" "$max_samples"

for sample in $(seq 1 "$max_samples"); do
	tuples=$(carrier_tuples)
	count=$(printf '%s\n' "$tuples" | awk 'NF {++n} END {print n+0}')
	reason=

	if (( count != expected_carriers )); then
		(( ++wrong_count_samples ))
		reason="carrier_count"
	elif [[ -z $baseline ]]; then
		baseline=$tuples
	elif [[ $tuples != "$baseline" ]]; then
		(( ++tuple_changes ))
		reason="tuple_change"
	fi

	printf '%s\n%s\n' \
		"--- $(date +%s.%N) sample=$sample count=$count tuple_changes=$tuple_changes wrong_count_samples=$wrong_count_samples ---" \
		"$tuples"
	if [[ -n $reason ]]; then
		snapshot "$reason"
		if [[ $reason == tuple_change ]]; then
			baseline=$tuples
		fi
	fi
	(( sample == max_samples )) || sleep "$interval_s"
done

if (( tuple_changes == 0 && wrong_count_samples == 0 )); then
	printf 'carrier_diagnostic=passed samples=%s tuple_changes=0 wrong_count_samples=0\n' \
		"$max_samples"
	exit 0
fi

printf 'carrier_diagnostic=failed samples=%s tuple_changes=%s wrong_count_samples=%s\n' \
	"$max_samples" "$tuple_changes" "$wrong_count_samples" >&2
exit 1
