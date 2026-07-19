#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 4 )); then
	echo "usage: $0 PEER_PHYS [REQUIRED_SAMPLES] [INTERVAL_S] [MAX_SAMPLES]" >&2
	exit 2
fi

peer_phys=$1
required_samples=${2:-80}
interval_s=${3:-0.5}
max_samples=${4:-240}
baseline=
stable_samples=0

for sample in $(seq 1 "$max_samples"); do
	tuples=$(
		ss -Htn state established |
			awk -v peer="$peer_phys" \
				'($3 ~ /:51821$/ || $4 ~ /:51821$/) &&
				 (index($3, peer ":") || index($4, peer ":")) {
					print $3, $4
				}' |
			sort
	)
	count=$(printf '%s\n' "$tuples" | awk 'NF {++n} END {print n+0}')
	if (( count != 2 )); then
		baseline=
		stable_samples=0
	elif [[ -z $baseline || $tuples != "$baseline" ]]; then
		baseline=$tuples
		stable_samples=1
	else
		(( ++stable_samples ))
	fi
	printf '%s\n%s\n' \
		"--- $(date +%s.%N) sample=$sample count=$count stable=$stable_samples ---" \
		"$tuples"
	if (( stable_samples >= required_samples )); then
		printf 'carrier_qualification=passed stable_samples=%s\n' "$stable_samples"
		exit 0
	fi
	sleep "$interval_s"
done

echo "no stable two-carrier window within $max_samples samples" >&2
exit 1
