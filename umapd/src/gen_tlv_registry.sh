#!/bin/sh

ids=

for path in u1905/tlv/[0-9a-f][0-9a-f].uc; do
	id=${path##*/}
	ids="$ids ${id%.uc}"
done

for id in $ids; do
	printf 'import tlv_%s from "u1905.tlv.%s";\n' $id $id
done

printf '\nexport default [\n';

prev_id=0

for id in $ids; do
	for n in $(seq $((prev_id + 1)) $((0x$id - 1))); do
		printf '\tnull,\n'
	done

	printf '\ttlv_%s,\n' $id
	prev_id=$((0x$id))
done

printf '];\n'
