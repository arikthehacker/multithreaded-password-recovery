#!/usr/bin/env bash
# Build thread_hash, crack the bundled example, and check the four known plaintexts
# are recovered. Needs libcrypt (Linux).
set -euo pipefail
cd "$(dirname "$0")"

make >/dev/null

out=$(./thread_hash -i example-hashes.txt -d example-dict.txt 2>/dev/null)

rc=0
for word in password dragon trustno1 swordfish; do
    if echo "$out" | grep -q "cracked  $word  "; then
        echo "ok    cracked $word"
    else
        echo "FAIL  did not crack $word"
        rc=1
    fi
done

[ "$rc" -eq 0 ] && echo "PASS: all four example passwords recovered"
exit $rc
