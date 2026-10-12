#!/bin/sh
set -u
job=$1
. "$job/plan.sh"
printf ready > "$job/ready"
attempt=0
while /bin/kill -0 "$parent_pid" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 600 ] || exit 1
    /bin/sleep 0.2
done
apply() {
    /bin/sh "$job/apply.sh" "$staged" "$destination" "$incoming" "$backup" "$1"
    code=$?
    if [ "$code" -eq 77 ]; then
        /usr/bin/osascript "$job/elevate.applescript" "$job/apply.sh" "$staged" "$destination" "$incoming" "$backup" "$1"
        return $?
    fi
    return "$code"
}
if apply install; then
    printf '{"success":true,"version":"%s"}\n' "$version" > "$receipt"
    if /usr/bin/open -n "$destination"; then
        /bin/rm -rf "$backup" 2>/dev/null || true
        /bin/rm -rf "$job" 2>/dev/null || true
        exit 0
    fi
    apply rollback || true
fi
printf '{"success":false,"version":"%s"}\n' "$version" > "$receipt"
/usr/bin/open -n "$fallback"
