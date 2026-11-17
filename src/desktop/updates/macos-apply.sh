#!/bin/sh
set -eu
source_app=$1
destination=$2
incoming=$3
backup=$4
mode=${5:-install}
owner=${6:-}
parent=$(/usr/bin/dirname "$destination")
[ -w "$parent" ] || exit 77
# The app and its persistent helper are one install transaction. Ask for root
# before changing either, even when the user's Applications folder is writable.
if [ -n "$owner" ] && [ "$(/usr/bin/id -u)" -ne 0 ]; then exit 77; fi
[ ! -L "$destination" ] || exit 1
restore_previous() {
    if [ -d "$backup" ]; then
        if [ -e "$destination" ]; then /bin/mv "$destination" "$incoming" || return 1; fi
        /bin/mv "$backup" "$destination" || { /bin/mv "$incoming" "$destination"; return 1; }
        /bin/rm -rf "$incoming"
        if [ "$1" -eq 1 ] && [ -n "$owner" ]; then
            "$destination/Contents/MacOS/easy-connect" install-service --owner "$owner"
        fi
    fi
}
if [ "$mode" = rollback ]; then
    restore_previous 1
    exit 0
fi
[ -d "$source_app" ] && [ ! -e "$incoming" ] && [ ! -e "$backup" ] || exit 1
service_attempted=0
cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then
        # If installing the helper failed, try restoring both versions while
        # this authorization is still active, before reopening the previous app.
        restore_previous "$service_attempted" || true
        /bin/rm -rf "$incoming"
    fi
    exit "$result"
}
trap cleanup EXIT
/usr/bin/ditto "$source_app" "$incoming"
/usr/bin/codesign --verify --deep --strict "$incoming"
if [ -e "$destination" ]; then /bin/mv "$destination" "$backup"; fi
/bin/mv "$incoming" "$destination"
if [ -n "$owner" ]; then
    service_attempted=1
    "$destination/Contents/MacOS/easy-connect" install-service --owner "$owner"
fi
