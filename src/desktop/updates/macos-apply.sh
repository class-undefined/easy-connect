#!/bin/sh
set -eu
source_app=$1
destination=$2
incoming=$3
backup=$4
mode=${5:-install}
parent=$(/usr/bin/dirname "$destination")
[ -w "$parent" ] || exit 77
[ ! -L "$destination" ] || exit 1
if [ "$mode" = rollback ]; then
    if [ -d "$backup" ]; then
        /bin/mv "$destination" "$incoming"
        /bin/mv "$backup" "$destination" || { /bin/mv "$incoming" "$destination"; exit 1; }
        /bin/rm -rf "$incoming"
    fi
    exit 0
fi
[ -d "$source_app" ] && [ ! -e "$incoming" ] && [ ! -e "$backup" ] || exit 1
cleanup() {
    result=$?
    trap - EXIT
    if [ "$result" -ne 0 ]; then
        if [ -d "$backup" ] && [ ! -e "$destination" ]; then
            /bin/mv "$backup" "$destination" || true
        fi
        /bin/rm -rf "$incoming"
    fi
    exit "$result"
}
trap cleanup EXIT
/usr/bin/ditto "$source_app" "$incoming"
/usr/bin/codesign --verify --deep --strict "$incoming"
if [ -e "$destination" ]; then /bin/mv "$destination" "$backup"; fi
/bin/mv "$incoming" "$destination"
