#!/bin/bash -xe
# Release packages to PyPI

if [ "`dirname $0`" != "tools" ] ; then
    echo Please run this script from the repo root
    exit 1
fi

CheckVersion() {
    # Args: <description of version type> <version number>
    if ! echo "$1" | grep -q -e '[0-9]\+.[0-9]\+.[0-9]\+' ; then
        echo "$1 doesn't look like 1.2.3"
        echo "Usage:"
        echo "$0 RELEASE_VERSION NEXT_VERSION"
        exit 1
    fi
}

CheckVersion "$1"
CheckVersion "$2"

if ! gpg2 --card-status >/dev/null 2>&1; then
    echo OpenPGP card not found!
    echo Please insert your PGP card and run this script again.
    exit 1
fi

if ! command -v script >/dev/null 2>&1; then
    echo The command script was not found.
    echo Please install it.
    exit 1
fi

export RELEASE_DIR="./releases"
mv "$RELEASE_DIR" "$RELEASE_DIR.$(date +%s).bak" || true
LOG_PATH="log"
mv "$LOG_PATH" "$LOG_PATH.$(date +%s).bak" || true

CMD="tools/release.sh $1 $2"
# Work with both Linux and macOS versions of script
if script --help | grep -q -- '--command'; then
    script --command "$CMD" "$LOG_PATH"
else
    script "$LOG_PATH" "$CMD"
fi

tools/_release.sh
