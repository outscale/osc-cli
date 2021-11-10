#!/bin/bash
set -e
echo -n "$(basename $0)... "

if [ -z "$OSC_TEST_ACCESS_KEY" ]; then
    echo "OSC_TEST_ACCESS_KEY not set, aborting"
    exit 1
fi

if [ -z "$OSC_TEST_SECRET_KEY" ]; then
    echo "OSC_TEST_SECRET_KEY not set, aborting"
    exit 1
fi

if [ -z "$OSC_TEST_ENDPOINT_ICU" ]; then
    echo "OSC_TEST_ENDPOINT_ICU not set, aborting"
    exit 1
fi

if [ -z "$OSC_TEST_REGION" ]; then
    echo "OSC_TEST_REGION not set, aborting"
    exit 1
fi

PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
. .venv/bin/activate
pytest osc_sdk &> /dev/null
echo "OK"
