#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

# All calls must fail with a bad auth method even if accesskey method is available
# This env variable must be set:
# OSC_TEST_LOGIN
# OSC_TEST_PASSWORD

if [ -z "$OSC_TEST_LOGIN" ]; then
    echo "error, OSC_TEST_LOGIN must be set"
    exit 1
fi
if [ -z "$OSC_TEST_PASSWORD" ]; then
    echo "error, OSC_TEST_PASSWORD must be set"
    exit 1
fi

function clean_tmp() {
    rm -rf /tmp/osc-cli_* || true
}

function bad_tmp_file() {
    filepath="/tmp/osc-cli_$(id -u)_default.json"
    echo '{"access_key":"bad_ak", "secret_key":"bad_sk", "expiration_date":"2077/01/01"}' > $filepath
}

# Testing bad temp files

# Should fail
clean_tmp
$c api ReadNets --authentication-method=ephemeral &> /dev/null && { echo "API error 1"; exit 1; }

# Should fail
bad_tmp_file
$c api ReadNets --authentication-method=ephemeral &> /dev/null && { echo "API error 2"; exit 1; }

# Should fail and retry with success as login and password are provided
bad_tmp_file
sleep 5
$c api ReadNets --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "API error"; exit 1; }
clean_tmp

echo "OK"
