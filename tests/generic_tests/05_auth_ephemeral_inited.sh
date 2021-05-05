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

# One-time init tmp auth file then run simple test on all API
clean_tmp
sleep 5
$c api ReadNets --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "Init error"; exit 1; }

$c api ReadNets --authentication-method=ephemeral &> /dev/null || { echo "API error"; exit 1; }
$c fcu DescribeVpcs --authentication-method=ephemeral &> /dev/null || { echo "FCU error"; exit 1; }
$c lbu DescribeLoadBalancers --authentication-method=ephemeral &> /dev/null || { echo "LBU error"; exit 1; }
$c eim ListServerCertificates --authentication-method=ephemeral &> /dev/null || { echo "EIM error"; exit 1; }
sleep 3
$c icu ReadQuotas --authentication-method=ephemeral &> /dev/null || { echo "ICU error"; exit 1; }
$c directlink DescribeConnections --authentication-method=ephemeral &> /dev/null || { echo "DirectLink error"; exit 1; }
clean_tmp

echo "OK"
