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

# Simple test but cleaning tmp auth file each time
# Ensure you have at least some quota to run this
clean_tmp
sleep 5
$c api ReadNets --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "API error"; exit 1; }
sleep 5
clean_tmp
$c fcu DescribeVpcs --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "API error"; exit 1; }
sleep 5
clean_tmp
$c lbu DescribeLoadBalancers --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "LBU error"; exit 1; }
sleep 5
clean_tmp
$c eim ListServerCertificates --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "EIM error"; exit 1; }
sleep 5
clean_tmp
$c icu ReadQuotas --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "ICU error"; exit 1; }
sleep 5
clean_tmp
$c directlink DescribeConnections --authentication-method=ephemeral --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "DirectLink error"; exit 1; }
clean_tmp

echo "OK"
