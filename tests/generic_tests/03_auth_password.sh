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

# slow down to avoid bruteforce protection
sleep 5
# Listing Access Keys through ICU should succeed with password method
$c icu ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "error, cannot list access keys on ICU with password method"; exit 1; }

sleep 5
# Listing Access Keys through Outscale API should succeed with password method
$c api ReadAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "error, cannot list access keys on Outsacale API with password method"; exit 1; }

sleep 5
# Should fail without password
$c icu ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" &> /dev/null && { echo "error, can read access keys without password"; exit 1; }
sleep 5
$c api ReadAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" &> /dev/null && { echo "error, can read access keys without password"; exit 1; }

sleep 5
# Should fail without login
$c icu ListAccessKeys --authentication-method=password --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read access keys without login"; exit 1; }
sleep 5
$c api ReadAccessKeys --authentication-method=password --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read access keys without login"; exit 1; }

sleep 5
# Listing ICU quota should succeed with access keys
$c icu ReadQuotas --authentication-method=accesskey &> /dev/null || { echo "error, cannot read quota on ICU with accesskey method"; exit 1; }

sleep 5
# Listing ICU quota with password method should fail
$c icu ReadQuotas --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read quota with password method"; exit 1; }

echo "OK"
