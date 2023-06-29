#!/bin/bash
set -e
source common_functions.sh

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

setup_osc_config_file_accesskey

# Listing Access Keys through ICU should succeed with password method

try_hard $c icu $ENDPOINT_CLI_ARG ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "error, cannot list access keys on ICU with password method"; exit 1; }

# Listing Access Keys through Outscale API $ENDPOINT_CLI_ARG should succeed with password method
try_hard $c api $ENDPOINT_CLI_ARG ReadAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "error, cannot list access keys on Outsacale API with password method"; exit 1; }

# Should fail without password
$c icu $ENDPOINT_CLI_ARG ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" &> /dev/null && { echo "error, can read access keys without password"; exit 1; }
$c api $ENDPOINT_CLI_ARG ReadAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" &> /dev/null && { echo "error, can read access keys without password"; exit 1; }

# Should fail without login
$c icu $ENDPOINT_CLI_ARG ListAccessKeys --authentication-method=password --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read access keys without login"; exit 1; }
$c api $ENDPOINT_CLI_ARG ReadAccessKeys --authentication-method=password --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read access keys without login"; exit 1; }

# Listing ICU $ENDPOINT_CLI_ARG quota should succeed with access keys
try_hard $c icu $ENDPOINT_CLI_ARG ReadQuotas --authentication-method=accesskey &> /dev/null || { echo "error, cannot read quota on ICU  with accesskey method"; exit 1; }

# Listing ICU $ENDPOINT_CLI_ARG quota with password method should fail
$c icu $ENDPOINT_CLI_ARG ReadQuotas --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "error, can read quota with password method"; exit 1; }

echo "OK"
