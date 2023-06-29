#!/bin/bash
set -e
source common_functions.sh

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

setup_osc_config_file_accesskey

# Test one simple call on each service with explicit access key
$c api  $ENDPOINT_CLI_ARG ReadNets --authentication-method=accesskey &> /dev/null || { echo "API error"; exit 1; }
$c fcu  $ENDPOINT_CLI_ARG DescribeVpcs --authentication-method=accesskey &> /dev/null || { echo "FCU error"; exit 1; }
$c lbu  $ENDPOINT_CLI_ARG DescribeLoadBalancers --authentication-method=accesskey &> /dev/null || { echo "LBU error"; exit 1; }
try_hard $c eim $ENDPOINT_CLI_ARG ListServerCertificates --authentication-method=accesskey &> /dev/null || { echo "EIM error"; exit 1; }
try_hard $c icu $ENDPOINT_CLI_ARG ReadQuotas --authentication-method=accesskey  &> /dev/null || { echo "ICU error"; exit 1; }
$c directlink $ENDPOINT_CLI_ARG DescribeConnections --authentication-method=accesskey &> /dev/null || { echo "DirectLink error"; exit 1; }

echo "OK"
