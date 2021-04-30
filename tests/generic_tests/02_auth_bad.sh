#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

# All calls must fail with a bad auth method even if accesskey method is available
$c api ReadNets --authentication-method=accesskey &> /dev/null || { echo "Control error"; exit 1; }

set -e
$c api ReadNets --authentication-method=bad &> /dev/null && { echo "API error"; exit 1; }
$c fcu DescribeVpcs --authentication-method=bad &> /dev/null && { echo "API error"; exit 1; }
$c lbu DescribeLoadBalancers --authentication-method=bad &> /dev/null && { echo "LBU error"; exit 1; }
$c eim ListServerCertificates --authentication-method=bad &> /dev/null && { echo "EIM error"; exit 1; }
sleep 5
$c icu ReadQuotas --authentication-method=bad &> /dev/null && { echo "ICU error"; exit 1; }
$c directlink DescribeConnections --authentication-method=bad &> /dev/null && { echo "DirectLink error"; exit 1; }

echo "OK"
