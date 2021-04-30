#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

# Test one simple call on each service with explicit access key
$c api ReadNets --authentication-method=accesskey &> /dev/null || { echo "API error"; exit 1; }
$c fcu DescribeVpcs --authentication-method=accesskey &> /dev/null || { echo "FCU error"; exit 1; }
$c lbu DescribeLoadBalancers --authentication-method=accesskey &> /dev/null || { echo "LBU error"; exit 1; }
$c eim ListServerCertificates --authentication-method=accesskey &> /dev/null || { echo "EIM error"; exit 1; }
sleep 5
$c icu ReadQuotas --authentication-method=accesskey &> /dev/null || { echo "ICU error"; exit 1; }
$c directlink DescribeConnections --authentication-method=accesskey &> /dev/null || { echo "DirectLink error"; exit 1; }

echo "OK"
