#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

# Test one simple call on each service
$c api ReadNets &> /dev/null || { echo "API error"; exit 1; }
$c fcu DescribeVpcs &> /dev/null || { echo "API error"; exit 1; }
$c lbu DescribeLoadBalancers &> /dev/null || { echo "LBU error"; exit 1; }
$c eim ListServerCertificates &> /dev/null || { echo "EIM error"; exit 1; }
$c icu ReadQuotas &> /dev/null || { echo "ICU error"; exit 1; }
$c directlink DescribeConnections &> /dev/null || { echo "DirectLink error"; exit 1; }

echo "OK"
