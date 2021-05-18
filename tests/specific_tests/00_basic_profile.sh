#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

$PROJECT_ROOT/tests/clean_config_files.sh
$PROJECT_ROOT/tests/gen_config_file_profile.sh

echo -n "$(basename $0): "

p="--profile my-profile"

# Test one simple call on each service with specific profile
$c $p api ReadNets &> /dev/null || { echo "API error"; exit 1; }
$c $p fcu DescribeVpcs &> /dev/null || { echo "FCU error"; exit 1; }
$c $p lbu DescribeLoadBalancers &> /dev/null || { echo "LBU error"; exit 1; }
$c $p eim ListServerCertificates &> /dev/null || { echo "EIM error"; exit 1; }
sleep 5
$c $p icu ReadQuotas &> /dev/null || { echo "ICU error"; exit 1; }
$c $p directlink DescribeConnections &> /dev/null || { echo "DirectLink error"; exit 1; }

echo "OK"
