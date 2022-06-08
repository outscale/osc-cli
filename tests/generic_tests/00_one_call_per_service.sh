#!/bin/bash
set -e
source common_functions.sh

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"

echo -n "$(basename $0): "

setup_osc_config_file_accesskey

# Test simple calls on each service (preferably with mandatory arguments)
name="osc-cli-test-${RANDOM}${RANDOM}${RANDOM}"

$c api CreateKeypair --KeypairName $name &> /dev/null || { echo "API error (keypair creation)"; exit 1; }
$c api DeleteKeypair --KeypairName $name &> /dev/null || { echo "API error (keypair deletion)"; exit 1; }

$c fcu CreateKeyPair --KeyName $name &> /dev/null || { echo "FCU error (keypair creation)"; exit 1; }
$c fcu DeleteKeyPair --KeyName $name &> /dev/null || { echo "FCU error (keypair deletion)"; exit 1; }

$c lbu CreateLoadBalancer --LoadBalancerName $name --Listeners '[{"Protocol":"HTTP", "LoadBalancerPort":"80", "InstanceProtocol":"HTTP", "InstancePort":"80"}]' --AvailabilityZones '["eu-west-2a"]' &> /dev/null || { echo "LBU error (load balancer creation)"; exit 1; }
$c lbu DeleteLoadBalancer --LoadBalancerName $name &> /dev/null || { echo "LBU error (load balancer deletion)"; exit 1; }

try_hard $c eim CreateUser --UserName $name &> /dev/null || { echo "EIM error (user creation)"; exit 1; }
try_hard $c eim DeleteUser --UserName $name &> /dev/null || { echo "EIM error (user deletion)"; exit 1; }

try_hard $c icu ReadConsumptionAccount --FromDate 2021-06-01 --ToDate 2021-06-02 &> /dev/null || { echo "ICU error (consumption reading)"; exit 1; }

$c directlink DescribeConnections &> /dev/null || { echo "DirectLink error (connection reading)"; exit 1; }

echo "OK"
