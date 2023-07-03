#!/bin/bash
set -e
source common_functions.sh

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/../.." && pwd)
cd $PROJECT_ROOT
c="python osc_sdk/sdk.py"


echo -n "$(basename $0): "

# All calls must fail with a bad auth method even if accesskey method is available
if [ -z "$OSC_TEST_LOGIN" ]; then
    echo "error, OSC_TEST_LOGIN must be set"
    exit 1
fi
if [ -z "$OSC_TEST_PASSWORD" ]; then
    echo "error, OSC_TEST_PASSWORD must be set"
    exit 1
fi

setup_osc_config_file_accesskey

# Test password auth
try_hard $c icu $ENDPOINT_CLI_ARG ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "login auth check error 1"; exit 1; }
$c icu $ENDPOINT_CLI_ARG ListAccessKeys --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null && { echo "login auth check error 2"; exit 1; }
# Test accesskey auth
$c api $ENDPOINT_CLI_ARG ReadVolumes --authentication-method=accesskey &> /dev/null || { echo "accesskey auth check error"; exit 1; }

# On Outscale API $ENDPOINT_CLI_ARG, calls which do not require authentication also succeed when authenticated.
$c api $ENDPOINT_CLI_ARG ReadRegions --authentication-method=accesskey &> /dev/null || { echo "api:ReadRegion error 1"; exit 1; }
$c api $ENDPOINT_CLI_ARG ReadRegions --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "api:ReadRegion error 2"; exit 1; }
$c api $ENDPOINT_CLI_ARG ReadRegions --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null || { echo "api:ReadRegion error 3"; exit 1; }
# Bad auth method should still be refused by cli
$c api $ENDPOINT_CLI_ARG ReadRegions --authentication-method=bad &> /dev/null && { echo "api:ReadRegion error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c api $ENDPOINT_CLI_ARG ReadRegions --authentication-method=none &> /dev/null || { echo "api:ReadRegion error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c api $ENDPOINT_CLI_ARG ReadVolumes --authentication-method=none &> /dev/null && { echo "api:ReadVolumes error 6"; exit 1; }
# Should default to authentication-method=none
$c api $ENDPOINT_CLI_ARG ReadRegions &> /dev/null || { echo "api:ReadRegion error 7"; exit 1; }

# On ICU $ENDPOINT_CLI_ARG, calls which do not require authentication also succeed when authenticated.
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog --authentication-method=accesskey &> /dev/null || { echo "icu:ReadPublicCatalog error 1"; exit 1; }
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "icu:ReadPublicCatalog error 2"; exit 1; }
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null || { echo "icu:ReadPublicCatalog error 3"; exit 1; }
# Bad auth method should still be refused by cli
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog --authentication-method=bad &> /dev/null && { echo "icu:ReadPublicCatalog error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog --authentication-method=none &> /dev/null || { echo "icu:ReadPublicCatalog error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c icu $ENDPOINT_CLI_ARG GetAccount --authentication-method=none &> /dev/null && { echo "icu:GetAccount error 6"; exit 1; }
# Should default to authentication-method=none
$c icu $ENDPOINT_CLI_ARG ReadPublicCatalog &> /dev/null || { echo "icu:ReadPublicCatalog error 7"; exit 1; }

# On FCU $ENDPOINT_CLI_ARG, calls which do not require authentication also succeed when authenticated.
$c fcu $ENDPOINT_CLI_ARG DescribeRegions --authentication-method=accesskey &> /dev/null || { echo "fcu:DescribeRegions error 1"; exit 1; }
# On FCU $ENDPOINT_CLI_ARG, this kind call should not work with password authentication.

if [ -z "$OSC_TEST_USING_RICOCHET" ]; then
    $c fcu $ENDPOINT_CLI_ARG DescribeRegions --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "fcu:DescribeRegions error 2"; exit 1; }
    $c fcu $ENDPOINT_CLI_ARG DescribeRegions --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null && { echo "fcu:DescribeRegions error 3"; exit 1; }
fi

# Bad auth method should still be refused by cli
$c fcu $ENDPOINT_CLI_ARG DescribeRegions --authentication-method=bad &> /dev/null && { echo "fcu:DescribeRegions error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c fcu $ENDPOINT_CLI_ARG DescribeRegions --authentication-method=none &> /dev/null || { echo "fcu:DescribeRegions error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c fcu $ENDPOINT_CLI_ARG DescribeVolumes --authentication-method=none &> /dev/null && { echo "fcu: DescribeVolumes error 6"; exit 1; }
# Should default to authentication-method=none
$c fcu $ENDPOINT_CLI_ARG DescribeRegions &> /dev/null || { echo "fcu DescribeRegions error 7"; exit 1; }

echo "OK"
