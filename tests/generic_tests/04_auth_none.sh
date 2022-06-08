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
$c icu ListAccessKeys --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "login auth check error 1"; exit 1; }
$c icu ListAccessKeys --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null && { echo "login auth check error 2"; exit 1; }
# Test accesskey auth
$c api ReadVolumes --authentication-method=accesskey &> /dev/null || { echo "accesskey auth check error"; exit 1; }

# On Outscale API, calls which do not require authentication also succeed when authenticated.
$c api ReadRegions --authentication-method=accesskey &> /dev/null || { echo "api:ReadRegion error 1"; exit 1; }
$c api ReadRegions --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "api:ReadRegion error 2"; exit 1; }
$c api ReadRegions --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null || { echo "api:ReadRegion error 3"; exit 1; }
# Bad auth method should still be refused by cli
$c api ReadRegions --authentication-method=bad &> /dev/null && { echo "api:ReadRegion error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c api ReadRegions --authentication-method=none &> /dev/null || { echo "api:ReadRegion error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c api ReadVolumes --authentication-method=none &> /dev/null && { echo "api:ReadVolumes error 6"; exit 1; }
# Should default to authentication-method=none
$c api ReadRegions &> /dev/null || { echo "api:ReadRegion error 7"; exit 1; }

# On ICU, calls which do not require authentication also succeed when authenticated.
$c icu ReadPublicCatalog --authentication-method=accesskey &> /dev/null || { echo "icu:ReadPublicCatalog error 1"; exit 1; }
$c icu ReadPublicCatalog --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null || { echo "icu:ReadPublicCatalog error 2"; exit 1; }
$c icu ReadPublicCatalog --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null || { echo "icu:ReadPublicCatalog error 3"; exit 1; }
# Bad auth method should still be refused by cli
$c icu ReadPublicCatalog --authentication-method=bad &> /dev/null && { echo "icu:ReadPublicCatalog error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c icu ReadPublicCatalog --authentication-method=none &> /dev/null || { echo "icu:ReadPublicCatalog error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c icu GetAccount --authentication-method=none &> /dev/null && { echo "icu:GetAccount error 6"; exit 1; }
# Should default to authentication-method=none
$c icu ReadPublicCatalog &> /dev/null || { echo "icu:ReadPublicCatalog error 7"; exit 1; }

# On FCU, calls which do not require authentication also succeed when authenticated.
$c fcu DescribeRegions --authentication-method=accesskey &> /dev/null || { echo "fcu:DescribeRegions error 1"; exit 1; }
# On FCU, this kind call should not work with password authentication.
$c fcu DescribeRegions --authentication-method=password --login "$OSC_TEST_LOGIN" --password "$OSC_TEST_PASSWORD" &> /dev/null && { echo "fcu:DescribeRegions error 2"; exit 1; }
$c fcu DescribeRegions --authentication-method=password --login "BAD_LOGIN" --password "BAD_PASSWORD" &> /dev/null && { echo "fcu:DescribeRegions error 3"; exit 1; }
# Bad auth method should still be refused by cli
$c fcu DescribeRegions --authentication-method=bad &> /dev/null && { echo "fcu:DescribeRegions error 4"; exit 1; }
# Explicitly ignore authentication for non auth call
$c fcu DescribeRegions --authentication-method=none &> /dev/null || { echo "fcu:DescribeRegions error 5"; exit 1; }
# Explicitly ignore authentication for auth call
$c fcu DescribeVolumes --authentication-method=none &> /dev/null && { echo "fcu:DescribeVolumes error 6"; exit 1; }
# Should default to authentication-method=none
$c fcu DescribeRegions &> /dev/null || { echo "fcu:DescribeRegions error 7"; exit 1; }

echo "OK"
