#!/bin/bash
set -e
echo -n "$(basename $0): "
rm -rf ~/.osc_sdk
mkdir -p ~/.osc_sdk

# using "host" and not "endpoint"
echo -n "
{\"default\":
    {\"access_key\": \"${OSC_TEST_ACCESS_KEY}\",
     \"secret_key\": \"${OSC_TEST_SECRET_KEY}\",
     \"host\": \"outscale.com\",
     \"https\": true,
     \"method\": \"POST\",
     \"region_name\": \"eu-west-2\",
     \"version\": \"2018-11-19\"
    }
}" > ~/.osc_sdk/config.json
echo "OK"
