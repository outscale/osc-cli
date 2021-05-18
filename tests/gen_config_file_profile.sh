#!/bin/bash
set -e
echo -n "$(basename $0): "
rm -rf ~/.osc
mkdir -p ~/.osc
echo -n "
{
    \"my-profile\": {
	\"access_key\": \"${OSC_TEST_ACCESS_KEY}\",
	\"secret_key\": \"${OSC_TEST_SECRET_KEY}\",
	\"protocol\": \"https\",
	\"method\": \"post\",
	\"region\": \"eu-west-2\",
	\"endpoints\": {
	    \"api\": \"api.eu-west-2.outscale.com/api/v1\",
	    \"fcu\": \"fcu.eu-west-2.outscale.com\",
	    \"lbu\": \"lbu.eu-west-2.outscale.com\",
	    \"eim\": \"eim.eu-west-2.outscale.com\",
	    \"icu\": \"icu.eu-west-2.outscale.com\",
	    \"directlink\": \"directlink.eu-west-2.outscale.com\",
	    \"oos\": \"oos.eu-west-2.outscale.com\"
	}
    }
}" > ~/.osc/config.json
echo "OK"
