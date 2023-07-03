#!/bin/sh

export OSC_TEST_PASSWORD='ashita wa dochida'
export OSC_TEST_LOGIN=joe
export OSC_TEST_SECRET_KEY=0000001111112222223333334444445555555666
export OSC_TEST_ACCESS_KEY=11112211111110000000

export OSC_SECRET_KEY=0000001111112222223333334444445555555666
export OSC_ACCESS_KEY=11112211111110000000

export ENDPOINT_CLI_ARG="--endpoint http://127.0.0.1:3000"
export OSC_TEST_ENDPOINT_ICU="http://127.0.0.1:3000/icu/"
export OSC_TEST_ENDPOINT_FCU="http://127.0.0.1:3000"
export OSC_TEST_ENDPOINT_API="http://127.0.0.1:3000"
export OSC_TEST_REGION="vp-ware-3"

export OSC_TEST_USING_RICOCHET="oui"

if [ "$#" -eq 0 ]; then

    if [ ! -d "osc-ricochet-2" ]; then
	git clone https://github.com/outscale-mgo/osc-ricochet-2
    fi

    cd osc-ricochet-2
    pkill ricochet

    cargo build
    cargo run -- ./ricochet.json &> /dev/null  &
    cd ..

    sleep 5
fi

set -e

make test-int
