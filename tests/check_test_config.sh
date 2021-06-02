#!/bin/bash
set -e

incomplete=false

# Note: would be better to use -v to test if variable is set
# but this feature is available on bash >= 4.2 which is not available on macOS. 

echo -n "OSC_TEST_LOGIN: "
if [ -z "$OSC_TEST_LOGIN" ] || [[ "$OSC_TEST_LOGIN" == "user@domain.tld" ]]; then
    echo "KO"
    incomplete=true
else
    echo "OK"
fi

echo -n "OSC_TEST_PASSWORD: "
if [ -z "$OSC_TEST_PASSWORD" ] || [[ "$OSC_TEST_PASSWORD" == "P4ssW0rd" ]]; then
    echo "KO"
    incomplete=true
else
    echo "OK"
fi

echo -n "OSC_TEST_ACCESS_KEY: "
if [ -z "$OSC_TEST_ACCESS_KEY" ] || [[ "$OSC_TEST_ACCESS_KEY" == "S65FD45EXAMPLE" ]]; then
    echo "KO"
    incomplete=true
else
    echo "OK"
fi

echo -n "OSC_TEST_SECRET_KEY: "
if [ -z "$OSC_TEST_SECRET_KEY" ] || [[ "$OSC_TEST_SECRET_KEY" == "54SDFSD5S6D789SF465SF447GS97DEXAMPLE" ]]; then
    echo "KO"
    incomplete=true
else
    echo "OK"
fi

echo -n "OSC_TEST_SMARTCARD_SOFTHSM: "
if [[ "$OSC_TEST_SMARTCARD_SOFTHSM" == "true" ]]; then
    echo "enabled"
elif [[ "$OSC_TEST_SMARTCARD_SOFTHSM" == "false" ]]; then
    echo "disabled"
else
    echo "KO"
    incomplete=true
fi

echo -n "OSC_TEST_SMARTCARD_YUBIKEY: "
if [[ "$OSC_TEST_SMARTCARD_YUBIKEY" == "true" ]]; then
    echo "enabled"
elif [[ "$OSC_TEST_SMARTCARD_YUBIKEY" == "false" ]]; then
    echo "disabled"
else
    echo "KO"
    incomplete=true
fi

if $incomplete; then
   echo "error: incomplete test configuration, check tests/config.env"
   exit 1
fi
