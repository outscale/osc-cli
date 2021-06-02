#!/bin/bash
set -e
echo -n "$(basename $0): "

if [[ "$OSTYPE" == "darwin"* ]]; then
    ssl_engine="/usr/local/Cellar/libp11/0.4.11/lib/engines-1.1/pkcs11.dylib"
    module="/usr/local/Cellar/yubico-piv-tool/2.2.0/lib/libykcs11.dylib"
elif [[ "$OSTYPE" == "linux"* ]]; then
    ssl_engine="/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so"
    module="/usr/lib/x86_64-linux-gnu/libykcs11.so.2.2.0"
fi
pin="123456"

# Test ykman
ykman --help &> /dev/null || { echo "ykman not found"; exit 1; }

# Reset token with default credentials
ykman piv reset -f &> /dev/null || { echo "Cannot reset yubikey"; exit 1; }

# Test yubico-piv-tool
yubico-piv-tool --help &> /dev/null || { echo "yubico-piv-tool not found"; exit 1; }

# Reset token with default credentials
ykman piv reset -f &> /dev/null || { echo "Cannot reset yubikey"; exit 1; }

# Generate private key
yubico-piv-tool -s 9a -a generate -o public.pem &> /dev/null || { echo "Cannot generate private key"; exit 1; }

# Generate certificate
yubico-piv-tool -a verify-pin -a selfsign-certificate -s 9a -S "/CN=SSH key/" -i public.pem -o cert.pem --pin=$pin &> /dev/null || { echo "Cannot generate certificate"; exit 1; }

# Upload certificate
yubico-piv-tool -a import-certificate -s 9a -i cert.pem &> /dev/null || { echo "Cannot upload certificate"; exit 1; }

# Generate configuration
rm -rf ~/.osc
mkdir -p ~/.osc
echo -n "
{
    \"default\": {
	\"access_key\": \"${OSC_TEST_ACCESS_KEY}\",
	\"secret_key\": \"${OSC_TEST_SECRET_KEY}\",
	\"ssl_engine_id\": \"pkcs11\",
	\"ssl_engine_path\": \"${ssl_engine}\",
	\"ssl_module_path\": \"${module}\",
	\"x509_client_cert\": \"pkcs11:type=cert;id=%01\",
	\"x509_client_key\": \"pkcs11:type=private;id=%01;pin-value=${pin}\",
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
