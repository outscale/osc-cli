#!/bin/bash
set -e
echo -n "$(basename $0): "

if [[ "$OSTYPE" == "darwin"* ]]; then
    ssl_engine="/usr/local/Cellar/libp11/0.4.11/lib/engines-1.1/pkcs11.dylib"
    module="/usr/local/Cellar/yubico-piv-tool/2.2.0/lib/libykcs11.dylib"
    openssl="/usr/local/Cellar/openssl@1.1/1.1.1k/bin/openssl"
elif [[ "$OSTYPE" == "linux"* ]]; then
    ssl_engine="/usr/lib/x86_64-linux-gnu/engines-1.1/pkcs11.so"
    module="/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
    openssl="openssl"
fi
token_label="osc-test-token"
rsa_label="osc.key"
cert_label="osc.cert"
pin="0000"

# Test SoftHSMv2
softhsm2-util --version &> /dev/null || { echo "softhsm2-util not found"; exit 1; }

# Clean existing SoftHSMv2 token
softhsm2-util --delete-token --token $token_label &> /dev/null || true
softhsm2-util --init-token --pin ${pin} --so-pin 1234 --free --label $token_label &> /dev/null || { echo "Cannot initialize SoftHSM token"; exit 1; }

# Test pkcs11-tool
pkcs11-tool --test --module $module &> /dev/null || { echo "pkcs11-tool --test failed"; exit 1; }

# Test openssl
$openssl help &> /dev/null || { echo "openssl not found"; exit 1;}

# Generate RSA key on smartcard
pkcs11-tool --module $module --keypairgen --key-type rsa:2048 --usage-sign --login --pin ${pin} --token-label $token_label --label $rsa_label &> /dev/null || { echo "Cannot create RSA key"; exit 1; }

# Test engine
$openssl engine -t -c pkcs11 &> /dev/null || { echo "pkcs11 engine not available to openssl"; exit 1; }

# Generate cert
$openssl req -new -x509 -out osc.crt -days 365 -addext basicConstraints=critical,CA:TRUE,pathlen:1 -subj "/CN=OSC-TEST-CA" -engine pkcs11 -keyform engine -key "pkcs11:token=${token_label};object=${rsa_label};pin-value=${pin}" &> /dev/null || { echo "Cannot create openssl cert"; exit 1; }

# Convert to der format
$openssl x509 -inform pem -outform der -in osc.crt -out osc.crt.der &> /dev/null || { echo "Cannot convert to der format"; exit 1; }

# Send der to smartcard
pkcs11-tool --module $module --write-object osc.crt.der --type cert --token-label $token_label --label $cert_label &> /dev/null || { echo "Cannot write certificate to smartcard"; exit 1; }

# Clean files
rm -rf osc.crt osc.crt.der

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
	\"x509_client_cert\": \"pkcs11:token=${token_label};type=cert;object=${cert_label}\",
	\"x509_client_key\": \"pkcs11:token=${token_label};type=private;object=${rsa_label};pin-value=${pin}\",
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
