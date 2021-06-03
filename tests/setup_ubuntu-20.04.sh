#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT

echo -n "$(basename $0)"
sudo apt-get update -y
sudo apt-get install -y opensc libengine-pkcs11-openssl swig python3-dev libssl-dev softhsm
sudo usermod -a -G softhsm $(whoami)
newgrp softhsm
echo "OK"
