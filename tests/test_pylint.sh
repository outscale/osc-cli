#!/bin/bash
set -e
echo -n "$(basename $0)"

PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
. .venv/bin/activate
pylint --rcfile=$PROJECT_ROOT/tests/pylint_py3.conf osc_sdk

echo "OK"
