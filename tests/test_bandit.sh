#!/bin/bash
set -e
echo -n "$(basename $0)"

PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
. .venv/bin/activate
bandit -c $PROJECT_ROOT/tests/bandit.conf -r osc_sdk

echo "OK"
