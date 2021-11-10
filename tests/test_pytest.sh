#!/bin/bash
set -e
echo -n "$(basename $0)... "

PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
. .venv/bin/activate
pytest osc_sdk &> /dev/null
echo "OK"
