#!/bin/bash
set -e
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT
. .venv/bin/activate
cd $PROJECT_ROOT/tests/generic_tests/

for t in *.sh ; do
    ./$t
done
