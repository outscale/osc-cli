#!/bin/bash
set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT

echo -n "$(basename $0): "

. .venv/bin/activate > /dev/null
pip install setuptools wheel twine > /dev/null
python setup.py sdist bdist_wheel > /dev/null

echo "OK"
