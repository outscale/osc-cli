set -e

# Assuming you are running this from a prepared virtual environment
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
cd $PROJECT_ROOT

echo -n "$(basename $0): "

rm -rf .venv > /dev/null
python3 -m venv .venv > /dev/null
. .venv/bin/activate > /dev/null
python -m pip install --upgrade pip > /dev/null
pip install setuptools wheel twine > /dev/null
pip install -r requirements.txt > /dev/null
touch .venv/ok > /dev/null

echo "OK"
