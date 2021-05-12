#!/bin/bash
set -e
PROJECT_ROOT=$(cd "$(dirname $0)/.." && pwd)
. $PROJECT_ROOT/.venv/bin/activate

$PROJECT_ROOT/tests/clean_config_files.sh
$PROJECT_ROOT/tests/gen_config_file.sh
cd $PROJECT_ROOT/tests/generic_tests/
for t in *.sh ; do
    ./$t
done

$PROJECT_ROOT/tests/clean_config_files.sh
$PROJECT_ROOT/tests/gen_deprecated_config_file_host.sh
cd $PROJECT_ROOT/tests/generic_tests/
for t in *.sh ; do
    ./$t
done

$PROJECT_ROOT/tests/clean_config_files.sh
