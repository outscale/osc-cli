#!/bin/sh

source ./config.sh

echo "$1()" >> osc-cli-completion.calls
echo "{" >> osc-cli-completion.calls
echo -n "    COMPREPLY=(\$(compgen -W \"" >> osc-cli-completion.calls
JSON_SEARCH ${1}Request osc-api.json | JSON_SEARCH -K properties | tr -d "\n[],\"" | sed 's/  / --/g' >> osc-cli-completion.calls
echo "\" -- \${cur}))" >> osc-cli-completion.calls
echo "}" >> osc-cli-completion.calls
