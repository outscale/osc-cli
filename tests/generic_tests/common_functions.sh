function setup_no_configuration_file {
    rm -rf ~/.osc/config.json
    rm -rf ~/.osc_sdk/config.json
}

function setup_osc_config_file_accesskey {
    setup_no_configuration_file

    if [ -z "$OSC_TEST_ACCESS_KEY" ]; then
    echo "OSC_TEST_ACCESS_KEY not set, aborting"
    exit 1
    fi

    if [ -z "$OSC_TEST_SECRET_KEY" ]; then
        echo "OSC_TEST_SECRET_KEY not set, aborting"
        exit 1
    fi

    if [ -z "$OSC_TEST_REGION" ]; then
        echo "OSC_TEST_REGION not set, aborting"
        exit 1
    fi

    mkdir -p ~/.osc/
    cat <<EOF > ~/.osc/config.json
    {
        "default": {
            "access_key": "$OSC_TEST_ACCESS_KEY",
            "secret_key": "$OSC_TEST_SECRET_KEY",
            "protocol": "https",
            "method": "POST",
            "region": "$OSC_TEST_REGION"
        }
    }
EOF
}

function setup_osc_config_file_no_auth {
    setup_no_configuration_file

    if [ -z "$OSC_TEST_REGION" ]; then
        echo "OSC_TEST_REGION not set, aborting"
        exit 1
    fi

    mkdir -p ~/.osc/
    cat <<EOF > ~/.osc/config.json
    {
        "default": {
            "protocol": "https",
            "method": "POST",
            "region": "$OSC_TEST_REGION"
        }
    }
EOF
}

function try_hard {
    local cmd
    local result
    cmd=$@
    result="unknown"
    cnt=0
    while true; do
        set +e
        $cmd
        result=$?
        set -e
	if [[ $cnt > 99 ]]; then
	    echo "'$@' fail after $cnt retry"
	    exit 1
	fi

        if [[ "$result" == "0" ]]; then
            break
        fi
        sleep $(( $RANDOM % 10 + 1 ))
	cnt=$((cnt + 1))
    done
}
