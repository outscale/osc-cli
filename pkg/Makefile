include config.mk

all: osc-cli-x86_64.AppImage osc-cli-x86_64.zip osc-cli-completion.bash

config.mk:
	$(if $(wildcard $@),,@echo "auto run ./configure. to create default conf" && sleep 2 && ./configure)

$(PY_TARGET):
	wget https://github.com/niess/python-appimage/releases/download/$(PY_STR)/$(PY_TARGET)
	chmod +x ./$(PY_TARGET)

osc-cli.AppDir/done: $(PY_TARGET)
	./$(PY_TARGET) --appimage-extract
	mv squashfs-root osc-cli.AppDir
	rm osc-cli.AppDir/usr/bin/python3.9
	cd osc-cli.AppDir/usr/bin/ && ln -s ../../opt/python3.9/bin/python3.9 python3.9
	cp linux/AppRun-py osc-cli.AppDir/AppRun-py
	cd .. && APPDIR=$${PWD}/pkg/osc-cli.AppDir/ ./pkg/osc-cli.AppDir/AppRun-py ./setup.py install --prefix=./pkg/osc-cli.AppDir/opt/$(PY_STR)/ --optimize=1
	cd osc-cli.AppDir/ && \
	for package in requests charset-normalizer urllib3 defusedxml fire xmltodict termcolor idna typing_extensions ; do  \
	PIP_CONFIG_FILE=/dev/null usr/bin/pip$(PY_VER) install --isolated --root="" --ignore-installed --no-deps $${package} \
	; done
	rm osc-cli.AppDir/$(PY_STR).$(PY_MIN).desktop
	cp linux/osc-cli.desktop osc-cli.AppDir/
	echo 'export PY_VERSION=$(PY_VER)' > osc-cli.AppDir/py_version.sh
	echo 'export PY_STR=$(PY_STR)' >> osc-cli.AppDir/py_version.sh
	rm osc-cli.AppDir/AppRun
	cp linux/AppRun osc-cli.AppDir/
	chmod +x osc-cli.AppDir/AppRun
	touch osc-cli.AppDir/done


appimagetool-x86_64.AppImage:
	wget https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage
	chmod +x appimagetool-x86_64.AppImage

osc-cli-x86_64.AppImage:  osc-cli.AppDir/done appimagetool-x86_64.AppImage
	./appimagetool-x86_64.AppImage osc-cli.AppDir/

osc-api.json:
	curl -s https://raw.githubusercontent.com/outscale/osc-api/master/outscale.yaml | yq $(YQ_ARG) > osc-api.json

osc-cli-completion.call_list: osc-api.json
	$(JSON_SEARCH) operationId osc-api.json | tr -d "\n[]\"" | sed 's/,/ /g' >> osc-cli-completion.call_list

config.sh:
	echo alias JSON_SEARCH=$(JSON_SEARCH) > config.sh

osc-cli-completion.calls: config.sh
	echo "" > osc-cli-completion.calls
	cat osc-cli-completion.call_list | sed 's/ /\n/g' | xargs -I {} ./mk_functions.sh {}

osc-cli-completion.bash: osc-api.json osc-cli-completion.call_list osc-cli-completion.calls fcu.call_list osc-cli-completion-fcu.calls osc-cli-completion.bash-0 osc-cli-completion.bash-2
	echo '#/usr/bin/env bash' > osc-cli-completion.bash
	echo '# OUTSCALE API' >> osc-cli-completion.bash
	cat osc-cli-completion.calls >> osc-cli-completion.bash
	echo '# OUTSCALE FCU' >> osc-cli-completion.bash
	cat osc-cli-completion-fcu.calls >> osc-cli-completion.bash
	cat osc-cli-completion.bash-0 >> osc-cli-completion.bash
	cat osc-cli-completion.call_list >> osc-cli-completion.bash
	echo -e '" -- $${cur}))'"\n\t;;" >> osc-cli-completion.bash
	echo -ne 'fcu)\nCOMPREPLY=($$(compgen -W ' >> osc-cli-completion.bash
	echo -e "\"$$(cat fcu.call_list)\" -- \$${cur}))\n;;\n" >> osc-cli-completion.bash
	echo "$$(cat fcu.call_list | sed 's/ / | /g'))" >> osc-cli-completion.bash
	echo -e 'eval $${prev}\n;;' >> osc-cli-completion.bash
	cat osc-cli-completion.call_list | sed 's/ / | /g' >> osc-cli-completion.bash
	cat osc-cli-completion.bash-2 >> osc-cli-completion.bash

clean:
	rm -rvf appimagetool-x86_64.AppImage osc-cli-x86_64.AppImage python*AppImage\
		osc-cli.AppDir  osc-cli-completion.bash\
		osc-cli-completion.call_list \
		osc-cli-completion.calls osc-api.json config.sh

.PHONY: clean all
