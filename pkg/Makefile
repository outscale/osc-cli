include config.mk

all: osc-cli-x86_64.AppImage osc-cli-x86_64.zip

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

osc-cli-x86_64.zip: osc-cli
	zip -r osc-cli-x86_64.zip osc-cli

osc-cli:
	$(SUDO) docker run --rm -v ${PWD}/..:/src outscale/wine-pyinstaller:0.0.1 --distpath ./pkg --clean --name osc-cli osc_sdk/sdk.py

clean:
	rm -rvf *AppImage* osc-cli.AppDir osc-cli.zip osc-cli

.PHONY: clean all
