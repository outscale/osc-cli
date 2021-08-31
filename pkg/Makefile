# either 1, 2010 or 2014
WHICH_LINUX=2010

# go https://github.com/niess/python-appimage/releases for the list
PY_MAJ=3
PY_MID=9
PY_MIN=6
PY_VER=$(PY_MAJ).$(PY_MID)
PY_CP=cp$(PY_MAJ)$(PY_MID)
PY_STR=python$(PY_VER)
PY_TARGET="$(PY_STR).$(PY_MIN)-$(PY_CP)-$(PY_CP)-manylinux$(WHICH_LINUX)_x86_64.AppImage"

all: osc-cli-x86_64.AppImage osc-cli-x86_64.zip

$(PY_TARGET):
	wget https://github.com/niess/python-appimage/releases/download/$(PY_STR)/$(PY_TARGET)
	chmod +x ./$(PY_TARGET)

osc-cli.AppDir/: $(PY_TARGET)
	./$(PY_TARGET) --appimage-extract
	mv squashfs-root osc-cli.AppDir

osc-cli.AppDir/AppRun-py: osc-cli.AppDir/ $(PY_TARGET)
	cp osc-cli.AppDir/AppRun osc-cli.AppDir/AppRun-py

osc-cli.AppDir/AppRun: osc-cli.AppDir/ $(PY_TARGET) osc-cli.AppDir/AppRun-py
	cp linux/AppRun osc-cli.AppDir/

osc-cli.AppDir/done:
	cd .. && pkg/osc-cli.AppDir/AppRun-py ./setup.py install --prefix=./pkg/osc-cli.AppDir/opt/$(PY_STR)/ --optimize=1
	cd osc-cli.AppDir/ && \
	for package in requests charset-normalizer urllib3 defusedxml fire xmltodict termcolor idna ; do  \
	PIP_CONFIG_FILE=/dev/null usr/bin/pip$(PY_VER) install --isolated --root="" --ignore-installed --no-deps $${package} \
	; done
	rm osc-cli.AppDir/$(PY_STR).$(PY_MIN).desktop
	cp linux/osc-cli.desktop osc-cli.AppDir/
	echo 'export PY_VERSION=$(PY_VER)' > osc-cli.AppDir/py_version.sh
	echo 'export PY_STR=$(PY_STR)' >> osc-cli.AppDir/py_version.sh
	touch osc-cli.AppDir/done


appimagetool-x86_64.AppImage:
	wget https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage
	chmod +x appimagetool-x86_64.AppImage

osc-cli-x86_64.AppImage: osc-cli.AppDir/AppRun osc-cli.AppDir osc-cli.AppDir/done appimagetool-x86_64.AppImage $(PY_TARGET)
	./appimagetool-x86_64.AppImage osc-cli.AppDir/

osc-cli-x86_64.zip: osc-cli
	zip -r osc-cli-x86_64.zip osc-cli

osc-cli:
	docker run --rm -it -v ${PWD}/..:/src outscale/wine-pyinstaller:0.0.1 --distpath ./pkg --clean --name osc-cli osc_sdk/sdk.py

clean:
	rm -rvf *AppImage* osc-cli.AppDir osc-cli.zip osc-cli
