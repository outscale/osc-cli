# Install on Linux (AppImage)

1. Download `osc-cli-x86_64.AppImage` from the latest GitHub release.
2. Make the file executable:
```bash
chmod a+x osc-cli-x86_64.AppImage
```
3. Run it:
```bash
./osc-cli-x86_64.AppImage
```
Optional (system-wide):
```bash
sudo mv osc-cli-x86_64.AppImage /usr/local/bin/osc-cli
osc-cli --version
```

## Arch Linux (AUR)
```bash
yay -S osc-cli-git
```

## FUSE troubleshooting

If you see errors like:
```
fuse: failed to exec fusermount: No such file or directory
Cannot mount AppImage, please check your FUSE setup.
```
Install FUSE for your distribution, or use the slower fallback:
```bash
./osc-cli-x86_64.AppImage --appimage-extract-and-run osc-cli api ReadImages --profile=my
```
