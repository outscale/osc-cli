# Troubleshooting

## AppImage / FUSE
If you see:
```
fuse: failed to exec fusermount: No such file or directory
Cannot mount AppImage, please check your FUSE setup.
```
Install FUSE or run with:
```bash
./osc-cli-x86_64.AppImage --appimage-extract-and-run osc-cli api ReadImages --profile=my
```

## Common issues
- Permission denied: ensure the AppImage is executable (`chmod a+x ...`).
- Unknown profile: verify `~/.osc/config.json` and the `--profile` name.
- Authentication errors: re-check `access_key`/`secret_key` and region.
