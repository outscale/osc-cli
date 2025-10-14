# Usage

Two forms:
```bash
osc-cli SERVICE CALL [PROFILE] [CALL-PARAMETERS]
# or
osc-cli --service SERVICE --call CALL [PROFILE] [--CALL_PARAMS ...]
```

- `SERVICE`: one of OUTSCALE services (e.g., `fcu`, `lbu`, `icu`, `eim`, `directlink`, `okms`, `api`)
- `CALL`: the API action (e.g., `ReadVms`, `CreateVolume`)
- `PROFILE`: optional profile name from your config
- `CALL-PARAMETERS`: case-sensitive action parameters

Quick example:
```bash
osc-cli api ReadVms
```
