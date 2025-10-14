# Shell completion (bash)

Activate for the current shell:
```bash
source <(osc-cli --bash_completion)
```

Persist it:
```bash
osc-cli --bash_completion > ~/.osc/cli-completion.bash
# then in your ~/.bashrc
source ~/.osc/cli-completion.bash
```
