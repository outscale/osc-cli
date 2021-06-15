# Osc-cli on Microsoft Windows

- Install python:
  - Go to [python website](https://www.python.org/downloads/)
  - Download latest python installer
  - Start installer and check "Add Python 3.x to PATH"
  - Select default installation
  - Once installed, click on "Disable path length limit"
  - For more details, see [how to use python on windows](https://docs.python.org/3.9/using/windows.html)

- Install osc-cli:
  - Start a Windows cmd prompt
  - run `pip install --upgrade pip`
  - run `pip install osc-sdk`

- Setup your credentials:
  - As you are in your cmd prompt, you should see `C:\Users\YOUR_USER>`
  - type `mkdir .osc_sdk`
  - In Windows Explorer, go to `C:\Users\YOUR_USER\.osc_sdk`
  - Import [`config.json`](https://github.com/outscale/osc-cli/blob/0f54e6ee0e17df7af4fc22d2fd29cd21825ddd0d/osc_sdk/config.json) in that folder (be sure to name the file `config.json` and not `config.json.txt`)
  - Edit `config.json` and setup your credentials
  
- Run osc-cli:
  - Open a Windows cmd prompt
  - You should now be able to run `osc-cli` (e.g. `osc-cli api ReadVolumes`)
