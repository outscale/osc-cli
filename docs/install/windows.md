# osc-cli on Microsoft Windows

This guide explains how to install and configure `osc-cli` on a Windows system.

---

## 1. Install Python

1. Go to the [official Python website](https://www.python.org/downloads/)
2. Download the latest version of Python (3.x)
3. Run the installer:

   * Check **"Add Python 3.x to PATH"**
   * Select **Default Installation**
4. Once installation is complete:

   * Click **"Disable path length limit"** (important for Windows compatibility)

📘 For details, see the [official Python on Windows guide](https://docs.python.org/3/using/windows.html)

---

## 2. Install `osc-cli`

1. Open **Command Prompt** (press `Win + R`, type `cmd`, press Enter)
2. Upgrade `pip`:

   ```cmd
   python -m pip install --upgrade pip
   ```
3. Install `osc-sdk` (which includes `osc-cli`):

   ```cmd
   pip install osc-sdk
   ```

---

## 3. Set up your credentials

1. Still in Command Prompt:

   ```cmd
   mkdir %USERPROFILE%\.osc
   ```
2. Open Windows Explorer and navigate to:

   ```
   C:\Users\YOUR_USERNAME\.osc
   ```
3. Download this example [`config.json`](https://github.com/outscale/osc-cli/blob/osc_sdk/config.json) and save it in that folder:

   * Make sure the file is named exactly `config.json` (not `config.json.txt`)
4. Edit the file to add your `access_key`, `secret_key`, and `region`:

   ```json
   {
     "default": {
       "access_key": "YOUR_ACCESS_KEY",
       "secret_key": "YOUR_SECRET_KEY",
       "region": "eu-west-2"
     }
   }
   ```

---

## 4. Run `osc-cli`

1. Open a new Command Prompt window
2. Run a test command, such as:

   ```cmd
   osc-cli api ReadVolumes
   ```

If everything is correctly configured, you should see a JSON response from the Outscale API.
