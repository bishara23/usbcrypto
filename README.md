# usbcrypto
Python project for encrypting and decrypting files on a USB storage device.

# Installation
## Install dependencies
From the repo root, run `pip install -r requirements.txt`.

## Automation Installation
### Event Viewer Log Enable
Event viewer USB logs must be enabled. Enter `Event Viewer` and follow the following steps:
1. Launch Event Viewer ( eventvwr.msc ).
2. Navigate to Applications and Services Logs ▶ Microsoft ▶ Windows ▶ DriverFrameworks-UserMode ▶ Operational.
3. Right-click Operational and choose Enable Log. This log records Event ID 2003 whenever any USB device is first recognized.

### Task Scheduler Configuration
After enabling the logging of event 2003, task scheduler can pick up that event and respond accordingly. Perform the following steps:
1. Open Task Scheduler and select Create Task…
2. On the General tab, give it a name like “USB Insert → Encrypt.”
3. On the Triggers tab, click New… and choose Begin the task: On an event.
    - Log: Microsoft-Windows-DriverFrameworks-UserMode/Operational
    - Source: (leave blank)
    - Event ID: 2003
4. Click OK
5. Switch to the Actions tab → New…
6. Action: Start a program
    - Program/script:
    ```
    C:\Windows\System32\cmd.exe
    ```
    - Add arguments:
    ```
    /c "python -m usbutils.scripts.decrypt"
    ```
    - Start in: add the folder containing the project.

