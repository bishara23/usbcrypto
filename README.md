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
    /c "python -m usbcrypto.scripts.decrypt"
    ```
    - Start in: add the folder containing the project.


# Usage
## Encrypt & Sign
On a **trusted PC**, from the repo root run:
```bash
python encrypt.py
```
This will:
1. Auto-detect your USB stick (`USBManager.find_usb_drive`)  
2. Prompt you for a password  
3. Prepend a 32-byte SHA3-256 signature to every file (`Encryptor.sign_all_files_in_folder`)  
4. Encrypt each file in-place with AES-GCM using an Argon2id-derived key (`Encryptor.encrypt_all_in_folder`)

## Decrypt & Verify (Automatic on USB Insert)
Once Task Scheduler is configured, decrypt & verify runs automatically upon USB insertion (Event ID 2003). The `decrypt.py` script will:
1. Auto-detect the USB stick (`USBManager.find_usb_drive`)  
2. Prompt for the **same** password  
3. Decrypt each file and verify its SHA3-256 signature (`Decryptor.decrypt_all_in_folder`)  
4. Strip the 32-byte signature on success (`Decryptor.strip_signature`)  
5. Pop up “✅ Access Granted” or immediately disable the USB on any failure (`USBManager.alert_and_disable`)

# Project Structure
```text
usbcrypto/
├── derive_key.py        # Argon2id KDF for key derivation
├── crypto.py            # Core Encryptor, Decryptor & USBManager
├── encrypt.py           # CLI: sign & encrypt all files on USB
├── decrypt.py           # CLI: decrypt & verify all files on USB
├── requirements.txt     # cryptography, argon2-cffi
└── metadata.json        # Generated on USB after encryption
```

# Metadata Format
After encryption, a `metadata.json` is created in the USB root. It maps each relative file path to:
- **salt**: Argon2id salt (base64)  
- **iv**: AES-GCM nonce (base64)  
- **kdf**: key-derivation function identifier  

The decrypt script reads this file to derive the correct key/IV for each file.
